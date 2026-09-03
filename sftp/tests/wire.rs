//! Checks the bytes a [`SftpClient`] puts on the wire, and how it
//! handles responses that a cooperating server wouldn't produce.

mod common;

use common::pipe::{self, Pipe, run_test};

use core::pin::pin;
use core::task::{Context, Poll, Waker};

use sunset_sftp::client::{self, RemoteHandle, SftpClient};
use sunset_sftp::error::SftpError;
use sunset_sftp::protocol::StatusCode;

type Client =
    SftpClient<pipe::PipeReader, pipe::PipeWriter, { client::DEFAULT_CLIENT_BUF }>;

/// Encodes a `u32` length prefixed string.
fn string(s: &[u8]) -> Vec<u8> {
    let mut v = (s.len() as u32).to_be_bytes().to_vec();
    v.extend_from_slice(s);
    v
}

/// Wraps a packet body in its length field.
fn packet(body: Vec<u8>) -> Vec<u8> {
    let mut v = (body.len() as u32).to_be_bytes().to_vec();
    v.extend_from_slice(&body);
    v
}

/// `SSH_FXP_VERSION` with the given extension names.
fn version_packet(version: u32, exts: &[&str]) -> Vec<u8> {
    let mut body = vec![2u8];
    body.extend_from_slice(&version.to_be_bytes());
    for e in exts {
        body.extend_from_slice(&string(e.as_bytes()));
        body.extend_from_slice(&string(b"1"));
    }
    packet(body)
}

/// `SSH_FXP_STATUS` for `id`.
fn status_packet(id: u32, code: u32) -> Vec<u8> {
    let mut body = vec![101u8];
    body.extend_from_slice(&id.to_be_bytes());
    body.extend_from_slice(&code.to_be_bytes());
    body.extend_from_slice(&string(b""));
    body.extend_from_slice(&string(b""));
    packet(body)
}

/// `SSH_FXP_DATA` for `id`.
fn data_packet(id: u32, data: &[u8]) -> Vec<u8> {
    let mut body = vec![103u8];
    body.extend_from_slice(&id.to_be_bytes());
    body.extend_from_slice(&string(data));
    packet(body)
}

struct Scripted {
    to_client: Pipe,
    from_client: Pipe,
}

impl Scripted {
    /// Sets up a client that has completed a handshake advertising `exts`.
    fn new(exts: &[&str]) -> (Self, Client) {
        let to_client = Pipe::new();
        let from_client = Pipe::new();
        to_client.push(&version_packet(3, exts));

        let mut client: Client =
            SftpClient::new(to_client.reader(), from_client.writer());
        run_test(client.init()).expect("init");
        // Discard the SSH_FXP_INIT the client sent
        assert_eq!(from_client.take(), packet(vec![1, 0, 0, 0, 3]));

        (Self { to_client, from_client }, client)
    }
}

#[test]
fn init_packet_and_extensions() {
    let (s, client) = Scripted::new(&[
        "posix-rename@openssh.com",
        "unknown-extension@example.com",
        "fsync@openssh.com",
    ]);
    let e = client.extensions();
    assert!(e.posix_rename);
    assert!(e.fsync);
    assert!(!e.hardlink);
    assert!(!e.statvfs);
    assert!(s.to_client.take().is_empty(), "version packet fully consumed");
}

#[test]
fn init_rejects_other_versions() {
    let to_client = Pipe::new();
    let from_client = Pipe::new();
    to_client.push(&version_packet(2, &[]));

    let mut client: Client =
        SftpClient::new(to_client.reader(), from_client.writer());
    assert!(matches!(run_test(client.init()), Err(SftpError::NotSupported)));
    assert_eq!(client.version(), None);
}

#[test]
fn init_only_once() {
    let (s, mut client) = Scripted::new(&[]);
    s.to_client.push(&version_packet(3, &[]));
    assert!(matches!(run_test(client.init()), Err(SftpError::AlreadyInitialized)));
}

/// draft-ietf-secsh-filexfer-02 orders SSH_FXP_SYMLINK as linkpath then
/// targetpath, but OpenSSH reversed them and that is what peers expect.
#[test]
fn symlink_uses_openssh_argument_order() {
    let (s, mut client) = Scripted::new(&[]);
    s.to_client.push(&status_packet(1, 0));

    run_test(client.symlink("/target", "/link")).expect("symlink");

    let mut expect = vec![20u8];
    expect.extend_from_slice(&1u32.to_be_bytes());
    expect.extend_from_slice(&string(b"/target"));
    expect.extend_from_slice(&string(b"/link"));
    assert_eq!(s.from_client.take(), packet(expect));
}

#[test]
fn posix_rename_encoding() {
    let (s, mut client) = Scripted::new(&["posix-rename@openssh.com"]);
    s.to_client.push(&status_packet(1, 0));

    run_test(client.posix_rename("/a", "/b")).expect("posix_rename");

    let mut expect = vec![200u8];
    expect.extend_from_slice(&1u32.to_be_bytes());
    expect.extend_from_slice(&string(b"posix-rename@openssh.com"));
    expect.extend_from_slice(&string(b"/a"));
    expect.extend_from_slice(&string(b"/b"));
    assert_eq!(s.from_client.take(), packet(expect));
}

#[test]
fn request_ids_increment() {
    let (s, mut client) = Scripted::new(&[]);
    s.to_client.push(&status_packet(1, 0));
    s.to_client.push(&status_packet(2, 0));

    run_test(client.remove("/a")).expect("remove");
    run_test(client.remove("/b")).expect("remove");

    let sent = s.from_client.take();
    // Request id follows the packet type at offset 5
    assert_eq!(sent[5..9], 1u32.to_be_bytes());
    let second = 4 + u32::from_be_bytes(sent[0..4].try_into().unwrap()) as usize;
    assert_eq!(sent[second + 5..second + 9], 2u32.to_be_bytes());
}

#[test]
fn mismatched_request_id_is_rejected() {
    let (s, mut client) = Scripted::new(&[]);
    // A response for a request that was never made
    s.to_client.push(&status_packet(99, 0));

    assert!(matches!(run_test(client.remove("/a")), Err(SftpError::BadResponse)));
}

/// Opens a file, returning the handle and discarding what was sent.
fn open_file(s: &Scripted, client: &mut Client) -> RemoteHandle {
    let mut handle_body = vec![102u8];
    handle_body.extend_from_slice(&1u32.to_be_bytes());
    handle_body.extend_from_slice(&string(b"abcd"));
    s.to_client.push(&packet(handle_body));

    let h = run_test(client.open_read("/f")).expect("open");
    let _ = s.from_client.take();
    h
}

/// Pulls the (id, offset, len) out of each `SSH_FXP_READ` sent.
fn sent_reads(sent: &[u8]) -> Vec<(u32, u64, u32)> {
    let mut out = Vec::new();
    let mut p = 0;
    while p < sent.len() {
        let len = u32::from_be_bytes(sent[p..p + 4].try_into().unwrap()) as usize;
        let body = &sent[p + 4..p + 4 + len];
        assert_eq!(body[0], 5, "expected SSH_FXP_READ");
        let id = u32::from_be_bytes(body[1..5].try_into().unwrap());
        // handle string
        let hlen = u32::from_be_bytes(body[5..9].try_into().unwrap()) as usize;
        let rest = &body[9 + hlen..];
        let offset = u64::from_be_bytes(rest[..8].try_into().unwrap());
        let want = u32::from_be_bytes(rest[8..12].try_into().unwrap());
        out.push((id, offset, want));
        p += 4 + len;
    }
    out
}

/// A read larger than `MAX_READ_LEN` is split, and the requests are all
/// sent before their replies are read.
///
/// The replies are queued in reverse, which only works if the client
/// has more than one request outstanding and matches replies by id.
#[test]
fn reads_are_chunked_pipelined_and_unordered() {
    let (s, mut client) = Scripted::new(&[]);
    let h = open_file(&s, &mut client);

    let chunk = client::MAX_READ_LEN as usize;
    let tail = 1000;
    let total = 2 * chunk + tail;

    // open() was request 1, so the reads are 2, 3 and 4
    s.to_client.push(&data_packet(4, &vec![0xcc; tail]));
    s.to_client.push(&data_packet(3, &vec![0xbb; chunk]));
    s.to_client.push(&data_packet(2, &vec![0xaa; chunk]));

    let mut buf = vec![0u8; total];
    let n = run_test(client.read(&h, 0, &mut buf)).expect("read");

    assert_eq!(n, total);
    assert!(buf[..chunk].iter().all(|b| *b == 0xaa));
    assert!(buf[chunk..2 * chunk].iter().all(|b| *b == 0xbb));
    assert!(buf[2 * chunk..].iter().all(|b| *b == 0xcc));

    // No request asked for more than MAX_READ_LEN, and each covers its
    // own part of the file.
    let reads = sent_reads(&s.from_client.take());
    assert_eq!(
        reads,
        [
            (2, 0, chunk as u32),
            (3, chunk as u64, chunk as u32),
            (4, 2 * chunk as u64, tail as u32),
        ]
    );
}

/// The client fills its window before it waits for any reply.
///
/// Without that, each request would cost a round trip.
#[test]
fn the_pipeline_is_filled_before_waiting() {
    let (s, mut client) = Scripted::new(&[]);
    let h = open_file(&s, &mut client);
    let chunk = client::MAX_READ_LEN as usize;

    // No replies are queued, so the read gets as far as it can and then
    // blocks. Whatever it sent first was sent without waiting.
    let mut buf = vec![0u8; 20 * chunk];
    {
        let mut fut = pin!(client.read(&h, 0, &mut buf));
        let mut cx = Context::from_waker(Waker::noop());
        assert!(matches!(fut.as_mut().poll(&mut cx), Poll::Pending));
        // Dropped here, which leaves the client interrupted
    }

    let reads = sent_reads(&s.from_client.take());
    assert_eq!(
        reads.len(),
        client::PIPELINE_DEPTH,
        "the whole pipeline should be in flight"
    );
    // Covering consecutive parts of the file
    for (i, (_, offset, len)) in reads.iter().enumerate() {
        assert_eq!(*offset, (i * chunk) as u64);
        assert_eq!(*len as usize, chunk);
    }
}

/// A chunk that comes back short ends the contiguous data, whatever the
/// later chunks returned.
#[test]
fn a_short_chunk_ends_the_read() {
    let (s, mut client) = Scripted::new(&[]);
    let h = open_file(&s, &mut client);

    let chunk = client::MAX_READ_LEN as usize;
    s.to_client.push(&data_packet(2, &vec![0xaa; chunk]));
    // Short, so the third chunk's data is beyond a gap
    s.to_client.push(&data_packet(3, &[0xbb; 100]));
    s.to_client.push(&data_packet(4, &vec![0xcc; 500]));

    let mut buf = vec![0u8; 2 * chunk + 500];
    let n = run_test(client.read(&h, 0, &mut buf)).expect("read");
    assert_eq!(n, chunk + 100);

    // Reading on from there works normally. A buffer within one chunk
    // makes a single request.
    s.to_client.push(&status_packet(5, 1));
    assert_eq!(
        run_test(client.read(&h, n as u64, &mut buf[..100])).expect("read"),
        0
    );
}

/// End of file on the first chunk is a zero length read.
#[test]
fn eof_on_the_first_chunk() {
    let (s, mut client) = Scripted::new(&[]);
    let h = open_file(&s, &mut client);

    let chunk = client::MAX_READ_LEN as usize;
    // SSH_FX_EOF for the first, data for the second
    s.to_client.push(&status_packet(2, 1));
    s.to_client.push(&data_packet(3, &vec![0xbb; chunk]));

    let mut buf = vec![0u8; 2 * chunk];
    assert_eq!(run_test(client.read(&h, 0, &mut buf)).expect("read"), 0);
}

/// Writes longer than `MAX_WRITE_LEN` are split into several requests.
#[test]
fn writes_are_chunked_and_pipelined() {
    let (s, mut client) = Scripted::new(&[]);
    let h = open_file(&s, &mut client);

    let chunk = client::MAX_WRITE_LEN as usize;
    let data = vec![0x5a; chunk + 7];

    // Replies in reverse, as for reads
    s.to_client.push(&status_packet(3, 0));
    s.to_client.push(&status_packet(2, 0));

    run_test(client.write(&h, 64, &data)).expect("write");

    // Two SSH_FXP_WRITE packets, at the right offsets
    let sent = s.from_client.take();
    let mut p = 0;
    let mut seen = Vec::new();
    while p < sent.len() {
        let len = u32::from_be_bytes(sent[p..p + 4].try_into().unwrap()) as usize;
        let body = &sent[p + 4..p + 4 + len];
        assert_eq!(body[0], 6, "expected SSH_FXP_WRITE");
        let id = u32::from_be_bytes(body[1..5].try_into().unwrap());
        let hlen = u32::from_be_bytes(body[5..9].try_into().unwrap()) as usize;
        let rest = &body[9 + hlen..];
        let offset = u64::from_be_bytes(rest[..8].try_into().unwrap());
        let dlen = u32::from_be_bytes(rest[8..12].try_into().unwrap()) as usize;
        assert_eq!(rest.len(), 12 + dlen, "data follows the header");
        seen.push((id, offset, dlen));
        p += 4 + len;
    }
    assert_eq!(seen, [(2, 64, chunk), (3, 64 + chunk as u64, 7)]);
}

/// A failure on one chunk of a write fails the whole write, and the
/// remaining replies are consumed so the session survives.
#[test]
fn a_failed_write_chunk_fails_the_write() {
    let (s, mut client) = Scripted::new(&[]);
    let h = open_file(&s, &mut client);

    let chunk = client::MAX_WRITE_LEN as usize;
    s.to_client.push(&status_packet(2, 0));
    // SSH_FX_PERMISSION_DENIED for the second chunk
    s.to_client.push(&status_packet(3, 3));

    let data = vec![0u8; chunk + 1];
    match run_test(client.write(&h, 0, &data)) {
        Err(SftpError::FileServerError(StatusCode::SSH_FX_PERMISSION_DENIED)) => (),
        r => panic!("unexpected {r:?}"),
    }

    // Still usable
    s.to_client.push(&status_packet(4, 0));
    run_test(client.close(&h)).expect("close");
}

#[test]
fn oversized_data_response_is_refused() {
    let (s, mut client) = Scripted::new(&[]);
    let mut handle_body = vec![102u8];
    handle_body.extend_from_slice(&1u32.to_be_bytes());
    handle_body.extend_from_slice(&string(b"abcd"));
    s.to_client.push(&packet(handle_body));
    // More data than was asked for
    s.to_client.push(&data_packet(2, &[7u8; 40]));
    s.to_client.push(&status_packet(3, 0));

    let h = run_test(client.open_read("/f")).expect("open");

    let mut buf = [0u8; 8];
    assert!(matches!(
        run_test(client.read(&h, 0, &mut buf)),
        Err(SftpError::BadResponse)
    ));
    // The oversized packet was drained, so the session continues
    run_test(client.close(&h)).expect("close");
}

#[test]
fn attrs_response_with_extended_attributes() {
    let (s, mut client) = Scripted::new(&[]);

    let mut body = vec![105u8];
    body.extend_from_slice(&1u32.to_be_bytes());
    // SSH_FILEXFER_ATTR_SIZE | PERMISSIONS | EXTENDED
    body.extend_from_slice(&0x8000_0005u32.to_be_bytes());
    body.extend_from_slice(&42u64.to_be_bytes());
    body.extend_from_slice(&0o644u32.to_be_bytes());
    body.extend_from_slice(&2u32.to_be_bytes());
    for (ty, data) in [(&b"x@example.com"[..], &b"1"[..]), (b"y@example.com", b"")] {
        body.extend_from_slice(&string(ty));
        body.extend_from_slice(&string(data));
    }
    s.to_client.push(&packet(body));
    s.to_client.push(&status_packet(2, 0));

    let a = run_test(client.stat("/f")).expect("stat");
    assert_eq!(a.size, Some(42));
    assert_eq!(a.permissions, Some(0o644));
    // Recorded, but the values themselves are discarded
    assert_eq!(a.ext_count, Some(2));

    // The extended attributes were consumed, not left in the stream
    run_test(client.remove("/f")).expect("remove");
}

#[test]
fn interrupted_request_poisons_the_client() {
    let (s, mut client) = Scripted::new(&[]);

    // Start a request but never let it see a response.
    {
        let mut fut = pin!(client.remove("/a"));
        let mut cx = Context::from_waker(Waker::noop());
        assert!(matches!(fut.as_mut().poll(&mut cx), Poll::Pending));
        // Future dropped here, mid request.
    }
    assert!(!s.from_client.take().is_empty(), "the request was sent");

    // Even with a response now available, the client refuses to
    // continue rather than pairing it with the wrong request.
    s.to_client.push(&status_packet(1, 0));
    assert!(matches!(run_test(client.remove("/b")), Err(SftpError::Interrupted)));
}

#[test]
fn truncated_response_reports_disconnect() {
    let (s, mut client) = Scripted::new(&[]);
    // A length field promising more than is delivered
    s.to_client.push(&[0, 0, 0, 20, 101, 0, 0, 0, 1]);
    s.to_client.close();

    assert!(matches!(run_test(client.remove("/a")), Err(SftpError::Disconnected)));
}
