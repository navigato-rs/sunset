//! Checks the bytes a [`SftpClient`] puts on the wire, and how it
//! handles responses that a cooperating server wouldn't produce.

mod common;

use common::pipe::{self, Pipe, run_test};

use core::pin::pin;
use core::task::{Context, Poll, Waker};

use sunset_sftp::client::{self, SftpClient};
use sunset_sftp::error::SftpError;

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

#[test]
fn read_requests_are_capped() {
    let (s, mut client) = Scripted::new(&[]);
    // Handle for a file
    let mut handle_body = vec![102u8];
    handle_body.extend_from_slice(&1u32.to_be_bytes());
    handle_body.extend_from_slice(&string(b"abcd"));
    s.to_client.push(&packet(handle_body));
    s.to_client.push(&data_packet(2, b"hi"));

    let h = run_test(client.open_read("/f")).expect("open");
    let _ = s.from_client.take();

    let mut buf = vec![0u8; 100_000];
    let n = run_test(client.read(&h, 0, &mut buf)).expect("read");
    assert_eq!(&buf[..n], b"hi");

    // type(1) id(4) handle(4+4) offset(8) len(4)
    let sent = s.from_client.take();
    let len = u32::from_be_bytes(sent[sent.len() - 4..].try_into().unwrap());
    assert_eq!(len, sunset_sftp::client::MAX_READ_LEN);
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
