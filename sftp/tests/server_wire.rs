//! Drives [`SftpServerHandler`] with raw bytes.
//!
//! Requests that the client wouldn't send, such as an unknown extension
//! or a malformed payload, only reach the server this way.

mod common;

use common::memfs::MemFs;
use common::pipe::{Pipe, run_test};

use embassy_futures::select::{Either, select};
use sunset_sftp::SftpServerHandler;
use sunset_sftp::embedded_io_async::Read;

fn string(s: &[u8]) -> Vec<u8> {
    let mut v = (s.len() as u32).to_be_bytes().to_vec();
    v.extend_from_slice(s);
    v
}

fn packet(body: Vec<u8>) -> Vec<u8> {
    let mut v = (body.len() as u32).to_be_bytes().to_vec();
    v.extend_from_slice(&body);
    v
}

/// Reads one packet, returning its body.
async fn read_packet(r: &mut impl Read) -> Vec<u8> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len).await.expect("packet length");
    let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
    r.read_exact(&mut body).await.expect("packet body");
    body
}

/// The status code of a `SSH_FXP_STATUS` body.
fn status_code(body: &[u8]) -> u32 {
    assert_eq!(body[0], 101, "expected SSH_FXP_STATUS, got {}", body[0]);
    u32::from_be_bytes(body[5..9].try_into().unwrap())
}

/// Runs `f` against a `MemFs` server, having done the version handshake.
fn with_raw_server<F, Fut>(fs: MemFs, f: F)
where
    F: FnOnce(Pipe, common::pipe::PipeReader) -> Fut,
    Fut: Future<Output = ()>,
{
    let c2s = Pipe::new();
    let s2c = Pipe::new();

    let mut handler = SftpServerHandler::default();
    let mut fs = fs;
    let server = handler.run(&mut fs, c2s.reader(), s2c.writer());

    let to_server = c2s.clone();
    let driver = async move {
        let mut from_server = s2c.reader();
        // SSH_FXP_INIT, version 3
        to_server.push(&packet(vec![1, 0, 0, 0, 3]));
        let version = read_packet(&mut from_server).await;
        assert_eq!(version[0], 2, "expected SSH_FXP_VERSION");
        assert_eq!(version[1..5], 3u32.to_be_bytes(), "version 3");

        f(to_server, from_server).await
    };

    match run_test(select(server, driver)) {
        Either::First(r) => panic!("server exited early: {r:?}"),
        Either::Second(()) => (),
    }
}

/// The version reply carries the extensions the server announces.
#[test]
fn version_announces_extensions() {
    let c2s = Pipe::new();
    let s2c = Pipe::new();

    let mut handler = SftpServerHandler::default();
    let mut fs = MemFs::new();
    let server = handler.run(&mut fs, c2s.reader(), s2c.writer());

    let driver = async {
        let mut from_server = s2c.reader();
        c2s.push(&packet(vec![1, 0, 0, 0, 3]));
        let version = read_packet(&mut from_server).await;

        assert_eq!(version[0], 2);
        assert_eq!(version[1..5], 3u32.to_be_bytes());

        // name/data pairs follow the version
        let mut names = Vec::new();
        let mut p = 5;
        while p < version.len() {
            let n =
                u32::from_be_bytes(version[p..p + 4].try_into().unwrap()) as usize;
            names.push(
                String::from_utf8(version[p + 4..p + 4 + n].to_vec()).unwrap(),
            );
            p += 4 + n;
            // skip the data string
            let n =
                u32::from_be_bytes(version[p..p + 4].try_into().unwrap()) as usize;
            p += 4 + n;
        }
        assert_eq!(
            names,
            [
                "posix-rename@openssh.com",
                "hardlink@openssh.com",
                "fsync@openssh.com"
            ]
        );
    };

    match run_test(select(server, driver)) {
        Either::First(r) => panic!("server exited early: {r:?}"),
        Either::Second(()) => (),
    }
}

/// A server announcing nothing sends a bare version packet.
#[test]
fn version_without_extensions() {
    with_raw_server(MemFs::without_extensions(), |_to, _from| async {});
}

/// An extension the server doesn't implement is refused, not ignored.
#[test]
fn unknown_extension_is_unsupported() {
    with_raw_server(MemFs::new(), |to, mut from| async move {
        let mut body = vec![200u8];
        body.extend_from_slice(&7u32.to_be_bytes());
        body.extend_from_slice(&string(b"invented@example.com"));
        body.extend_from_slice(&string(b"payload"));
        to.push(&packet(body));

        let reply = read_packet(&mut from).await;
        assert_eq!(reply[1..5], 7u32.to_be_bytes(), "same request id");
        // SSH_FX_OP_UNSUPPORTED
        assert_eq!(status_code(&reply), 8);
    })
}

/// A known extension with a payload that doesn't decode is a bad message.
#[test]
fn malformed_extension_payload() {
    with_raw_server(MemFs::new(), |to, mut from| async move {
        let mut body = vec![200u8];
        body.extend_from_slice(&9u32.to_be_bytes());
        body.extend_from_slice(&string(b"posix-rename@openssh.com"));
        // Needs two strings, this is neither
        body.extend_from_slice(b"\xff\xff");
        to.push(&packet(body));

        let reply = read_packet(&mut from).await;
        assert_eq!(reply[1..5], 9u32.to_be_bytes());
        // SSH_FX_BAD_MESSAGE
        assert_eq!(status_code(&reply), 5);
    })
}

/// Trailing data after a valid payload is refused too.
#[test]
fn extension_payload_with_trailing_data() {
    with_raw_server(MemFs::new(), |to, mut from| async move {
        let mut body = vec![200u8];
        body.extend_from_slice(&11u32.to_be_bytes());
        body.extend_from_slice(&string(b"posix-rename@openssh.com"));
        body.extend_from_slice(&string(b"/a"));
        body.extend_from_slice(&string(b"/b"));
        body.extend_from_slice(b"junk");
        to.push(&packet(body));

        let reply = read_packet(&mut from).await;
        assert_eq!(status_code(&reply), 5, "SSH_FX_BAD_MESSAGE");
    })
}

/// A working extended request, driven at the byte level.
#[test]
fn extension_round_trip() {
    with_raw_server(MemFs::new(), |to, mut from| async move {
        // Create /a so there is something to rename
        let mut open = vec![3u8];
        open.extend_from_slice(&1u32.to_be_bytes());
        open.extend_from_slice(&string(b"/a"));
        // SSH_FXF_WRITE | SSH_FXF_CREAT, no attributes
        open.extend_from_slice(&0x0000000au32.to_be_bytes());
        open.extend_from_slice(&0u32.to_be_bytes());
        to.push(&packet(open));
        let reply = read_packet(&mut from).await;
        assert_eq!(reply[0], 102, "expected SSH_FXP_HANDLE");

        let mut body = vec![200u8];
        body.extend_from_slice(&2u32.to_be_bytes());
        body.extend_from_slice(&string(b"posix-rename@openssh.com"));
        body.extend_from_slice(&string(b"/a"));
        body.extend_from_slice(&string(b"/b"));
        to.push(&packet(body));

        let reply = read_packet(&mut from).await;
        assert_eq!(status_code(&reply), 0, "SSH_FX_OK");
    })
}

/// A request type the server has no case for is refused rather than
/// desynchronising the stream.
#[test]
fn unknown_packet_type() {
    with_raw_server(MemFs::new(), |to, mut from| async move {
        let mut body = vec![99u8];
        body.extend_from_slice(&5u32.to_be_bytes());
        body.extend_from_slice(b"whatever");
        to.push(&packet(body));

        let reply = read_packet(&mut from).await;
        assert_eq!(status_code(&reply), 8, "SSH_FX_OP_UNSUPPORTED");

        // The next request is still understood
        let mut stat = vec![17u8];
        stat.extend_from_slice(&6u32.to_be_bytes());
        stat.extend_from_slice(&string(b"/"));
        to.push(&packet(stat));
        let reply = read_packet(&mut from).await;
        assert_eq!(reply[0], 105, "expected SSH_FXP_ATTRS");
    })
}
