//! Runs [`SftpClient`] against [`SftpServerHandler`] over an in-memory
//! pipe, with a small in-memory filesystem behind the server.

mod common;

use common::memfs::MemFs;
use common::pipe::{self, Pipe, run_test};

use sunset_sftp::SftpServerHandler;
use sunset_sftp::client::{self, SftpClient, pflags};
use sunset_sftp::error::SftpError;
use sunset_sftp::protocol::{Attrs, StatusCode};

use embassy_futures::select::{Either, select};

type Client =
    SftpClient<pipe::PipeReader, pipe::PipeWriter, { client::DEFAULT_CLIENT_BUF }>;

/// Runs `f` with an initialised client talking to a `MemFs` server.
fn with_client<F, Fut>(f: F)
where
    F: FnOnce(Client) -> Fut,
    Fut: Future<Output = Result<(), SftpError>>,
{
    let c2s = Pipe::new();
    let s2c = Pipe::new();

    let mut handler = SftpServerHandler::default();
    let mut fs = MemFs::new();

    let server = handler.run(&mut fs, c2s.reader(), s2c.writer());

    let client = SftpClient::new(s2c.reader(), c2s.writer());
    let client = async move {
        let mut client = client;
        assert_eq!(client.init().await.unwrap(), 3);
        assert_eq!(client.version(), Some(3));
        f(client).await
    };

    match run_test(select(server, client)) {
        Either::First(r) => panic!("server exited early: {r:?}"),
        Either::Second(r) => r.expect("client failed"),
    }
}

#[test]
fn version_handshake() {
    with_client(|_client| async { Ok(()) })
}

#[test]
fn write_then_read_back() {
    with_client(|mut client| async move {
        let content = b"the quick brown fox";

        let h = client.create("/file").await?;
        client.write(&h, 0, content).await?;
        client.close(&h).await?;

        let attrs = client.stat("/file").await?;
        assert_eq!(attrs.size, Some(content.len() as u64));

        let h = client.open_read("/file").await?;
        let mut buf = [0u8; 64];
        let n = client.read(&h, 0, &mut buf).await?;
        assert_eq!(&buf[..n], content);
        // End of file
        assert_eq!(client.read(&h, content.len() as u64, &mut buf).await?, 0);
        client.close(&h).await?;
        Ok(())
    })
}

#[test]
fn partial_reads_and_writes() {
    with_client(|mut client| async move {
        // Larger than the client's buffer, to check that file data is
        // streamed rather than being copied through it.
        let content: Vec<u8> = (0..5000u32).map(|i| i as u8).collect();

        let h = client.create("/big").await?;
        for (i, chunk) in content.chunks(700).enumerate() {
            client.write(&h, (i * 700) as u64, chunk).await?;
        }
        client.close(&h).await?;

        assert_eq!(client.stat("/big").await?.size, Some(content.len() as u64));

        let h = client.open_read("/big").await?;
        let mut got = Vec::new();
        let mut buf = [0u8; 333];
        loop {
            let n = client.read(&h, got.len() as u64, &mut buf).await?;
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
        }
        client.close(&h).await?;
        assert_eq!(got, content);
        Ok(())
    })
}

#[test]
fn read_offset() {
    with_client(|mut client| async move {
        let h = client.create("/f").await?;
        client.write(&h, 0, b"0123456789").await?;
        client.close(&h).await?;

        let h = client.open_read("/f").await?;
        let mut buf = [0u8; 4];
        let n = client.read(&h, 3, &mut buf).await?;
        assert_eq!(&buf[..n], b"3456");
        client.close(&h).await?;
        Ok(())
    })
}

#[test]
fn open_missing_file() {
    with_client(|mut client| async move {
        match client.open_read("/nope").await {
            Err(SftpError::FileServerError(StatusCode::SSH_FX_NO_SUCH_FILE)) => (),
            r => panic!("unexpected {r:?}"),
        }
        // The session is still usable after an error status.
        let h = client.create("/yes").await?;
        client.close(&h).await?;
        Ok(())
    })
}

#[test]
fn directory_listing() {
    with_client(|mut client| async move {
        // More than one SSH_FXP_READDIR batch worth
        for n in ["/a", "/b", "/c", "/d", "/e", "/f", "/g"] {
            let h = client.create(n).await?;
            client.write(&h, 0, b"x").await?;
            client.close(&h).await?;
        }
        client.mkdir("/sub", &Attrs::default()).await?;

        let d = client.opendir("/").await?;
        let mut names = Vec::new();
        while let Some(mut entries) = client.readdir(&d).await? {
            while let Some(e) = entries.next().await? {
                names.push((
                    e.filename_str()?.to_string(),
                    e.attrs().size,
                    e.attrs().permissions,
                ));
            }
        }
        client.close(&d).await?;

        names.sort();
        assert_eq!(
            names.iter().map(|(n, _, _)| n.as_str()).collect::<Vec<_>>(),
            ["a", "b", "c", "d", "e", "f", "g", "sub"]
        );
        // Sizes come from the entry attributes
        assert_eq!(names[0].1, Some(1));
        assert!(names[7].2.unwrap() & 0o40000 != 0, "sub is a directory");
        Ok(())
    })
}

#[test]
fn directory_listing_abandoned() {
    with_client(|mut client| async move {
        for i in 0..10 {
            let h = client.create(&format!("/f{i}")).await?;
            client.close(&h).await?;
        }

        let d = client.opendir("/").await?;
        {
            let mut entries = client.readdir(&d).await?.expect("entries");
            assert!(entries.remaining() > 1);
            let e = entries.next().await?.expect("one entry");
            assert!(!e.filename().is_empty());
            // Dropped without reading the rest.
        }

        // The unread entries are discarded, the session still works.
        assert!(client.stat("/f0").await.is_ok());
        client.close(&d).await?;
        Ok(())
    })
}

#[test]
fn empty_directory_listing() {
    with_client(|mut client| async move {
        client.mkdir("/empty", &Attrs::default()).await?;
        let d = client.opendir("/empty").await?;
        assert!(client.readdir(&d).await?.is_none());
        client.close(&d).await?;
        Ok(())
    })
}

#[test]
fn handles_are_typed() {
    with_client(|mut client| async move {
        let d = client.opendir("/").await?;
        let mut buf = [0u8; 8];
        assert!(matches!(
            client.read(&d, 0, &mut buf).await,
            Err(SftpError::BadHandle)
        ));

        let f = client.create("/f").await?;
        assert!(matches!(client.readdir(&f).await, Err(SftpError::BadHandle)));
        assert!(!f.is_dir());
        assert!(d.is_dir());

        client.close(&f).await?;
        client.close(&d).await?;
        Ok(())
    })
}

#[test]
fn remove_rename_mkdir_rmdir() {
    with_client(|mut client| async move {
        let h = client.create("/one").await?;
        client.write(&h, 0, b"hello").await?;
        client.close(&h).await?;

        client.rename("/one", "/two").await?;
        assert_eq!(client.stat("/two").await?.size, Some(5));
        assert!(client.stat("/one").await.is_err());

        // Version 3 rename must not clobber an existing destination
        let h = client.create("/three").await?;
        client.close(&h).await?;
        match client.rename("/two", "/three").await {
            Err(SftpError::FileServerError(StatusCode::SSH_FX_FAILURE)) => (),
            r => panic!("unexpected {r:?}"),
        }

        client.remove("/two").await?;
        assert!(client.stat("/two").await.is_err());

        client.mkdir("/d", &Attrs::default()).await?;
        assert!(client.stat("/d").await?.permissions.unwrap() & 0o40000 != 0);
        client.rmdir("/d").await?;
        assert!(client.stat("/d").await.is_err());

        // remove() must not remove a directory
        client.mkdir("/d2", &Attrs::default()).await?;
        assert!(client.remove("/d2").await.is_err());
        Ok(())
    })
}

#[test]
fn symlinks() {
    with_client(|mut client| async move {
        let h = client.create("/target").await?;
        client.write(&h, 0, b"abc").await?;
        client.close(&h).await?;

        client.symlink("/target", "/link").await?;

        let mut buf = [0u8; 64];
        assert_eq!(client.readlink("/link", &mut buf).await?, b"/target");

        // stat follows the link, lstat doesn't
        assert_eq!(client.stat("/link").await?.size, Some(3));
        assert_eq!(client.lstat("/link").await?.size, Some(7));
        Ok(())
    })
}

#[test]
fn realpath() {
    with_client(|mut client| async move {
        let mut buf = [0u8; 64];
        assert_eq!(client.realpath(".", &mut buf).await?, b"/");
        assert_eq!(client.realpath("/a/b", &mut buf).await?, b"/a/b");

        // A short buffer fails without breaking the session
        let mut small = [0u8; 2];
        assert!(matches!(
            client.realpath("/a/b", &mut small).await,
            Err(SftpError::NoRoom)
        ));
        assert_eq!(client.realpath("/x", &mut buf).await?, b"/x");
        Ok(())
    })
}

#[test]
fn attributes() {
    with_client(|mut client| async move {
        let h = client.create("/f").await?;
        client.write(&h, 0, b"1234").await?;

        let a = client.fstat(&h).await?;
        assert_eq!(a.size, Some(4));

        let set = Attrs { permissions: Some(0o600), ..Default::default() };
        client.fsetstat(&h, &set).await?;
        assert_eq!(client.fstat(&h).await?.permissions, Some(0o600));
        client.close(&h).await?;

        let set = Attrs { permissions: Some(0o644), ..Default::default() };
        client.setstat("/f", &set).await?;
        assert_eq!(client.stat("/f").await?.permissions, Some(0o644));
        Ok(())
    })
}

#[test]
fn unsupported_operation() {
    with_client(|mut client| async move {
        // MemFs doesn't implement it, and the server has no extensions
        assert!(!client.extensions().posix_rename);
        assert!(matches!(
            client.posix_rename("/a", "/b").await,
            Err(SftpError::NotSupported)
        ));
        // Still usable
        assert!(client.stat("/").await.is_ok());
        Ok(())
    })
}

#[test]
fn open_flags() {
    with_client(|mut client| async move {
        // EXCL on an existing file fails
        let h = client
            .open("/f", pflags::WRITE | pflags::CREAT, &Attrs::default())
            .await?;
        client.write(&h, 0, b"abcdef").await?;
        client.close(&h).await?;

        match client
            .open(
                "/f",
                pflags::WRITE | pflags::CREAT | pflags::EXCL,
                &Attrs::default(),
            )
            .await
        {
            Err(SftpError::FileServerError(StatusCode::SSH_FX_FAILURE)) => (),
            r => panic!("unexpected {r:?}"),
        }

        // TRUNC empties it
        let h = client.create("/f").await?;
        client.close(&h).await?;
        assert_eq!(client.stat("/f").await?.size, Some(0));
        Ok(())
    })
}

#[test]
fn requests_before_init_are_refused() {
    let c2s = Pipe::new();
    let s2c = Pipe::new();
    let mut client: Client = SftpClient::new(s2c.reader(), c2s.writer());
    let r = run_test(async { client.stat("/").await });
    assert!(matches!(r, Err(SftpError::NotInitialized)));
}
