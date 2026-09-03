//! Runs the client against OpenSSH's `sftp-server`.
//!
//! Skipped when OpenSSH isn't installed, so this doesn't have to be a
//! build dependency. On Debian and Ubuntu the binary is in the
//! `openssh-sftp-server` package.

mod common;

use common::pipe::run_test;
use common::subproc::{PipeReader, PipeWriter, SftpServerProc, sftp_server_path};

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use sunset_sftp::client::{self, SftpClient};
use sunset_sftp::error::{SftpError, SftpResult};
use sunset_sftp::protocol::{Attrs, StatusCode};

type Client = SftpClient<PipeReader, PipeWriter, { client::DEFAULT_CLIENT_BUF }>;

/// A directory of its own for each test, removed afterwards.
struct TestDir(PathBuf);

impl TestDir {
    fn new(name: &str) -> Self {
        // The pid keeps concurrent cargo runs apart
        let d = std::env::temp_dir()
            .join(format!("sunset-sftp-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).expect("create test dir");
        // Resolved, since macOS puts the temp dir behind a symlink and
        // realpath() replies with the resolved form.
        Self(fs::canonicalize(&d).expect("canonicalize"))
    }

    fn path(&self, rel: &str) -> String {
        self.0.join(rel).to_str().expect("utf-8 path").to_string()
    }

    fn dir(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Runs `f` with a client connected to `sftp-server`.
///
/// Returns without running anything if OpenSSH isn't installed.
fn with_openssh<F, Fut>(name: &str, f: F)
where
    F: FnOnce(Client, TestDir) -> Fut,
    Fut: Future<Output = SftpResult<()>>,
{
    let Some(server) = sftp_server_path() else {
        eprintln!("skipping {name}, no OpenSSH sftp-server installed");
        return;
    };

    let dir = TestDir::new(name);
    let (proc, reader, writer) = SftpServerProc::start(
        server,
        dir.dir().to_str().unwrap(),
        Duration::from_secs(30),
    )
    .expect("start sftp-server");

    let mut client: Client = SftpClient::new(reader, writer);

    run_test(async {
        client.init().await.expect("version handshake");
        f(client, dir).await
    })
    .expect("client failed");

    drop(proc);
}

#[test]
fn version_and_extensions() {
    with_openssh("version", |client, _dir| async move {
        assert_eq!(client.version(), Some(3));
        // OpenSSH has announced these since 5.x
        let e = client.extensions();
        assert!(e.posix_rename, "posix-rename@openssh.com");
        assert!(e.fsync, "fsync@openssh.com");
        assert!(e.hardlink, "hardlink@openssh.com");
        assert!(e.statvfs, "statvfs@openssh.com");
        Ok(())
    })
}

#[test]
fn write_and_read_a_file() {
    with_openssh("readwrite", |mut client, dir| async move {
        let content: Vec<u8> = (0..70_000u32).map(|i| (i * 7) as u8).collect();
        let p = dir.path("f");

        let h = client.create(&p).await?;
        for (i, chunk) in content.chunks(16 * 1024).enumerate() {
            client.write(&h, (i * 16 * 1024) as u64, chunk).await?;
        }
        // The OpenSSH fsync extension
        client.fsync(&h).await?;
        assert_eq!(client.fstat(&h).await?.size, Some(content.len() as u64));
        client.close(&h).await?;

        // Written to the real filesystem
        assert_eq!(fs::read(dir.dir().join("f")).unwrap(), content);

        let h = client.open_read(&p).await?;
        let mut got = Vec::new();
        // Larger than MAX_READ_LEN, so reads are capped and repeated
        let mut buf = vec![0u8; 50_000];
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
fn directory_operations() {
    with_openssh("dirs", |mut client, dir| async move {
        client.mkdir(&dir.path("sub"), &Attrs::default()).await?;
        for n in 0..25 {
            fs::write(dir.dir().join(format!("sub/f{n:02}")), b"x").unwrap();
        }

        let d = client.opendir(&dir.path("sub")).await?;
        let mut names = Vec::new();
        let mut longnames = 0;
        while let Some(mut entries) = client.readdir(&d).await? {
            while let Some(e) = entries.next().await? {
                if !e.longname().is_empty() {
                    longnames += 1;
                }
                names.push(e.filename_str()?.to_string());
            }
        }
        client.close(&d).await?;

        names.sort();
        names.retain(|n| n != "." && n != "..");
        assert_eq!(names.len(), 25, "got {names:?}");
        assert_eq!(names[0], "f00");
        assert!(longnames > 0, "OpenSSH sends ls -l style long names");

        // rmdir needs it empty
        assert!(matches!(
            client.rmdir(&dir.path("sub")).await,
            Err(SftpError::FileServerError(_))
        ));
        for n in 0..25 {
            client.remove(&dir.path(&format!("sub/f{n:02}"))).await?;
        }
        client.rmdir(&dir.path("sub")).await?;
        assert!(!dir.dir().join("sub").exists());
        Ok(())
    })
}

#[test]
fn symlinks_use_the_right_argument_order() {
    with_openssh("symlink", |mut client, dir| async move {
        fs::write(dir.dir().join("target"), b"abc").unwrap();

        client.symlink(&dir.path("target"), &dir.path("link")).await?;

        // The link is what was created, pointing at the target. If the
        // arguments were the wrong way around this is reversed.
        let meta = fs::symlink_metadata(dir.dir().join("link")).unwrap();
        assert!(meta.file_type().is_symlink(), "link is the symlink");
        assert_eq!(
            fs::read_link(dir.dir().join("link")).unwrap(),
            dir.dir().join("target")
        );

        let mut buf = [0u8; 512];
        assert_eq!(
            client.readlink(&dir.path("link"), &mut buf).await?,
            dir.path("target").as_bytes()
        );

        // stat follows the link, lstat doesn't
        assert_eq!(client.stat(&dir.path("link")).await?.size, Some(3));
        let lattrs = client.lstat(&dir.path("link")).await?;
        assert_eq!(lattrs.size, Some(dir.path("target").len() as u64));
        assert_eq!(lattrs.permissions.unwrap() & 0o170000, 0o120000, "S_IFLNK");
        Ok(())
    })
}

#[test]
fn rename_and_posix_rename() {
    with_openssh("rename", |mut client, dir| async move {
        fs::write(dir.dir().join("a"), b"one").unwrap();
        fs::write(dir.dir().join("b"), b"two").unwrap();

        // Version 3 rename won't replace an existing file
        assert!(matches!(
            client.rename(&dir.path("a"), &dir.path("b")).await,
            Err(SftpError::FileServerError(_))
        ));

        // The OpenSSH extension does
        client.posix_rename(&dir.path("a"), &dir.path("b")).await?;
        assert!(!dir.dir().join("a").exists());
        assert_eq!(fs::read(dir.dir().join("b")).unwrap(), b"one");

        client.rename(&dir.path("b"), &dir.path("c")).await?;
        assert_eq!(fs::read(dir.dir().join("c")).unwrap(), b"one");

        // And hardlink
        client.hardlink(&dir.path("c"), &dir.path("d")).await?;
        assert_eq!(fs::read(dir.dir().join("d")).unwrap(), b"one");
        Ok(())
    })
}

#[test]
fn attributes() {
    with_openssh("attrs", |mut client, dir| async move {
        let p = dir.path("f");
        fs::write(dir.dir().join("f"), b"12345").unwrap();

        let a = client.stat(&p).await?;
        assert_eq!(a.size, Some(5));
        assert!(a.permissions.is_some());
        assert!(a.uid.is_some() && a.gid.is_some());
        assert!(a.mtime.is_some());

        let set = Attrs { permissions: Some(0o640), ..Default::default() };
        client.setstat(&p, &set).await?;
        assert_eq!(client.stat(&p).await?.permissions.unwrap() & 0o777, 0o640);

        // Truncate by setting the size
        let set = Attrs { size: Some(2), ..Default::default() };
        client.setstat(&p, &set).await?;
        assert_eq!(fs::read(dir.dir().join("f")).unwrap(), b"12");

        let h = client.open_read(&p).await?;
        assert_eq!(client.fstat(&h).await?.size, Some(2));
        client.close(&h).await?;
        Ok(())
    })
}

#[test]
fn realpath_and_errors() {
    with_openssh("realpath", |mut client, dir| async move {
        // sftp-server was started with -d pointing at the test dir
        let mut buf = [0u8; 4096];
        assert_eq!(
            client.realpath(".", &mut buf).await?,
            dir.path("").trim_end_matches('/').as_bytes()
        );

        match client.open_read(&dir.path("missing")).await {
            Err(SftpError::FileServerError(StatusCode::SSH_FX_NO_SUCH_FILE)) => (),
            r => panic!("unexpected {r:?}"),
        }
        match client.stat(&dir.path("missing")).await {
            Err(SftpError::FileServerError(StatusCode::SSH_FX_NO_SUCH_FILE)) => (),
            r => panic!("unexpected {r:?}"),
        }

        // Still usable after errors
        let h = client.create(&dir.path("ok")).await?;
        client.close(&h).await?;
        Ok(())
    })
}
