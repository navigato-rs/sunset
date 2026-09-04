//! Drives [`SftpRunner`] from a plain blocking loop, with no executor,
//! no futures, and no `embedded_io_async`.
//!
//! This is the point of the runner: the caller moves the bytes. Here
//! they are moved with `std::io` against OpenSSH's `sftp-server`, which
//! also checks the sequence against a real peer rather than a mock.
//!
//! Skipped when OpenSSH isn't installed.

use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use sunset_sftp::client::{DEFAULT_CLIENT_BUF, SftpEvent, SftpRunner, pflags};
use sunset_sftp::error::{SftpError, SftpResult};
use sunset_sftp::protocol::{Attrs, StatusCode};

/// Where distributions put the OpenSSH SFTP server.
const CANDIDATES: &[&str] = &[
    "/usr/lib/openssh/sftp-server",
    "/usr/libexec/openssh/sftp-server",
    "/usr/libexec/sftp-server",
    "/usr/lib/ssh/sftp-server",
];

/// A SFTP client built from the runner and blocking IO.
struct Client {
    runner: SftpRunner<{ DEFAULT_CLIENT_BUF }, { DEFAULT_CLIENT_BUF }>,
    child: Child,
    stdin: ChildStdin,
    stdout: ChildStdout,
}

/// A reply, with nothing borrowed from the runner.
#[derive(Debug)]
enum Reply {
    Version,
    Handle(Vec<u8>),
    Attrs(Attrs),
    Status(StatusCode),
    Data(usize),
    NameStart(u32),
    Name(Vec<u8>),
    NameEnd,
}

impl Client {
    fn start(server: &str, dir: &str) -> Option<Self> {
        let mut child = Command::new(server)
            .arg("-d")
            .arg(dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .ok()?;
        let stdin = child.stdin.take()?;
        let stdout = child.stdout.take()?;
        Some(Self { runner: SftpRunner::new(), child, stdin, stdout })
    }

    /// Hands the peer everything the runner has queued, plus `data` for
    /// a write request.
    fn send(&mut self, data: &[u8]) -> SftpResult<()> {
        while !self.runner.output_buf().is_empty() {
            let n = self
                .stdin
                .write(self.runner.output_buf())
                .map_err(|_| SftpError::Disconnected)?;
            self.runner.consume_output(n);
        }
        if let Some(len) = self.runner.send_data() {
            self.stdin
                .write_all(&data[..len])
                .map_err(|_| SftpError::Disconnected)?;
            self.runner.data_sent(len);
        }
        self.stdin.flush().map_err(|_| SftpError::Disconnected)
    }

    /// Reads until the runner has something to say.
    fn wait_event(&mut self) -> SftpResult<()> {
        while !self.runner.has_event() {
            let dest = self.runner.input_buf();
            assert!(!dest.is_empty(), "nowhere to read into");
            let n = self.stdout.read(dest).map_err(|_| SftpError::Disconnected)?;
            if n == 0 {
                return Err(SftpError::Disconnected);
            }
            self.runner.input_done(n)?;
        }
        Ok(())
    }

    fn reply(&mut self) -> SftpResult<Reply> {
        self.wait_event()?;
        // OK unwrap, wait_event() only returns with one ready
        Ok(match self.runner.event().unwrap() {
            SftpEvent::Version { .. } => Reply::Version,
            SftpEvent::Handle { handle, .. } => Reply::Handle(handle.to_vec()),
            SftpEvent::Attrs { attrs, .. } => Reply::Attrs(attrs),
            SftpEvent::Status { code, .. } => Reply::Status(code),
            SftpEvent::Data { len, .. } => Reply::Data(len),
            SftpEvent::NameStart { count, .. } => Reply::NameStart(count),
            SftpEvent::Name { filename, .. } => Reply::Name(filename.to_vec()),
            SftpEvent::NameEnd { .. } => Reply::NameEnd,
        })
    }

    /// Takes file data straight off the stream, never through the runner.
    fn take_data(&mut self, dest: &mut [u8]) -> SftpResult<()> {
        self.stdout.read_exact(dest).map_err(|_| SftpError::Disconnected)?;
        self.runner.data_taken(dest.len());
        Ok(())
    }

    fn ok_status(&mut self) -> SftpResult<()> {
        match self.reply()? {
            Reply::Status(StatusCode::SSH_FX_OK) => Ok(()),
            Reply::Status(c) => Err(SftpError::FileServerError(c)),
            r => panic!("expected a status, got {r:?}"),
        }
    }

    fn handle(&mut self) -> SftpResult<Vec<u8>> {
        match self.reply()? {
            Reply::Handle(h) => Ok(h),
            Reply::Status(c) => Err(SftpError::FileServerError(c)),
            r => panic!("expected a handle, got {r:?}"),
        }
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A directory of its own, removed afterwards.
struct TestDir(PathBuf);

impl TestDir {
    fn new(name: &str) -> Self {
        let d = std::env::temp_dir()
            .join(format!("sunset-sftp-sync-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).expect("create test dir");
        Self(fs::canonicalize(&d).expect("canonicalize"))
    }

    fn path(&self, rel: &str) -> String {
        self.0.join(rel).to_str().expect("utf-8 path").to_string()
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// The whole session, driven by hand without an executor in sight.
#[test]
fn a_session_without_an_executor() {
    let Some(server) = CANDIDATES.iter().find(|p| std::path::Path::new(p).exists())
    else {
        eprintln!("OpenSSH sftp-server not installed, skipping");
        return;
    };
    let dir = TestDir::new("session");
    let mut c = Client::start(server, dir.path(".").as_str()).expect("start server");

    // Handshake
    c.runner.init().unwrap();
    c.send(&[]).unwrap();
    assert!(matches!(c.reply().unwrap(), Reply::Version));
    assert_eq!(c.runner.version(), Some(3));

    // Write a file, in two chunks so the payload path is exercised
    let body: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
    let path = dir.path("f.bin");
    c.runner
        .open(
            &path,
            pflags::WRITE | pflags::CREAT | pflags::TRUNC,
            &Attrs::default(),
        )
        .unwrap();
    c.send(&[]).unwrap();
    let h = c.handle().unwrap();

    for (off, part) in [(0usize, &body[..2000]), (2000, &body[2000..])] {
        c.runner.write(&h, off as u64, part.len()).unwrap();
        c.send(part).unwrap();
        c.ok_status().unwrap();
    }
    c.runner.close(&h).unwrap();
    c.send(&[]).unwrap();
    c.ok_status().unwrap();

    // The size the server reports is the size that was written
    c.runner.stat(&path).unwrap();
    c.send(&[]).unwrap();
    match c.reply().unwrap() {
        Reply::Attrs(a) => assert_eq!(a.size, Some(body.len() as u64)),
        r => panic!("expected attrs, got {r:?}"),
    }

    // Read it back, one request at a time
    c.runner.open(&path, pflags::READ, &Attrs::default()).unwrap();
    c.send(&[]).unwrap();
    let h = c.handle().unwrap();

    let mut got = Vec::new();
    loop {
        c.runner.read(&h, got.len() as u64, 1024).unwrap();
        c.send(&[]).unwrap();
        match c.reply().unwrap() {
            Reply::Data(len) => {
                let mut buf = vec![0u8; len];
                c.take_data(&mut buf).unwrap();
                got.extend_from_slice(&buf);
            }
            Reply::Status(StatusCode::SSH_FX_EOF) => break,
            r => panic!("expected data, got {r:?}"),
        }
    }
    assert_eq!(got, body, "the file came back as it went out");

    c.runner.close(&h).unwrap();
    c.send(&[]).unwrap();
    c.ok_status().unwrap();

    // List the directory
    c.runner.opendir(dir.path(".").as_str()).unwrap();
    c.send(&[]).unwrap();
    let d = c.handle().unwrap();

    let mut names: Vec<Vec<u8>> = Vec::new();
    loop {
        c.runner.readdir(&d).unwrap();
        c.send(&[]).unwrap();
        match c.reply().unwrap() {
            Reply::NameStart(count) => {
                let mut seen = 0;
                loop {
                    match c.reply().unwrap() {
                        Reply::Name(n) => {
                            names.push(n);
                            seen += 1;
                        }
                        Reply::NameEnd => break,
                        r => panic!("expected a name, got {r:?}"),
                    }
                }
                assert_eq!(seen, count, "as many entries as announced");
            }
            Reply::Status(StatusCode::SSH_FX_EOF) => break,
            r => panic!("expected names, got {r:?}"),
        }
    }
    assert!(names.iter().any(|n| n == b"f.bin"), "the file was listed: {names:?}");

    c.runner.close(&d).unwrap();
    c.send(&[]).unwrap();
    c.ok_status().unwrap();

    // And clean up through the protocol as well
    c.runner.remove(&path).unwrap();
    c.send(&[]).unwrap();
    c.ok_status().unwrap();

    c.runner.stat(&path).unwrap();
    c.send(&[]).unwrap();
    assert!(matches!(
        c.reply().unwrap(),
        Reply::Status(StatusCode::SSH_FX_NO_SUCH_FILE)
    ));
}
