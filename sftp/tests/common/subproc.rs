//! Runs OpenSSH's `sftp-server` as a subprocess to talk to.
//!
//! `sftp-server` speaks SFTP over stdin/stdout without any SSH around
//! it, so it can be driven directly.

#![allow(dead_code)]

use std::io::{Read as _, Write as _};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sunset_sftp::embedded_io_async::{ErrorType, Read, Write};
use sunset_sftp::sunset;

/// Where distributions put the OpenSSH SFTP server.
const CANDIDATES: &[&str] = &[
    "/usr/lib/openssh/sftp-server",
    "/usr/libexec/openssh/sftp-server",
    "/usr/libexec/sftp-server",
    "/usr/lib/ssh/sftp-server",
];

pub fn sftp_server_path() -> Option<&'static str> {
    CANDIDATES.iter().find(|p| std::path::Path::new(p).exists()).copied()
}

/// A running `sftp-server`, killed when dropped.
pub struct SftpServerProc {
    child: Arc<Mutex<Child>>,
    finished: Arc<AtomicBool>,
}

impl SftpServerProc {
    /// Starts `sftp-server`, returning it with its stdio.
    ///
    /// A watchdog kills it after `timeout`, so that a client waiting for
    /// a reply that never comes fails rather than hanging.
    pub fn start(
        path: &str,
        start_dir: &str,
        timeout: Duration,
    ) -> std::io::Result<(Self, PipeReader, PipeWriter)> {
        let mut child = Command::new(path)
            .arg("-e")
            .arg("-l")
            .arg("ERROR")
            .arg("-d")
            .arg(start_dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;

        // OK unwrap, both were piped above.
        let stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();

        let child = Arc::new(Mutex::new(child));
        let finished = Arc::new(AtomicBool::new(false));

        let watch_child = child.clone();
        let watch_finished = finished.clone();
        std::thread::spawn(move || {
            let step = Duration::from_millis(50);
            let mut waited = Duration::ZERO;
            while waited < timeout {
                std::thread::sleep(step);
                waited += step;
                if watch_finished.load(Ordering::Relaxed) {
                    return;
                }
            }
            // Killing closes the pipe, so a blocked read returns EOF.
            let _ = watch_child.lock().unwrap().kill();
        });

        Ok((Self { child, finished }, PipeReader(stdout), PipeWriter(stdin)))
    }
}

impl Drop for SftpServerProc {
    fn drop(&mut self) {
        self.finished.store(true, Ordering::Relaxed);
        if let Ok(mut c) = self.child.lock() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

/// Blocking IO is fine here, the peer is a separate process.
pub struct PipeReader(ChildStdout);
pub struct PipeWriter(ChildStdin);

impl ErrorType for PipeReader {
    type Error = sunset::Error;
}

impl ErrorType for PipeWriter {
    type Error = sunset::Error;
}

impl Read for PipeReader {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, sunset::Error> {
        self.0.read(buf).map_err(|_| sunset::Error::ChannelEOF)
    }
}

impl Write for PipeWriter {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, sunset::Error> {
        self.0.write(buf).map_err(|_| sunset::Error::ChannelEOF)
    }

    async fn flush(&mut self) -> Result<(), sunset::Error> {
        self.0.flush().map_err(|_| sunset::Error::ChannelEOF)
    }
}
