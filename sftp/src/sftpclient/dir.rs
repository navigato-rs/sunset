use embedded_io_async::{Read, Write};

use crate::error::{SftpError, SftpResult};
use crate::proto::{Attrs, ReqId};
use crate::sftpclient::runner::SftpEvent;
use crate::sftpclient::sftpclient::SftpClient;

#[allow(unused_imports)]
use log::{debug, error, info, log, trace, warn};

/// One entry of a directory listing.
///
/// The name borrows the client's buffer, so only one entry exists at a
/// time. Copy anything that is needed for longer.
#[derive(Debug)]
pub struct DirEntry<'a> {
    filename: &'a [u8],
    longname: &'a [u8],
    attrs: Attrs,
}

impl<'a> DirEntry<'a> {
    /// The file name, relative to the directory being listed.
    ///
    /// SFTP version 3 doesn't define an encoding for filenames, so these
    /// are raw bytes. [`filename_str()`](Self::filename_str) is
    /// available where UTF-8 is expected.
    pub fn filename(&self) -> &'a [u8] {
        self.filename
    }

    /// The file name as a `str`.
    ///
    /// Fails with [`SftpError::BadResponse`] if it isn't valid UTF-8.
    pub fn filename_str(&self) -> SftpResult<&'a str> {
        core::str::from_utf8(self.filename).map_err(|_| {
            debug!("Filename is not UTF-8");
            SftpError::BadResponse
        })
    }

    /// The server's `ls -l` style description of the entry.
    ///
    /// The format is unspecified, so this is only useful for display.
    /// Empty if the server didn't provide one.
    pub fn longname(&self) -> &'a [u8] {
        self.longname
    }

    /// Attributes of the entry.
    pub fn attrs(&self) -> &Attrs {
        &self.attrs
    }
}

/// A batch of directory entries from [`SftpClient::readdir`].
///
/// Returned entries are read from the connection as
/// [`next()`](Self::next) is called, rather than being buffered.
/// Dropping this before the entries are exhausted is fine, the rest are
/// discarded when the next request is made.
pub struct DirIter<'a, R: Read, W: Write, const BUF: usize> {
    client: &'a mut SftpClient<R, W, BUF>,
    /// The readdir this is answering
    id: ReqId,
    /// Entries left in this `SSH_FXP_NAME` response
    remaining: u32,
    /// Set once the response has ended, or gone wrong
    done: bool,
}

impl<'a, R: Read, W: Write, const BUF: usize> DirIter<'a, R, W, BUF> {
    pub(crate) fn new(
        client: &'a mut SftpClient<R, W, BUF>,
        id: ReqId,
        count: u32,
    ) -> Self {
        Self { client, id, remaining: count, done: false }
    }

    /// Number of entries left in this batch.
    pub fn remaining(&self) -> u32 {
        self.remaining
    }

    /// Returns the next entry, or `None` at the end of the batch.
    ///
    /// [`SftpClient::readdir`] must be called again for further entries,
    /// until it returns `None`.
    pub async fn next(&mut self) -> SftpResult<Option<DirEntry<'_>>> {
        if self.done {
            return Ok(None);
        }
        self.client.wait_event().await?;

        // `self.done` and `self.remaining` are set alongside the event,
        // which borrows `self.client`.
        let want = self.id;
        match self.client.runner.event() {
            Some(SftpEvent::Name { id, filename, longname, attrs })
                if id == want =>
            {
                self.remaining = self.remaining.saturating_sub(1);
                Ok(Some(DirEntry { filename, longname, attrs }))
            }
            Some(SftpEvent::NameEnd { id }) if id == want => {
                self.done = true;
                self.remaining = 0;
                Ok(None)
            }
            ev => {
                debug!("Unexpected {:?} listing a directory", ev);
                // Whatever is left of the response is discarded before
                // the next request.
                self.done = true;
                self.remaining = 0;
                Err(SftpError::BadResponse)
            }
        }
    }
}
