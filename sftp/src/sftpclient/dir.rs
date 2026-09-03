use embedded_io_async::{Read, Write};

use crate::error::{SftpError, SftpResult};
use crate::proto::Attrs;
use crate::sftpclient::packetread::{take_attrs, try_take_string};
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
    /// Empty if the server didn't provide one, or if it was too long for
    /// the client's buffer.
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
    /// Entries left in this `SSH_FXP_NAME` response
    remaining: u32,
}

impl<'a, R: Read, W: Write, const BUF: usize> DirIter<'a, R, W, BUF> {
    pub(crate) fn new(client: &'a mut SftpClient<R, W, BUF>, count: u32) -> Self {
        Self { client, remaining: count }
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
        if self.remaining == 0 {
            // The count is what the server announced. Anything left over
            // is a peer bug, discard it so the connection stays usable.
            self.client.drain_packet().await?;
            return Ok(None);
        }

        // The stream position is only known between entries.
        self.client.set_poisoned(true);
        let r = Self::read_entry(self.client).await;
        match r {
            Ok((flen, llen, attrs)) => {
                self.remaining -= 1;
                self.client.set_poisoned(false);
                let (_, _, buf) = self.client.reader_buf();
                Ok(Some(DirEntry {
                    filename: &buf[..flen],
                    longname: &buf[flen..flen + llen],
                    attrs,
                }))
            }
            Err(e) => {
                // Give up on the rest of the response. The client stays
                // poisoned unless the packet drains cleanly.
                self.remaining = 0;
                if self.client.drain_packet().await.is_ok() {
                    self.client.set_poisoned(false);
                }
                Err(e)
            }
        }
    }

    /// Reads one entry into the client's buffer.
    ///
    /// Returns the filename and long name lengths, which are stored
    /// consecutively at the start of the buffer.
    async fn read_entry(
        client: &mut SftpClient<R, W, BUF>,
    ) -> SftpResult<(usize, usize, Attrs)> {
        let (reader, rem, buf) = client.reader_buf();
        let flen = try_take_string(reader, rem, buf)
            .await?
            .ok_or_else(|| {
                warn!("Directory entry filename too long for the buffer");
                SftpError::NoRoom
            })?
            .len();

        let (reader, rem, buf) = client.reader_buf();
        // A long name that doesn't fit is dropped rather than failing,
        // the spec says it shouldn't be relied on.
        let llen = try_take_string(reader, rem, &mut buf[flen..])
            .await?
            .map_or(0, |l| l.len());

        let (reader, rem, _) = client.reader_buf();
        let attrs = take_attrs(reader, rem).await?;

        Ok((flen, llen, attrs))
    }
}
