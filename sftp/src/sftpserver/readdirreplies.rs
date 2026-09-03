use crate::{
    error::SftpResult,
    proto::{ENCODED_SSH_FXP_NAME_HEADER, NameEntry, ReqId, SftpNum},
    protocol::StatusCode,
    sftphandler::SftpOutputProducer,
    sftpsink::SftpSink,
};

use embedded_io_async::Write;

use sunset::sshwire::SSHEncode;

use log::{debug, error};

/// Structures and helpers to handle the process of sending read replies for readdir operations in a structured way.
///
/// Enforces the correct sequence of sending a DirRead reply,
/// which consists of first sending a header with the announced data length using [`DirReadHeaderReply::send_header`] and then sending the data itself using [`DirReadDataReply::send_data`].
pub struct DirReadHeaderReply<'a, 'p, W: Write> {
    /// The request Id that will be use`d in the response
    req_id: ReqId,
    chan_out: &'a mut SftpOutputProducer<'p, W>,
}

impl<'a, 'p, W: Write> DirReadHeaderReply<'a, 'p, W> {
    /// Creates a new DirReadHeaderReply with the given request ID and output channel.
    ///
    /// It is meant to be called in [`SftpHandler`] and used to call a method of the [`SftpServer`] that requires a read reply header, such as [`SftpServer::readdir`]
    pub(crate) fn new(
        req_id: ReqId,
        chan_out: &'a mut SftpOutputProducer<'p, W>,
    ) -> Self {
        Self { req_id, chan_out }
    }

    /// Sends the header for a read reply with the given data length.
    ///
    /// Once used, the only way to obtain a [`DirReadReplyFinished`] is by using its returned value.
    pub async fn send_header(
        self,
        data_len: u32,
        count: u32,
    ) -> SftpResult<DirReadDataReply<'a, 'p, W>> {
        debug!(
            "DirReadReply: Sending header for request id {:?}: data length = {:?}",
            self.req_id, data_len
        );

        let (mut sink, w) = self.chan_out.sink();
        Self::encode_header(&mut sink, self.req_id, data_len, count).map_err(
            |err| {
                error!("WireError: {:?}", err);
                StatusCode::SSH_FX_FAILURE
            },
        )?;

        // debug!(
        //     "Sending header:  len = {:?}, content = {:?}",
        //     payload.len(),
        //     payload
        // );
        // Sending payload_slice since we are not making use of the sink sftpPacket length calculation
        sink.send(w).await?;

        Ok(DirReadDataReply::new(self.req_id, data_len, self.chan_out))
    }

    /// Sends an EOF status response for the read request.
    ///
    /// It will return a [`DirReadReplyFinished`] that can be used to represent the state of the successful read reply.
    pub async fn send_eof(&mut self) -> SftpResult<DirReadReplyFinished> {
        self.chan_out.send_status(self.req_id, StatusCode::SSH_FX_EOF, "").await?;
        Ok(DirReadReplyFinished::new(self.req_id))
    }

    fn encode_header(
        sink: &mut SftpSink,
        req_id: ReqId,
        data_len: u32,
        count: u32,
    ) -> SftpResult<()> {
        // length field
        (data_len + ENCODED_SSH_FXP_NAME_HEADER).enc(sink)?;
        // packet type (1)
        u8::from(SftpNum::SSH_FXP_NAME).enc(sink)?;
        // request id (4)
        req_id.enc(sink)?;
        count.enc(sink)?;
        Ok(())
    }
}

/// Represents the state of a successful read reply for a readdir operation after the
/// header has been sent and the data has been completely sent or an EOF status has been sent.
pub struct DirReadReplyFinished {
    /// The request Id that will be use`d in the response
    _req_id: ReqId,
}

impl DirReadReplyFinished {
    pub(crate) fn new(req_id: ReqId) -> Self {
        Self { _req_id: req_id }
    }
}

/// Helper struct to enforce the correct sequence of sending directory items in a readdir
///  reply, which consists of sending items until the announced data length is reached.
pub struct LimitedDirSender<'a, 'g, W: Write> {
    /// Immutable writer
    chan_out: &'a mut SftpOutputProducer<'g, W>,
    /// remaining data length to be sent as announced in [`DirReadDataReply::send_data`]
    ///  when calling the closure with this LimitedDirSender as an argument.
    remaining: u32,
}

impl<'a, 'g, W: Write> LimitedDirSender<'a, 'g, W> {
    fn new(chan_out: &'a mut SftpOutputProducer<'g, W>, limit: u32) -> Self {
        Self { chan_out, remaining: limit }
    }

    /// Sends a directory item to the client as a [`NameEntry`]
    ///
    /// Call this
    pub async fn send_item(&mut self, name_entry: &NameEntry<'_>) -> SftpResult<()> {
        let (mut sink, w) = self.chan_out.sink();
        name_entry.enc(&mut sink)?;
        let l = sink.send(w).await?;
        self.remaining -= l;
        Ok(())
    }

    /// Obtains a [`CompleteDirDataSent`] if the announced data length has been completely sent, otherwise returns None.
    pub fn completed(&self) -> Option<CompleteDirDataSent> {
        if self.is_complete() { Some(CompleteDirDataSent) } else { None }
    }

    fn is_complete(&self) -> bool {
        self.remaining == 0
    }
}

/// Token struct to represent the state of having sent all the announced data for a readdir reply.
///
/// It can only be obtained by calling [`LimitedDirSender::completed`] after having
/// sent items with [`LimitedDirSender::send_item`] until the announced data length is reached.
///
/// It is used to guarantee that all the announced data has been sent in the closure
/// provided to [`DirReadDataReply::send_data`] before being able to return a [`DirReadReplyFinished`]
/// and thus completing the readdir reply process.
pub struct CompleteDirDataSent;

/// Helper struct to enforce the correct sequence of sending a readdir reply,
///  which consists of first sending a header with the announced data length
/// using [`DirReadHeaderReply::send_header`] and then sending the data
///  itself using [`DirReadDataReply::send_data`].
pub struct DirReadDataReply<'a, 'g, W: Write> {
    /// The request Id that will be use`d in the response
    req_id: ReqId,
    /// Length of data to be sent as announced in [`DirReadHeaderReply::send_header`]
    data_len: u32,
    chan_out: &'a mut SftpOutputProducer<'g, W>,
}

impl<'a, 'g, W: Write> DirReadDataReply<'a, 'g, W> {
    pub(crate) fn new(
        req_id: ReqId,
        data_len: u32,
        chan_out: &'a mut SftpOutputProducer<'g, W>,
    ) -> Self {
        Self { req_id, chan_out, data_len }
    }

    /// A closure-based API where the user can send multiple [`NameEntry`]s of data until the announced data length is reached.
    ///
    /// It can only be called once, since it consumes self, and it returns a [`DirReadReplyFinished`]
    /// that can be used to represent the state of the successful read reply.
    pub async fn send_data<F, Fut>(self, f: F) -> SftpResult<DirReadReplyFinished>
    where
        F: FnOnce(LimitedDirSender<'a, 'g, W>) -> Fut,
        Fut: Future<Output = SftpResult<CompleteDirDataSent>>,
    {
        let dir_sender = LimitedDirSender::new(self.chan_out, self.data_len);
        f(dir_sender).await?;

        Ok(DirReadReplyFinished::new(self.req_id))
    }
}

#[cfg(test)]
mod enforcing_process_tests {

    use super::*;

    use crate::{
        proto::{Attrs, Filename, NameEntry},
        server::helpers,
        sftperror::SftpError,
        sftphandler::{MockWriter, SftpOutputProducer},
    };

    extern crate alloc;
    extern crate std;
    use std::vec::Vec;

    #[test]
    fn handling_process_eof() {
        const N: usize = 512;

        let req_id = ReqId(42);
        let mut buf = [0u8; N];
        let mut mock = MockWriter::new();
        let mut producer = SftpOutputProducer::new(&mut mock, &mut buf);

        embassy_futures::block_on(async {
            {
                let mut dir_header_reply =
                    DirReadHeaderReply::new(req_id, &mut producer);
                let _finished = dir_header_reply
                    .send_eof()
                    .await
                    .expect("send_eof should succeed returning ReadReplyFinished");
            }
        });

        // SSH_FXP_STATUS (101) packet for SSH_FX_EOF (1) with req_id 42:
        // [len:4][type:1=101][req_id:4][code:4][msg_len:4][msg][lang_len:4][lang]
        let buf = &mock.buffer;
        // packet type byte should be 101 (SSH_FXP_STATUS)
        assert_eq!(buf[4], 101, "expected SSH_FXP_STATUS packet type");
        // status code should be 1 (SSH_FX_EOF)
        let code = u32::from_be_bytes(buf[9..13].try_into().unwrap());
        assert_eq!(code, 1, "expected SSH_FX_EOF status code");
    }

    #[test]
    fn handling_process_data() {
        const N: usize = 2048;

        let req_id = ReqId(42);
        let mut buf = [0u8; N];
        let mut mock = MockWriter::new();
        let mut producer = SftpOutputProducer::new(&mut mock, &mut buf);

        // 1. Put together a collection of synthetic directory entries
        let filenames = ["file1", "file2", "file3"];
        let name_entries: Vec<NameEntry<'_>> = filenames
            .iter()
            .map(|name| NameEntry {
                filename: Filename::from(*name),
                _longname: Filename::from(""),
                attrs: Attrs::default(),
            })
            .collect();

        // 2. Obtain the length of the data to be sent by encoding these synthetic directory entries and summing their lengths
        let items_encoded_len = name_entries.iter().fold(0u32, |acc: u32, entry| {
            let len = helpers::get_name_entry_len(entry)
                .expect("Decoding should not fail");
            acc.checked_add(len)
                .expect("Length overflow when calculating total encoded length")
        });

        let items_count =
            u32::try_from(name_entries.len()).expect("Count should fit in u32");

        embassy_futures::block_on(async {
            {
                let dir_header_reply =
                    DirReadHeaderReply::new(req_id, &mut producer);

                // 3. Call send_header with the length of the data to be sent
                let dir_read_data_reply = dir_header_reply
                    .send_header(items_encoded_len, items_count)
                    .await
                    .expect("send_eof should succeed returning ReadReplyData");

                let _dir_read_reply_finished = dir_read_data_reply
                    .send_data(|mut limited_sender| async move {
                        for entry in name_entries.iter() {
                            limited_sender.send_item(entry).await?;
                        }
                        match limited_sender.completed() {
                            Some(completed_token) => Ok(completed_token),
                            None => Err(SftpError::FileServerError(
                                StatusCode::SSH_FX_FAILURE,
                            )),
                        }
                    })
                    .await
                    .expect("send_data should succeed returning ReadReplyFinished");
            }
        });

        let buf = &mock.buffer;
        // packet type byte should be 104 (SSH_FXP_NAME)
        assert_eq!(buf[4], 104, "expected SSH_FXP_NAME packet type");

        // data length should be
        let items = u32::from_be_bytes(
            buf[9..13]
                .try_into()
                .expect("data length should be present in the packet"),
        );
        assert_eq!(
            items, items_count,
            "expected data length to match encoded length"
        );
        assert_eq!(
            buf.len(),
            13 + items_encoded_len as usize,
            "expected packet length to be header (13 bytes) + data (items_encoded_len bytes)"
        );
    }
}

/// no_std compatible helpers to perform common tasks using solely sunset and sunset-sftp resources
pub mod helpers {
    use core::fmt::Write;

    use crate::{
        error::{SftpError, SftpResult},
        proto::{Attrs, MAX_NAME_ENTRY_SIZE, NameEntry},
        sftpsink::SftpSink,
    };

    use sunset::sshwire::SSHEncode;

    /// Helper function to get the length of a given [`NameEntry`]
    /// as it would be serialized to the wire.
    ///
    /// Use this function to calculate the total length of a collection
    /// of `NameEntry`s in order to send a correct response Name header
    pub fn get_name_entry_len(name_entry: &NameEntry<'_>) -> SftpResult<u32> {
        let mut buf = [0u8; MAX_NAME_ENTRY_SIZE];
        let mut temp_sink = SftpSink::new(&mut buf);
        name_entry.enc(&mut temp_sink)?;
        Ok(temp_sink.payload_len() as u32)
    }

    /// Space needed by [`write_long_name`] for everything but the name.
    pub const LONG_NAME_PREFIX_LEN: usize = 64;

    /// Formats an `ls -l` style long name into `buf`.
    ///
    /// SFTP version 3 leaves the `longname` field of a `SSH_FXP_NAME`
    /// entry undefined and says clients shouldn't parse it, but
    /// OpenSSH's `sftp` prints it verbatim for `ls -l`. A server that
    /// sends an empty long name gives blank lines there, so it is worth
    /// filling in.
    ///
    /// SFTP has no link count, so 1 is always reported. Fails with
    /// [`SftpError::NoRoom`] unless `buf` has room for the name plus
    /// [`LONG_NAME_PREFIX_LEN`].
    pub fn write_long_name<'b>(
        buf: &'b mut [u8],
        filename: &[u8],
        attrs: &Attrs,
    ) -> SftpResult<&'b [u8]> {
        let mode = attrs.permissions.unwrap_or(0);

        // The file type, from the S_IFMT bits
        let kind = match mode & 0o170000 {
            0o040000 => 'd',
            0o120000 => 'l',
            0o100000 => '-',
            0o020000 => 'c',
            0o060000 => 'b',
            0o010000 => 'p',
            0o140000 => 's',
            _ => '?',
        };

        let mut w = SliceWrite { buf, pos: 0 };
        w.write_char(kind).map_err(|_| SftpError::NoRoom)?;
        for shift in [6, 3, 0] {
            let bits = (mode >> shift) & 0o7;
            for (bit, c) in [(0o4, 'r'), (0o2, 'w'), (0o1, 'x')] {
                let c = if bits & bit != 0 { c } else { '-' };
                w.write_char(c).map_err(|_| SftpError::NoRoom)?;
            }
        }

        write!(
            w,
            " {:>3} {:<8} {:<8} {:>8} ",
            1,
            attrs.uid.unwrap_or(0),
            attrs.gid.unwrap_or(0),
            attrs.size.unwrap_or(0),
        )
        .map_err(|_| SftpError::NoRoom)?;

        match attrs.mtime {
            Some(t) => write_time(&mut w, t),
            // Keep the columns lined up
            None => write!(w, "            "),
        }
        .map_err(|_| SftpError::NoRoom)?;
        w.write_char(' ').map_err(|_| SftpError::NoRoom)?;

        let pos = w.pos;
        let end = pos.checked_add(filename.len()).ok_or(SftpError::NoRoom)?;
        let out = buf.get_mut(..end).ok_or(SftpError::NoRoom)?;
        out[pos..].copy_from_slice(filename);
        Ok(out)
    }

    /// Formats a unix timestamp as `ls -l` does, in UTC.
    fn write_time(w: &mut SliceWrite<'_>, secs: u32) -> core::fmt::Result {
        const MONTHS: [&str; 12] = [
            "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct",
            "Nov", "Dec",
        ];

        let days = (secs / 86400) as i64;
        let time_of_day = secs % 86400;

        // Days to a civil date, from Howard Hinnant's chrono algorithms
        let z = days + 719468;
        let era = if z >= 0 { z } else { z - 146096 } / 146097;
        let doe = z - era * 146097;
        let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let day = doy - (153 * mp + 2) / 5 + 1;
        let month = if mp < 10 { mp + 3 } else { mp - 9 };

        write!(
            w,
            "{} {:>2} {:02}:{:02}",
            MONTHS[(month - 1) as usize],
            day,
            time_of_day / 3600,
            (time_of_day % 3600) / 60,
        )
    }

    /// Formats into a fixed slice, for `no_std` without allocation.
    struct SliceWrite<'a> {
        buf: &'a mut [u8],
        pos: usize,
    }

    impl Write for SliceWrite<'_> {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            let end = self.pos.checked_add(s.len()).ok_or(core::fmt::Error)?;
            let d = self.buf.get_mut(self.pos..end).ok_or(core::fmt::Error)?;
            d.copy_from_slice(s.as_bytes());
            self.pos = end;
            Ok(())
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn long_name_matches_ls() {
            let attrs = Attrs {
                size: Some(3000000),
                uid: Some(0),
                gid: Some(0),
                permissions: Some(0o100644),
                // 2026-09-03 16:32:00 UTC
                mtime: Some(1788453120),
                ..Default::default()
            };
            let mut buf = [0u8; 128];
            let l = write_long_name(&mut buf, b"big.bin", &attrs).unwrap();
            assert_eq!(
                core::str::from_utf8(l).unwrap(),
                "-rw-r--r--   1 0        0         3000000 Sep  3 16:32 big.bin"
            );
        }

        #[test]
        fn long_name_kinds() {
            let dir = Attrs { permissions: Some(0o040755), ..Default::default() };
            let mut buf = [0u8; 128];
            let l = write_long_name(&mut buf, b"d", &dir).unwrap();
            assert!(l.starts_with(b"drwxr-xr-x"));

            let link = Attrs { permissions: Some(0o120777), ..Default::default() };
            let l = write_long_name(&mut buf, b"l", &link).unwrap();
            assert!(l.starts_with(b"lrwxrwxrwx"));

            // Nothing known about it
            let l = write_long_name(&mut buf, b"x", &Attrs::default()).unwrap();
            assert!(l.starts_with(b"?---------"));
        }

        #[test]
        fn long_name_needs_room() {
            let mut buf = [0u8; 8];
            assert!(matches!(
                write_long_name(&mut buf, b"x", &Attrs::default()),
                Err(SftpError::NoRoom)
            ));
        }
    }
}
