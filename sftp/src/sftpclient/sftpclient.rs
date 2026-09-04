use core::fmt;

use embedded_io_async::{Read, Write};
use sunset::sshwire::{SSHEncode, TextString};

use crate::error::{SftpError, SftpResult};
use crate::proto::{
    Attrs, MAX_HANDLE_LEN, MAX_REQUEST_LEN, Rename, ReqId, StatusCode,
};
use crate::sftpclient::dir::DirIter;
use crate::sftpclient::runner::{
    DEFAULT_CLIENT_BUF, MAX_READ_LEN, MAX_WRITE_LEN, SftpEvent, SftpRunner, pflags,
};

#[allow(unused_imports)]
use log::{debug, error, info, log, trace, warn};

/// Number of requests kept in flight during a transfer.
///
/// Each request otherwise costs a round trip, which is what limits a
/// transfer over anything but a local link. A `buf` of
/// `PIPELINE_DEPTH * MAX_READ_LEN` is the most a single
/// [`read()`](SftpClient::read) can fetch in one round trip.
///
/// This is deliberately modest. Requests sent ahead consume the SSH
/// channel's send window, and a peer that stops reading while it is
/// blocked sending a large reply could otherwise deadlock. Read
/// requests are tiny, and a peer's replies to pipelined writes are just
/// status packets, so neither direction fills a window here.
pub const PIPELINE_DEPTH: usize = 8;

/// Shorthand within this module.
const PIPELINE: usize = PIPELINE_DEPTH;

/// Records the lowest numbered chunk that came back short.
///
/// The contiguous data ends there, whatever later chunks returned.
fn note_short(short: &mut Option<(usize, usize)>, idx: usize, len: usize) {
    if short.is_none_or(|(i, _)| idx < i) {
        *short = Some((idx, len));
    }
}

/// Converts a status response to a result.
fn status_result(code: StatusCode) -> SftpResult<()> {
    match code {
        StatusCode::SSH_FX_OK => Ok(()),
        code => {
            debug!("SFTP request failed: {:?}", code);
            Err(SftpError::FileServerError(code))
        }
    }
}

/// Checks a reply belongs to the request that was made.
fn check_id(got: ReqId, want: ReqId) -> SftpResult<()> {
    if got == want {
        Ok(())
    } else {
        debug!("Response for {:?}, expected {:?}", got, want);
        Err(SftpError::BadResponse)
    }
}

/// Whether a [`RemoteHandle`] came from an open or an opendir.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HandleKind {
    File,
    Dir,
}

/// A handle for a file or directory open on the SFTP server.
///
/// The contents are opaque, defined by the server. Handles are returned
/// by [`SftpClient::open`] and [`SftpClient::opendir`], and must be
/// given back to [`SftpClient::close`] when finished with.
#[derive(Clone)]
pub struct RemoteHandle {
    handle: [u8; MAX_HANDLE_LEN],
    len: u16,
    kind: HandleKind,
}

impl RemoteHandle {
    /// True for handles from [`SftpClient::opendir`].
    pub fn is_dir(&self) -> bool {
        self.kind == HandleKind::Dir
    }

    fn new(handle: &[u8], kind: HandleKind) -> SftpResult<Self> {
        if handle.is_empty() || handle.len() > MAX_HANDLE_LEN {
            debug!("Server handle of {} bytes is unusable", handle.len());
            return Err(SftpError::NoRoom);
        }
        let mut h =
            Self { handle: [0; MAX_HANDLE_LEN], len: handle.len() as u16, kind };
        h.handle[..handle.len()].copy_from_slice(handle);
        Ok(h)
    }

    fn as_bytes(&self) -> &[u8] {
        &self.handle[..self.len as usize]
    }

    /// Checks the handle is the expected kind before using it.
    fn check(&self, kind: HandleKind) -> SftpResult<()> {
        if self.kind == kind {
            Ok(())
        } else {
            debug!("Wrong handle kind, {:?} is not {:?}", self.kind, kind);
            Err(SftpError::BadHandle)
        }
    }
}

impl fmt::Debug for RemoteHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RemoteHandle")
            .field("kind", &self.kind)
            .field("len", &self.len)
            .finish()
    }
}

/// A reply, reduced to something that doesn't borrow the runner.
#[derive(Debug)]
enum Reply {
    Version(u32),
    Handle(RemoteHandle),
    Attrs(Attrs),
    Status(StatusCode),
    /// `len` bytes of file data follow, taken with `take_data()`
    Data(usize),
    /// A name reply of `count` entries begins
    NameStart(u32),
    /// One name entry, whose filename is `len` bytes long
    Name(usize),
    NameEnd,
}

/// A SFTP client.
///
/// Wraps the [`Read`] and [`Write`] halves of a SSH channel that has had
/// the `sftp` subsystem started on it.
///
/// [`init()`](Self::init) must be called once before any other request.
///
/// This is IO around [`SftpRunner`], which is the protocol itself.
/// Anything that isn't `embedded_io_async` shaped can drive that
/// directly instead.
///
/// `BUF` sizes the buffer that holds the parts of a reply which aren't
/// file data: a handle, a status, one directory entry.
/// [`DEFAULT_CLIENT_BUF`] fits the largest of those. File contents and
/// directory listings are streamed, so they are not limited by `BUF`.
///
/// Requests are made one at a time, except within a single
/// [`read()`](Self::read), which pipelines.
///
/// ```
/// use sunset_sftp::client::SftpClient;
/// use sunset_sftp::embedded_io_async::{Read, Write};
/// use sunset_sftp::error::SftpResult;
///
/// // chan_in and chan_out are the two halves of the SFTP channel.
/// async fn upload(
///     chan_in: impl Read,
///     chan_out: impl Write,
///     data: &[u8],
/// ) -> SftpResult<()> {
///     let mut client = SftpClient::new_default_buffer(chan_in, chan_out);
///     client.init().await?;
///
///     let f = client.create("/tmp/hello").await?;
///     for (i, chunk) in data.chunks(4096).enumerate() {
///         client.write(&f, (i * 4096) as u64, chunk).await?;
///     }
///     client.close(&f).await
/// }
/// ```
pub struct SftpClient<R: Read, W: Write, const BUF: usize> {
    reader: R,
    writer: W,
    pub(super) runner: SftpRunner<MAX_REQUEST_LEN, BUF>,

    /// Set while the position in the stream is unknown.
    ///
    /// Only while bytes are being moved: everything else the runner
    /// holds, so an interrupted request no longer costs the session.
    poisoned: bool,
}

impl<R: Read, W: Write> SftpClient<R, W, DEFAULT_CLIENT_BUF> {
    /// Creates a `SftpClient` with a [`DEFAULT_CLIENT_BUF`] sized buffer.
    pub const fn new_default_buffer(reader: R, writer: W) -> Self {
        Self::new(reader, writer)
    }
}

impl<R: Read, W: Write, const BUF: usize> SftpClient<R, W, BUF> {
    /// Creates a `SftpClient` over an already established SFTP channel.
    ///
    /// [`init()`](Self::init) must be called before any request.
    ///
    /// Panics if `BUF` is too small, see [`DEFAULT_CLIENT_BUF`].
    pub const fn new(reader: R, writer: W) -> Self {
        Self { reader, writer, runner: SftpRunner::new(), poisoned: false }
    }

    /// Returns the underlying channel halves.
    pub fn into_parts(self) -> (R, W) {
        (self.reader, self.writer)
    }

    /// The negotiated SFTP version, or `None` before [`init()`](Self::init).
    pub fn version(&self) -> Option<u32> {
        self.runner.version()
    }

    /// Extensions announced by the server in its `SSH_FXP_VERSION`.
    pub fn extensions(&self) -> crate::proto::Extensions {
        self.runner.extensions()
    }

    // ============================ Moving bytes ============================

    /// Sends what the runner has queued, then `data` if the request
    /// carries a payload.
    async fn send_out(&mut self, data: &[u8]) -> SftpResult<()> {
        // A half sent request leaves the peer mid-packet, which nothing
        // can recover from.
        self.poisoned = true;
        while !self.runner.output_buf().is_empty() {
            let out = self.runner.output_buf();
            let n =
                self.writer.write(out).await.map_err(SftpError::from_embedded_io)?;
            if n == 0 {
                return Err(SftpError::Disconnected);
            }
            self.runner.consume_output(n);
        }

        if let Some(len) = self.runner.send_data() {
            let len = len.min(data.len());
            self.writer
                .write_all(&data[..len])
                .await
                .map_err(SftpError::from_embedded_io)?;
            self.runner.data_sent(len);
        }
        self.writer.flush().await.map_err(SftpError::from_embedded_io)?;
        self.poisoned = false;
        Ok(())
    }

    /// Reads more of the peer's reply into the runner.
    async fn fill(&mut self) -> SftpResult<()> {
        let dest = self.runner.want_buf();
        if dest.is_empty() {
            // Something is waiting for the caller, reading would block
            // for a reply that has already arrived.
            debug!("Nowhere to read into");
            return Err(sunset::error::BadUsage.build().into());
        }
        let n = self.reader.read(dest).await.map_err(SftpError::from_embedded_io)?;
        if n == 0 {
            return Err(SftpError::Disconnected);
        }
        self.runner.input_done(n)
    }

    /// Reads until the runner has an event.
    pub(super) async fn wait_event(&mut self) -> SftpResult<()> {
        while !self.runner.has_event() {
            self.fill().await?;
        }
        Ok(())
    }

    /// Takes file data straight into `dest`, without going through the
    /// runner.
    async fn take_data(&mut self, dest: &mut [u8]) -> SftpResult<()> {
        // Data half read leaves the stream mid-packet.
        self.poisoned = true;
        let mut done = 0;
        while done < dest.len() {
            let n = self
                .reader
                .read(&mut dest[done..])
                .await
                .map_err(SftpError::from_embedded_io)?;
            if n == 0 {
                return Err(SftpError::Disconnected);
            }
            done += n;
        }
        self.runner.data_taken(dest.len());
        self.poisoned = false;
        Ok(())
    }

    // ========================= Request/reply flow =========================

    /// The next reply, with any name entry copied into `out`.
    ///
    /// The returned length is the entry's, which may be longer than
    /// `out`; only what fits is copied.
    async fn next_reply(&mut self, out: &mut [u8]) -> SftpResult<(ReqId, Reply)> {
        self.wait_event().await?;
        // OK unwrap, wait_event() only returns with one ready
        let ev = self.runner.event().unwrap();
        trace!("SFTP <---- {:?}", ev);
        let r = match ev {
            SftpEvent::Version { version } => (ReqId(0), Reply::Version(version)),
            SftpEvent::Handle { id, handle } => {
                (id, Reply::Handle(RemoteHandle::new(handle, HandleKind::File)?))
            }
            SftpEvent::Attrs { id, attrs } => (id, Reply::Attrs(attrs)),
            SftpEvent::Status { id, code } => (id, Reply::Status(code)),
            SftpEvent::Data { id, len } => (id, Reply::Data(len)),
            SftpEvent::NameStart { id, count } => (id, Reply::NameStart(count)),
            SftpEvent::Name { id, filename, .. } => {
                let n = filename.len().min(out.len());
                out[..n].copy_from_slice(&filename[..n]);
                (id, Reply::Name(filename.len()))
            }
            SftpEvent::NameEnd { id } => (id, Reply::NameEnd),
        };
        Ok(r)
    }

    /// Takes file data the caller has nowhere to put.
    ///
    /// It still has to come off the stream, otherwise the next reply
    /// can't be found.
    async fn discard_data(&mut self) -> SftpResult<()> {
        // Only for discarding, so any size does
        let mut sink = [0u8; 256];
        while let Some(len) = self.runner.recv_data() {
            let n = len.min(sink.len());
            self.take_data(&mut sink[..n]).await?;
        }
        Ok(())
    }

    /// Discards the replies to requests that were never read.
    ///
    /// A request whose future was dropped leaves its reply on the
    /// stream; it has to come off before the next one makes sense.
    async fn drain_replies(&mut self) -> SftpResult<()> {
        while self.runner.outstanding() > 0 || self.runner.recv_data().is_some() {
            if self.runner.recv_data().is_some() {
                self.discard_data().await?;
                continue;
            }
            let _ = self.next_reply(&mut []).await?;
        }
        Ok(())
    }

    /// Prepares for a new operation.
    async fn begin(&mut self) -> SftpResult<()> {
        if self.poisoned {
            debug!("SftpClient used after an interrupted transfer");
            return Err(SftpError::Interrupted);
        }
        if self.runner.version().is_none() {
            return Err(SftpError::NotInitialized);
        }
        self.drain_replies().await
    }

    /// Sends the queued request and reads its `SSH_FXP_STATUS`.
    async fn do_status(&mut self, id: ReqId) -> SftpResult<()> {
        self.send_out(&[]).await?;
        self.expect_status(id).await
    }

    /// Reads a `SSH_FXP_STATUS` for `id`.
    async fn expect_status(&mut self, id: ReqId) -> SftpResult<()> {
        let (rid, r) = self.next_reply(&mut []).await?;
        check_id(rid, id)?;
        match r {
            Reply::Status(code) => status_result(code),
            r => {
                debug!("Unexpected {:?} response to a status request", r);
                Err(SftpError::BadResponse)
            }
        }
    }

    /// Sends the queued request and reads its `SSH_FXP_HANDLE`.
    async fn do_handle(
        &mut self,
        id: ReqId,
        kind: HandleKind,
    ) -> SftpResult<RemoteHandle> {
        self.send_out(&[]).await?;
        let (rid, r) = self.next_reply(&mut []).await?;
        check_id(rid, id)?;
        match r {
            Reply::Handle(mut h) => {
                h.kind = kind;
                Ok(h)
            }
            // A SSH_FX_OK status isn't a valid reply to an open
            Reply::Status(code) => {
                status_result(code)?;
                Err(SftpError::BadResponse)
            }
            r => {
                debug!("Unexpected {:?} response to an open request", r);
                Err(SftpError::BadResponse)
            }
        }
    }

    /// Sends the queued request and reads its `SSH_FXP_ATTRS`.
    async fn do_attrs(&mut self, id: ReqId) -> SftpResult<Attrs> {
        self.send_out(&[]).await?;
        let (rid, r) = self.next_reply(&mut []).await?;
        check_id(rid, id)?;
        match r {
            Reply::Attrs(a) => Ok(a),
            Reply::Status(code) => {
                status_result(code)?;
                Err(SftpError::BadResponse)
            }
            r => {
                debug!("Unexpected {:?} response to a stat request", r);
                Err(SftpError::BadResponse)
            }
        }
    }

    /// Sends the queued request and reads the single name it answers
    /// with into `out`.
    async fn do_name(&mut self, id: ReqId, out: &mut [u8]) -> SftpResult<usize> {
        self.send_out(&[]).await?;
        let (rid, r) = self.next_reply(&mut []).await?;
        check_id(rid, id)?;
        match r {
            Reply::NameStart(count) if count >= 1 => (),
            Reply::NameStart(_) => {
                debug!("Empty name response");
                // The NameEnd is left for the next drain
                return Err(SftpError::BadResponse);
            }
            Reply::Status(code) => {
                status_result(code)?;
                return Err(SftpError::BadResponse);
            }
            r => {
                debug!("Unexpected {:?} response to a name request", r);
                return Err(SftpError::BadResponse);
            }
        }

        let want = out.len();
        let (rid, r) = self.next_reply(out).await?;
        check_id(rid, id)?;
        let n = match r {
            Reply::Name(n) => n,
            r => {
                debug!("Unexpected {:?} in a name response", r);
                return Err(SftpError::BadResponse);
            }
        };
        // Leave the reply finished either way, so the next request
        // doesn't have to drain it.
        self.end_name(id).await?;
        if n > want {
            debug!("Name of {} bytes doesn't fit {}", n, want);
            return Err(SftpError::NoRoom);
        }
        Ok(n)
    }

    /// Consumes the rest of a name reply.
    async fn end_name(&mut self, id: ReqId) -> SftpResult<()> {
        loop {
            let (rid, r) = self.next_reply(&mut []).await?;
            check_id(rid, id)?;
            if matches!(r, Reply::NameEnd) {
                return Ok(());
            }
        }
    }

    // =========================== SFTP requests ============================

    /// Performs the SFTP version handshake.
    ///
    /// Must be called once, before any other request. Returns the
    /// version agreed with the server, always
    /// [`SFTP_VERSION`](crate::protocol::constants::SFTP_VERSION) since
    /// that is the only version implemented.
    pub async fn init(&mut self) -> SftpResult<u32> {
        if self.poisoned {
            return Err(SftpError::Interrupted);
        }
        self.runner.init()?;
        self.send_out(&[]).await?;

        let (_, r) = self.next_reply(&mut []).await?;
        match r {
            Reply::Version(version) => {
                debug!(
                    "SFTP version {}, extensions {:?}",
                    version,
                    self.runner.extensions()
                );
                Ok(version)
            }
            r => {
                debug!("Expected SSH_FXP_VERSION, got {:?}", r);
                Err(SftpError::BadResponse)
            }
        }
    }

    /// Opens a file.
    ///
    /// `flags` is a combination of the [`pflags`] constants. `attrs` are
    /// applied if the file is created.
    ///
    /// The returned handle must be given to [`close()`](Self::close).
    pub async fn open(
        &mut self,
        path: &str,
        flags: u32,
        attrs: &Attrs,
    ) -> SftpResult<RemoteHandle> {
        self.begin().await?;
        let id = self.runner.open(path, flags, attrs)?;
        self.do_handle(id, HandleKind::File).await
    }

    /// Opens an existing file for reading.
    pub async fn open_read(&mut self, path: &str) -> SftpResult<RemoteHandle> {
        self.open(path, pflags::READ, &Attrs::default()).await
    }

    /// Creates or truncates a file, opened for writing.
    pub async fn create(&mut self, path: &str) -> SftpResult<RemoteHandle> {
        self.open(
            path,
            pflags::WRITE | pflags::CREAT | pflags::TRUNC,
            &Attrs::default(),
        )
        .await
    }

    /// Opens a directory for listing with [`readdir()`](Self::readdir).
    ///
    /// The returned handle must be given to [`close()`](Self::close).
    pub async fn opendir(&mut self, path: &str) -> SftpResult<RemoteHandle> {
        self.begin().await?;
        let id = self.runner.opendir(path)?;
        self.do_handle(id, HandleKind::Dir).await
    }

    /// Closes a file or directory handle.
    pub async fn close(&mut self, handle: &RemoteHandle) -> SftpResult<()> {
        self.begin().await?;
        let id = self.runner.close(handle.as_bytes())?;
        self.do_status(id).await
    }

    /// Reads from an open file.
    ///
    /// Fills as much of `buf` as the file has, returning the number of
    /// bytes read. `Ok(0)` means end of file, as does passing an empty
    /// `buf`. A short result before the end of the file is possible,
    /// so callers should loop.
    ///
    /// A `buf` longer than [`MAX_READ_LEN`] is fetched with several
    /// requests, pipelined so that the transfer isn't limited to one
    /// chunk per round trip.
    pub async fn read(
        &mut self,
        handle: &RemoteHandle,
        offset: u64,
        buf: &mut [u8],
    ) -> SftpResult<usize> {
        handle.check(HandleKind::File)?;
        if buf.is_empty() {
            return Ok(0);
        }
        self.begin().await?;
        self.read_chunks(handle, offset, buf).await
    }

    /// The body of [`read()`](Self::read), with requests pipelined.
    async fn read_chunks(
        &mut self,
        handle: &RemoteHandle,
        offset: u64,
        buf: &mut [u8],
    ) -> SftpResult<usize> {
        let chunk = MAX_READ_LEN as usize;
        let chunks = buf.len().div_ceil(chunk);

        // Requests sent whose response hasn't arrived, by request id.
        let mut inflight: [Option<(ReqId, usize)>; PIPELINE] = [None; PIPELINE];
        let mut n_inflight = 0;
        // Next chunk to request
        let mut next = 0;
        // First chunk that came back short, which is where the
        // contiguous data ends. Responses can arrive in any order, so
        // this keeps the lowest.
        let mut short: Option<(usize, usize)> = None;
        let mut failed = None;

        loop {
            // Top up the window, unless the end of the file is in sight
            while n_inflight < PIPELINE
                && next < chunks
                && short.is_none()
                && failed.is_none()
            {
                let pos = next * chunk;
                let want = (buf.len() - pos).min(chunk);
                let id = self.runner.read(
                    handle.as_bytes(),
                    offset + pos as u64,
                    want as u32,
                )?;
                self.send_out(&[]).await?;

                // OK unwrap, n_inflight counts the used slots
                let slot = inflight.iter_mut().find(|s| s.is_none()).unwrap();
                *slot = Some((id, next));
                n_inflight += 1;
                next += 1;
            }

            if n_inflight == 0 {
                break;
            }

            let (id, r) = self.next_reply(&mut []).await?;
            let Some(slot) =
                inflight.iter_mut().find(|s| s.is_some_and(|(i, _)| i == id))
            else {
                debug!("Response for unknown {:?}", id);
                return Err(SftpError::BadResponse);
            };
            // OK unwrap, just matched
            let (_, idx) = slot.take().unwrap();
            n_inflight -= 1;

            let pos = idx * chunk;
            let want = (buf.len() - pos).min(chunk);

            match r {
                Reply::Data(len) if len > want => {
                    // Would overflow the caller's buffer. Take it off
                    // the stream anyway, other chunks are still coming.
                    warn!("Server returned {} bytes for a {} byte read", len, want);
                    self.discard_data().await?;
                    failed = failed.or(Some(SftpError::BadResponse));
                }
                Reply::Data(len) => {
                    self.take_data(&mut buf[pos..pos + len]).await?;
                    if len < want {
                        note_short(&mut short, idx, len);
                    }
                }
                Reply::Status(StatusCode::SSH_FX_EOF) => {
                    note_short(&mut short, idx, 0)
                }
                Reply::Status(code) => {
                    failed = failed.or(Some(SftpError::FileServerError(code)))
                }
                r => {
                    debug!("Unexpected {:?} response to a read request", r);
                    failed = failed.or(Some(SftpError::BadResponse));
                }
            }
        }

        if let Some(e) = failed {
            return Err(e);
        }
        // Data past a gap is discarded, the caller asks again from there
        Ok(match short {
            Some((idx, len)) => idx * chunk + len,
            None => buf.len(),
        })
    }

    /// Writes to an open file.
    ///
    /// All of `data` is written. Data longer than [`MAX_WRITE_LEN`] is
    /// split into several requests.
    ///
    /// Unlike [`read()`](Self::read) these aren't pipelined: a write
    /// sent ahead has to be held somewhere until the peer reads it,
    /// and a peer that is busy replying can stop reading, which would
    /// deadlock both sides.
    pub async fn write(
        &mut self,
        handle: &RemoteHandle,
        offset: u64,
        data: &[u8],
    ) -> SftpResult<()> {
        handle.check(HandleKind::File)?;
        self.begin().await?;

        let chunk = MAX_WRITE_LEN as usize;
        // A zero length write is still a request
        let chunks = data.len().div_ceil(chunk).max(1);
        for n in 0..chunks {
            let pos = n * chunk;
            let len = (data.len() - pos).min(chunk);
            let id =
                self.runner.write(handle.as_bytes(), offset + pos as u64, len)?;
            self.send_out(&data[pos..pos + len]).await?;
            self.expect_status(id).await?;
        }
        Ok(())
    }

    /// Lists part of an open directory.
    ///
    /// Returns `None` once the whole directory has been listed,
    /// otherwise an iterator over a batch of entries. Servers return an
    /// arbitrary number of entries per call, so this must be repeated
    /// until it returns `None`.
    ///
    /// Stopping early is allowed, unread entries are discarded by the
    /// next request.
    ///
    /// ```
    /// # use sunset_sftp::client::{DEFAULT_CLIENT_BUF, RemoteHandle, SftpClient};
    /// # use sunset_sftp::embedded_io_async::{Read, Write};
    /// # use sunset_sftp::error::SftpResult;
    /// async fn count_entries<R: Read, W: Write>(
    ///     client: &mut SftpClient<R, W, { DEFAULT_CLIENT_BUF }>,
    ///     dir: &RemoteHandle,
    /// ) -> SftpResult<usize> {
    ///     let mut count = 0;
    ///     while let Some(mut entries) = client.readdir(dir).await? {
    ///         while let Some(entry) = entries.next().await? {
    ///             let _name = entry.filename();
    ///             count += 1;
    ///         }
    ///     }
    ///     Ok(count)
    /// }
    /// ```
    pub async fn readdir(
        &mut self,
        handle: &RemoteHandle,
    ) -> SftpResult<Option<DirIter<'_, R, W, BUF>>> {
        handle.check(HandleKind::Dir)?;
        self.begin().await?;
        let id = self.runner.readdir(handle.as_bytes())?;
        self.send_out(&[]).await?;

        let (rid, r) = self.next_reply(&mut []).await?;
        check_id(rid, id)?;
        match r {
            // The entries are read by the iterator
            Reply::NameStart(count) => Ok(Some(DirIter::new(self, id, count))),
            Reply::Status(StatusCode::SSH_FX_EOF) => Ok(None),
            Reply::Status(code) => Err(SftpError::FileServerError(code)),
            r => {
                debug!("Unexpected {:?} response to a readdir request", r);
                Err(SftpError::BadResponse)
            }
        }
    }

    /// Returns the attributes of a path, following symbolic links.
    pub async fn stat(&mut self, path: &str) -> SftpResult<Attrs> {
        self.begin().await?;
        let id = self.runner.stat(path)?;
        self.do_attrs(id).await
    }

    /// Returns the attributes of a path, without following symbolic links.
    pub async fn lstat(&mut self, path: &str) -> SftpResult<Attrs> {
        self.begin().await?;
        let id = self.runner.lstat(path)?;
        self.do_attrs(id).await
    }

    /// Returns the attributes of an open file.
    pub async fn fstat(&mut self, handle: &RemoteHandle) -> SftpResult<Attrs> {
        self.begin().await?;
        let id = self.runner.fstat(handle.as_bytes())?;
        self.do_attrs(id).await
    }

    /// Modifies the attributes of a path.
    ///
    /// Only the attributes set in `attrs` are modified.
    pub async fn setstat(&mut self, path: &str, attrs: &Attrs) -> SftpResult<()> {
        self.begin().await?;
        let id = self.runner.setstat(path, attrs)?;
        self.do_status(id).await
    }

    /// Modifies the attributes of an open file.
    ///
    /// Only the attributes set in `attrs` are modified.
    pub async fn fsetstat(
        &mut self,
        handle: &RemoteHandle,
        attrs: &Attrs,
    ) -> SftpResult<()> {
        self.begin().await?;
        let id = self.runner.fsetstat(handle.as_bytes(), attrs)?;
        self.do_status(id).await
    }

    /// Removes a file. This will not remove directories.
    pub async fn remove(&mut self, path: &str) -> SftpResult<()> {
        self.begin().await?;
        let id = self.runner.remove(path)?;
        self.do_status(id).await
    }

    /// Creates a directory.
    pub async fn mkdir(&mut self, path: &str, attrs: &Attrs) -> SftpResult<()> {
        self.begin().await?;
        let id = self.runner.mkdir(path, attrs)?;
        self.do_status(id).await
    }

    /// Removes an empty directory.
    pub async fn rmdir(&mut self, path: &str) -> SftpResult<()> {
        self.begin().await?;
        let id = self.runner.rmdir(path)?;
        self.do_status(id).await
    }

    /// Renames a file or directory.
    ///
    /// SFTP version 3 requires this to fail if `new` already exists.
    /// [`posix_rename()`](Self::posix_rename) replaces the destination
    /// instead, where the server supports it.
    pub async fn rename(&mut self, old: &str, new: &str) -> SftpResult<()> {
        self.begin().await?;
        let id = self.runner.rename(old, new)?;
        self.do_status(id).await
    }

    /// Creates a symbolic link at `link_path` pointing to `target_path`.
    pub async fn symlink(
        &mut self,
        target_path: &str,
        link_path: &str,
    ) -> SftpResult<()> {
        self.begin().await?;
        let id = self.runner.symlink(target_path, link_path)?;
        self.do_status(id).await
    }

    /// Canonicalises a path, returning the server's absolute form.
    ///
    /// The path is written to `out`, which must be large enough,
    /// otherwise [`SftpError::NoRoom`] is returned.
    pub async fn realpath<'b>(
        &mut self,
        path: &str,
        out: &'b mut [u8],
    ) -> SftpResult<&'b [u8]> {
        self.begin().await?;
        let id = self.runner.realpath(path)?;
        // The length is returned rather than a slice of `out`, so that
        // `out` can be borrowed again here.
        let n = self.do_name(id, out).await?;
        Ok(&out[..n])
    }

    /// Returns the target of a symbolic link.
    ///
    /// The target is written to `out`, which must be large enough,
    /// otherwise [`SftpError::NoRoom`] is returned.
    pub async fn readlink<'b>(
        &mut self,
        path: &str,
        out: &'b mut [u8],
    ) -> SftpResult<&'b [u8]> {
        self.begin().await?;
        let id = self.runner.readlink(path)?;
        let n = self.do_name(id, out).await?;
        Ok(&out[..n])
    }

    // ======================== Extended requests ===========================

    /// Sends an extended request with `args` as its payload.
    async fn request_extended(
        &mut self,
        name: &str,
        args: &dyn SSHEncode,
    ) -> SftpResult<()> {
        self.begin().await?;
        let id = self.runner.extended(name, args)?;
        self.do_status(id).await
    }

    /// Renames a file, replacing `new` if it exists.
    ///
    /// Uses the `posix-rename@openssh.com` extension, only available
    /// when [`extensions()`](Self::extensions) reports `posix_rename`.
    pub async fn posix_rename(&mut self, old: &str, new: &str) -> SftpResult<()> {
        if !self.runner.extensions().posix_rename {
            return Err(SftpError::NotSupported);
        }
        // The extension payload is two paths, the same as a rename.
        self.request_extended(
            "posix-rename@openssh.com",
            &Rename {
                old_path: TextString(old.as_bytes()),
                new_path: TextString(new.as_bytes()),
            },
        )
        .await
    }

    /// Creates a hard link at `new` pointing at `old`.
    ///
    /// Uses the `hardlink@openssh.com` extension, only available when
    /// [`extensions()`](Self::extensions) reports `hardlink`.
    pub async fn hardlink(&mut self, old: &str, new: &str) -> SftpResult<()> {
        if !self.runner.extensions().hardlink {
            return Err(SftpError::NotSupported);
        }
        self.request_extended(
            "hardlink@openssh.com",
            &Rename {
                old_path: TextString(old.as_bytes()),
                new_path: TextString(new.as_bytes()),
            },
        )
        .await
    }

    /// Flushes an open file to the server's storage.
    ///
    /// Uses the `fsync@openssh.com` extension, only available when
    /// [`extensions()`](Self::extensions) reports `fsync`.
    pub async fn fsync(&mut self, handle: &RemoteHandle) -> SftpResult<()> {
        if !self.runner.extensions().fsync {
            return Err(SftpError::NotSupported);
        }
        handle.check(HandleKind::File)?;
        self.request_extended(
            "fsync@openssh.com",
            &crate::proto::OpaqueHandle(sunset::sshwire::BinString(
                handle.as_bytes(),
            )),
        )
        .await
    }
}
