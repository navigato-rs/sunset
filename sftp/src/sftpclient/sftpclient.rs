use core::fmt;

use embedded_io_async::{Read, Write};
use sunset::sshwire::{BinString, SSHEncode, TextString};

use crate::error::{SftpError, SftpResult};
use crate::proto::{
    Attrs, Close, FSetStat, FStat, Filename, InitVersionClient, LStat,
    MAX_HANDLE_LEN, MAX_REQUEST_LEN, MkDir, OpaqueHandle, Open, OpenDir, PFlags,
    PathInfo, ReadDir, ReadLink, Remove, Rename, ReqId, RmDir,
    SFTP_MAXIMUM_PACKET_LEN, SFTP_MINIMUM_PACKET_LEN, SFTP_VERSION,
    SSH_FXP_EXTENDED, SetStat, SftpNum, SftpPacket, Stat, StatusCode, Symlink,
};
use crate::sftpclient::dir::DirIter;
use crate::sftpclient::packetread::*;
use crate::sftpsink::SftpSink;

#[allow(unused_imports)]
use log::{debug, error, info, log, trace, warn};

/// Default buffer size for [`SftpClient`].
///
/// Large enough for the longest request, which also leaves room for a
/// directory entry's filename and a good part of its long name.
pub const DEFAULT_CLIENT_BUF: usize = MAX_REQUEST_LEN;

/// Largest `SSH_FXP_READ` that will be requested in one request.
///
/// Matches the OpenSSH client, and keeps a data response within the
/// 34000 byte packet size that draft-ietf-secsh-filexfer-02 requires
/// servers to accept. Larger reads are split into several requests.
pub const MAX_READ_LEN: u32 = 32 * 1024;

/// Largest `SSH_FXP_WRITE` that will be sent in one request.
///
/// Servers commonly refuse packets beyond the 34000 bytes the draft
/// requires them to accept. Larger writes are split into several
/// requests.
pub const MAX_WRITE_LEN: u32 = 32 * 1024;

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

/// Sanity limit for responses that are streamed rather than buffered.
///
/// `SSH_FXP_DATA` is bounded by [`MAX_READ_LEN`], but `SSH_FXP_NAME` for
/// a large directory can exceed the usual packet limit. Nothing is
/// buffered, so this is only a guard against a broken peer.
const MAX_STREAM_PACKET_LEN: usize = 1024 * 1024;

/// Flags for [`SftpClient::open`].
///
/// See [Opening, creating and closing files](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02#section-6.3).
#[allow(missing_docs)]
pub mod pflags {
    pub const READ: u32 = 0x00000001;
    pub const WRITE: u32 = 0x00000002;
    pub const APPEND: u32 = 0x00000004;
    pub const CREAT: u32 = 0x00000008;
    pub const TRUNC: u32 = 0x00000010;
    pub const EXCL: u32 = 0x00000020;
}

/// Records the lowest numbered chunk that came back short.
///
/// The contiguous data ends there, whatever later chunks returned.
fn note_short(short: &mut Option<(usize, usize)>, idx: usize, len: usize) {
    if short.is_none_or(|(i, _)| idx < i) {
        *short = Some((idx, len));
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
    fn empty(kind: HandleKind) -> Self {
        Self { handle: [0; MAX_HANDLE_LEN], len: 0, kind }
    }

    /// True for handles from [`SftpClient::opendir`].
    pub fn is_dir(&self) -> bool {
        self.kind == HandleKind::Dir
    }

    fn as_bytes(&self) -> &[u8] {
        &self.handle[..self.len as usize]
    }

    fn opaque(&self) -> OpaqueHandle<'_> {
        OpaqueHandle(BinString(self.as_bytes()))
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

/// Optional protocol extensions advertised by the server.
///
/// Populated from the `SSH_FXP_VERSION` response, see
/// [`SftpClient::extensions`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Extensions {
    /// `posix-rename@openssh.com`, see [`SftpClient::posix_rename`]
    pub posix_rename: bool,
    /// `hardlink@openssh.com`, see [`SftpClient::hardlink`]
    pub hardlink: bool,
    /// `fsync@openssh.com`, see [`SftpClient::fsync`]
    pub fsync: bool,
    /// `statvfs@openssh.com`, not implemented
    pub statvfs: bool,
    /// `limits@openssh.com`, not implemented
    pub limits: bool,
}

/// A SFTP client.
///
/// Wraps the [`Read`] and [`Write`] halves of a SSH channel that has had
/// the `sftp` subsystem started on it.
///
/// [`init()`](Self::init) must be called once before any other request.
///
/// `BUF` sizes the single internal buffer used to encode requests and to
/// hold the variable length parts of a response. It must be at least
/// [`MAX_REQUEST_LEN`]; [`DEFAULT_CLIENT_BUF`] is a reasonable choice and
/// is used by [`new_default_buffer()`](Self::new_default_buffer).
/// File contents and directory listings are streamed, so they are not
/// limited by `BUF`.
///
/// Requests are made one at a time; a request is written and its
/// response read before the next is sent.
pub struct SftpClient<R: Read, W: Write, const BUF: usize> {
    reader: R,
    writer: W,
    buf: [u8; BUF],

    /// Next request id to use
    next_id: u32,

    /// Bytes of the current response packet that haven't been read yet.
    ///
    /// Left non-zero when a caller stops reading a response early, for
    /// example dropping a [`DirIter`]. The next request drains it.
    pkt_remaining: usize,

    /// Requests that have been sent but whose response hasn't been read.
    ///
    /// More than one while a transfer is pipelining. Any left over are
    /// discarded before the next operation.
    outstanding: usize,

    /// Set while the stream position is unknown.
    ///
    /// A request that is interrupted (its future dropped) or that fails
    /// partway leaves the stream out of sync with the peer, so the client
    /// refuses further requests rather than misinterpreting data.
    poisoned: bool,

    /// Negotiated version, once `init()` has completed.
    version: Option<u32>,

    extensions: Extensions,
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
    /// Panics if `BUF` is smaller than [`MAX_REQUEST_LEN`].
    pub const fn new(reader: R, writer: W) -> Self {
        // A const generic bound would be preferable, but const generic
        // expressions aren't stable.
        assert!(
            BUF >= MAX_REQUEST_LEN,
            "SftpClient BUF must be at least MAX_REQUEST_LEN"
        );
        Self {
            reader,
            writer,
            buf: [0; BUF],
            next_id: 1,
            pkt_remaining: 0,
            outstanding: 0,
            poisoned: false,
            version: None,
            extensions: Extensions {
                posix_rename: false,
                hardlink: false,
                fsync: false,
                statvfs: false,
                limits: false,
            },
        }
    }

    /// Returns the underlying channel halves.
    pub fn into_parts(self) -> (R, W) {
        (self.reader, self.writer)
    }

    /// The negotiated SFTP version, or `None` before [`init()`](Self::init).
    pub fn version(&self) -> Option<u32> {
        self.version
    }

    /// Extensions advertised by the server in its `SSH_FXP_VERSION`.
    pub fn extensions(&self) -> Extensions {
        self.extensions
    }

    // ===================== Request/response plumbing =====================

    /// Checks the client is usable, and discards anything left over
    /// from a previous operation.
    ///
    /// The stream position is then unknown until the operation
    /// finishes, so an interrupted operation leaves the client
    /// unusable rather than misreading the next response.
    async fn start(&mut self) -> SftpResult<()> {
        if self.poisoned {
            debug!("SftpClient used after an interrupted request");
            return Err(SftpError::Interrupted);
        }
        if self.version.is_none() {
            return Err(SftpError::NotInitialized);
        }
        self.drain_responses().await?;

        self.poisoned = true;
        Ok(())
    }

    fn next_id(&mut self) -> ReqId {
        let id = ReqId(self.next_id);
        self.next_id = self.next_id.wrapping_add(1);
        id
    }

    /// Starts an operation that makes a single request.
    async fn begin(&mut self) -> SftpResult<ReqId> {
        self.start().await?;
        Ok(self.next_id())
    }

    /// Discards the rest of the current response, and the responses to
    /// any requests that were not read.
    async fn drain_responses(&mut self) -> SftpResult<()> {
        drain(&mut self.reader, &mut self.pkt_remaining).await?;

        while self.outstanding > 0 {
            let mut lb = [0u8; 4];
            read_exact(&mut self.reader, &mut lb).await?;
            let len = u32::from_be_bytes(lb) as usize;
            if len > MAX_STREAM_PACKET_LEN {
                debug!("Discarded response length {} too long", len);
                return Err(SftpError::MalformedPacket);
            }
            self.pkt_remaining = len;
            self.outstanding -= 1;
            drain(&mut self.reader, &mut self.pkt_remaining).await?;
        }
        Ok(())
    }

    /// Finishes an operation, discarding any responses not read.
    ///
    /// The client stays usable if the responses were consumed
    /// successfully. `r` failing for a reason that leaves the stream
    /// intact (an error status, a value too long for the buffer) is
    /// still recoverable.
    async fn finish<T>(&mut self, r: SftpResult<T>) -> SftpResult<T> {
        match self.drain_responses().await {
            Ok(()) => {
                self.poisoned = false;
                r
            }
            // Keep the earlier error, it explains the failure better.
            Err(e) => Err(r.err().unwrap_or(e)),
        }
    }

    /// Sends a request packet.
    async fn send(&mut self, packet: &SftpPacket<'_>) -> SftpResult<()> {
        trace!("SFTP ----> {:?}", packet);
        {
            let mut sink = SftpSink::new(&mut self.buf);
            packet.encode_request(&mut sink)?;
            let out = sink.used_slice();
            self.writer.write_all(out).await.map_err(SftpError::from_embedded_io)?;
        }
        self.outstanding += 1;
        self.writer.flush().await.map_err(SftpError::from_embedded_io)
    }

    /// Reads a response header, leaving `pkt_remaining` set to the
    /// unread packet content.
    ///
    /// The request id is returned rather than checked, since several
    /// requests may be in flight and a peer may answer them in any
    /// order.
    async fn recv_any(&mut self) -> SftpResult<(SftpNum, ReqId)> {
        let mut lb = [0u8; 4];
        read_exact(&mut self.reader, &mut lb).await?;
        let len = u32::from_be_bytes(lb) as usize;

        // Packet type and request id must be present.
        if len < SFTP_MINIMUM_PACKET_LEN - 4 {
            debug!("Response length {} too short", len);
            return Err(SftpError::MalformedPacket);
        }
        self.pkt_remaining = len;
        self.outstanding = self.outstanding.saturating_sub(1);

        let ty =
            SftpNum::from(take_u8(&mut self.reader, &mut self.pkt_remaining).await?);

        let limit = match ty {
            SftpNum::SSH_FXP_DATA | SftpNum::SSH_FXP_NAME => MAX_STREAM_PACKET_LEN,
            _ => SFTP_MAXIMUM_PACKET_LEN,
        };
        if len > limit {
            debug!("Response {:?} length {} too long", ty, len);
            return Err(SftpError::MalformedPacket);
        }

        let id = ReqId(take_u32(&mut self.reader, &mut self.pkt_remaining).await?);

        trace!("SFTP <---- {:?} {:?} {} bytes", ty, id, self.pkt_remaining);
        Ok((ty, id))
    }

    /// Reads a response header, which must be for `expect`.
    async fn recv(&mut self, expect: ReqId) -> SftpResult<SftpNum> {
        let (ty, id) = self.recv_any().await?;
        if id != expect {
            // Only one request was made, so this is the peer
            // misbehaving or a desynchronised stream.
            debug!("Response for {:?}, expected {:?}", id, expect);
            return Err(SftpError::BadResponse);
        }
        Ok(ty)
    }

    /// Reads a `SSH_FXP_STATUS` response body.
    ///
    /// The status message and language tag are discarded.
    async fn recv_status_body(&mut self) -> SftpResult<StatusCode> {
        let code = StatusCode::from(
            take_u32(&mut self.reader, &mut self.pkt_remaining).await?,
        );
        // message and language tag
        skip_string(&mut self.reader, &mut self.pkt_remaining).await?;
        skip_string(&mut self.reader, &mut self.pkt_remaining).await?;
        Ok(code)
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

    /// Performs a request whose only response is `SSH_FXP_STATUS`.
    async fn request_status(
        &mut self,
        id: ReqId,
        packet: SftpPacket<'_>,
    ) -> SftpResult<()> {
        let r = async {
            self.send(&packet).await?;
            match self.recv(id).await? {
                SftpNum::SSH_FXP_STATUS => {
                    Self::status_result(self.recv_status_body().await?)
                }
                ty => {
                    debug!("Unexpected {:?} response to a status request", ty);
                    Err(SftpError::BadResponse)
                }
            }
        }
        .await;
        self.finish(r).await
    }

    /// Performs a request whose response is `SSH_FXP_HANDLE`.
    async fn request_handle(
        &mut self,
        id: ReqId,
        packet: SftpPacket<'_>,
        kind: HandleKind,
    ) -> SftpResult<RemoteHandle> {
        let r = async {
            self.send(&packet).await?;
            match self.recv(id).await? {
                SftpNum::SSH_FXP_HANDLE => {
                    let mut h = RemoteHandle::empty(kind);
                    let l = take_string(
                        &mut self.reader,
                        &mut self.pkt_remaining,
                        &mut h.handle,
                    )
                    .await?
                    .len();
                    h.len = l as u16;
                    Ok(h)
                }
                SftpNum::SSH_FXP_STATUS => {
                    // A SSH_FX_OK status isn't a valid reply to an open
                    Self::status_result(self.recv_status_body().await?)?;
                    Err(SftpError::BadResponse)
                }
                ty => {
                    debug!("Unexpected {:?} response to an open request", ty);
                    Err(SftpError::BadResponse)
                }
            }
        }
        .await;
        self.finish(r).await
    }

    /// Performs a request whose response is `SSH_FXP_ATTRS`.
    async fn request_attrs(
        &mut self,
        id: ReqId,
        packet: SftpPacket<'_>,
    ) -> SftpResult<Attrs> {
        let r = async {
            self.send(&packet).await?;
            match self.recv(id).await? {
                SftpNum::SSH_FXP_ATTRS => {
                    take_attrs(&mut self.reader, &mut self.pkt_remaining).await
                }
                SftpNum::SSH_FXP_STATUS => {
                    Self::status_result(self.recv_status_body().await?)?;
                    Err(SftpError::BadResponse)
                }
                ty => {
                    debug!("Unexpected {:?} response to a stat request", ty);
                    Err(SftpError::BadResponse)
                }
            }
        }
        .await;
        self.finish(r).await
    }

    /// Performs a request whose response is a single entry `SSH_FXP_NAME`.
    ///
    /// The name is written to `out`, the rest of the entry is discarded.
    async fn request_name<'b>(
        &mut self,
        id: ReqId,
        packet: SftpPacket<'_>,
        out: &'b mut [u8],
    ) -> SftpResult<&'b [u8]> {
        // The length is returned rather than a slice of `out`, so that
        // `out` can be borrowed again after `finish()`.
        let r = async {
            self.send(&packet).await?;
            match self.recv(id).await? {
                SftpNum::SSH_FXP_NAME => {
                    let count =
                        take_u32(&mut self.reader, &mut self.pkt_remaining).await?;
                    if count < 1 {
                        debug!("Empty name response");
                        return Err(SftpError::BadResponse);
                    }
                    let n =
                        take_string(&mut self.reader, &mut self.pkt_remaining, out)
                            .await?
                            .len();
                    Ok(n)
                }
                SftpNum::SSH_FXP_STATUS => {
                    Self::status_result(self.recv_status_body().await?)?;
                    Err(SftpError::BadResponse)
                }
                ty => {
                    debug!("Unexpected {:?} response to a name request", ty);
                    Err(SftpError::BadResponse)
                }
            }
        }
        .await;
        let n = self.finish(r).await?;
        Ok(&out[..n])
    }

    // ========================== SFTP requests ============================

    /// Performs the SFTP version handshake.
    ///
    /// Must be called once, before any other request. Returns the
    /// version agreed with the server, always [`SFTP_VERSION`] since
    /// that is the only version implemented.
    pub async fn init(&mut self) -> SftpResult<u32> {
        if self.version.is_some() {
            return Err(SftpError::AlreadyInitialized);
        }
        if self.poisoned {
            return Err(SftpError::Interrupted);
        }
        // SSH_FXP_INIT carries a version rather than a request id, so it
        // doesn't use begin()/send()/recv().
        self.poisoned = true;

        let r = async {
            let init = SftpPacket::Init(InitVersionClient { version: SFTP_VERSION });
            {
                let mut sink = SftpSink::new(&mut self.buf);
                init.enc(&mut sink)?;
                let out = sink.used_slice();
                self.writer
                    .write_all(out)
                    .await
                    .map_err(SftpError::from_embedded_io)?;
            }
            self.writer.flush().await.map_err(SftpError::from_embedded_io)?;

            let mut lb = [0u8; 4];
            read_exact(&mut self.reader, &mut lb).await?;
            let len = u32::from_be_bytes(lb) as usize;
            if !(5..=SFTP_MAXIMUM_PACKET_LEN).contains(&len) {
                debug!("Bad version response length {}", len);
                return Err(SftpError::MalformedPacket);
            }
            self.pkt_remaining = len;

            let ty = SftpNum::from(
                take_u8(&mut self.reader, &mut self.pkt_remaining).await?,
            );
            if ty != SftpNum::SSH_FXP_VERSION {
                debug!("Expected SSH_FXP_VERSION, got {:?}", ty);
                return Err(SftpError::BadResponse);
            }

            let version =
                take_u32(&mut self.reader, &mut self.pkt_remaining).await?;
            if version != SFTP_VERSION {
                // The server replies with the lowest of the two versions,
                // and Sunset only implements version 3.
                warn!("Server SFTP version {} is not supported", version);
                return Err(SftpError::NotSupported);
            }

            // Extension pairs fill the rest of the packet.
            while self.pkt_remaining > 0 {
                let name = try_take_string(
                    &mut self.reader,
                    &mut self.pkt_remaining,
                    &mut self.buf,
                )
                .await?;
                match name {
                    Some(b"posix-rename@openssh.com") => {
                        self.extensions.posix_rename = true
                    }
                    Some(b"hardlink@openssh.com") => self.extensions.hardlink = true,
                    Some(b"fsync@openssh.com") => self.extensions.fsync = true,
                    Some(b"statvfs@openssh.com") => self.extensions.statvfs = true,
                    Some(b"limits@openssh.com") => self.extensions.limits = true,
                    _ => trace!("Ignoring unknown SFTP extension"),
                }
                // extension data
                skip_string(&mut self.reader, &mut self.pkt_remaining).await?;
            }

            Ok(version)
        }
        .await;

        let version = self.finish(r).await?;
        self.version = Some(version);
        debug!("SFTP version {}, extensions {:?}", version, self.extensions);
        Ok(version)
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
        let id = self.begin().await?;
        let packet = SftpPacket::Open(
            id,
            Open {
                filename: Filename::from(path),
                pflags: PFlags::from(flags),
                attrs: *attrs,
            },
        );
        self.request_handle(id, packet, HandleKind::File).await
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
        let id = self.begin().await?;
        let packet =
            SftpPacket::OpenDir(id, OpenDir { dirname: Filename::from(path) });
        self.request_handle(id, packet, HandleKind::Dir).await
    }

    /// Closes a file or directory handle.
    pub async fn close(&mut self, handle: &RemoteHandle) -> SftpResult<()> {
        let id = self.begin().await?;
        self.request_status(
            id,
            SftpPacket::Close(id, Close { handle: handle.opaque() }),
        )
        .await
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
        self.start().await?;
        let r = self.read_chunks(handle, offset, buf).await;
        self.finish(r).await
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
                let id = self.next_id();
                let packet = SftpPacket::Read(
                    id,
                    crate::proto::Read {
                        handle: handle.opaque(),
                        offset: offset + pos as u64,
                        len: want as u32,
                    },
                );
                self.send(&packet).await?;

                // OK unwrap, n_inflight counts the used slots
                let slot = inflight.iter_mut().find(|s| s.is_none()).unwrap();
                *slot = Some((id, next));
                n_inflight += 1;
                next += 1;
            }

            if n_inflight == 0 {
                break;
            }

            let (ty, id) = self.recv_any().await?;
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

            match ty {
                SftpNum::SSH_FXP_DATA => {
                    let len = take_u32(&mut self.reader, &mut self.pkt_remaining)
                        .await? as usize;
                    if len > want {
                        // Would overflow the caller's buffer
                        warn!(
                            "Server returned {} bytes for a {} byte read",
                            len, want
                        );
                        failed = failed.or(Some(SftpError::BadResponse));
                    } else {
                        take(
                            &mut self.reader,
                            &mut self.pkt_remaining,
                            &mut buf[pos..pos + len],
                        )
                        .await?;
                        if len < want {
                            note_short(&mut short, idx, len);
                        }
                    }
                }
                SftpNum::SSH_FXP_STATUS => match self.recv_status_body().await? {
                    StatusCode::SSH_FX_EOF => note_short(&mut short, idx, 0),
                    code => {
                        failed = failed.or(Some(SftpError::FileServerError(code)))
                    }
                },
                ty => {
                    debug!("Unexpected {:?} response to a read request", ty);
                    failed = failed.or(Some(SftpError::BadResponse));
                }
            }

            // Leave the stream at a packet boundary for the next response
            drain(&mut self.reader, &mut self.pkt_remaining).await?;
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
    /// split into several requests, pipelined so that the transfer
    /// isn't limited to one chunk per round trip.
    pub async fn write(
        &mut self,
        handle: &RemoteHandle,
        offset: u64,
        data: &[u8],
    ) -> SftpResult<()> {
        handle.check(HandleKind::File)?;
        self.start().await?;
        let r = self.write_chunks(handle, offset, data).await;
        self.finish(r).await
    }

    /// The body of [`write()`](Self::write), with requests pipelined.
    async fn write_chunks(
        &mut self,
        handle: &RemoteHandle,
        offset: u64,
        data: &[u8],
    ) -> SftpResult<()> {
        let chunk = MAX_WRITE_LEN as usize;
        // A zero length write is still a request
        let chunks = data.len().div_ceil(chunk).max(1);

        let mut inflight: [Option<ReqId>; PIPELINE] = [None; PIPELINE];
        let mut n_inflight = 0;
        let mut next = 0;
        let mut failed = None;

        loop {
            while n_inflight < PIPELINE && next < chunks && failed.is_none() {
                let pos = next * chunk;
                let len = (data.len() - pos).min(chunk);
                let id = self.next_id();
                self.send_write(
                    handle,
                    id,
                    offset + pos as u64,
                    &data[pos..pos + len],
                )
                .await?;

                // OK unwrap, n_inflight counts the used slots
                let slot = inflight.iter_mut().find(|s| s.is_none()).unwrap();
                *slot = Some(id);
                n_inflight += 1;
                next += 1;
            }

            if n_inflight == 0 {
                break;
            }

            let (ty, id) = self.recv_any().await?;
            let Some(slot) = inflight.iter_mut().find(|s| **s == Some(id)) else {
                debug!("Response for unknown {:?}", id);
                return Err(SftpError::BadResponse);
            };
            *slot = None;
            n_inflight -= 1;

            match ty {
                SftpNum::SSH_FXP_STATUS => {
                    if let Err(e) =
                        Self::status_result(self.recv_status_body().await?)
                    {
                        failed = failed.or(Some(e));
                    }
                }
                ty => {
                    debug!("Unexpected {:?} response to a write request", ty);
                    failed = failed.or(Some(SftpError::BadResponse));
                }
            }

            drain(&mut self.reader, &mut self.pkt_remaining).await?;
        }

        match failed {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// Sends one `SSH_FXP_WRITE`.
    ///
    /// Encoded by hand since the data is streamed rather than being
    /// copied through the client's buffer.
    async fn send_write(
        &mut self,
        handle: &RemoteHandle,
        id: ReqId,
        offset: u64,
        data: &[u8],
    ) -> SftpResult<()> {
        let body_len = 1 // packet type
            + 4 // request id
            + 4 + handle.as_bytes().len() // handle string
            + 8 // offset
            + 4 + data.len(); // data string
        let body_len: u32 = body_len.try_into().map_err(|_| SftpError::NoRoom)?;

        {
            let mut sink = SftpSink::new(&mut self.buf);
            // The length field is encoded explicitly here. send() uses
            // payload_slice(), skipping the sink's own length.
            body_len.enc(&mut sink)?;
            u8::from(SftpNum::SSH_FXP_WRITE).enc(&mut sink)?;
            id.enc(&mut sink)?;
            handle.opaque().enc(&mut sink)?;
            offset.enc(&mut sink)?;
            (data.len() as u32).enc(&mut sink)?;
            sink.send(&mut self.writer).await?;
        }
        self.writer.write_all(data).await.map_err(SftpError::from_embedded_io)?;
        self.outstanding += 1;
        self.writer.flush().await.map_err(SftpError::from_embedded_io)
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
        let id = self.begin().await?;
        let packet = SftpPacket::ReadDir(id, ReadDir { handle: handle.opaque() });

        let r = async {
            self.send(&packet).await?;
            match self.recv(id).await? {
                SftpNum::SSH_FXP_NAME => Ok(Some(
                    take_u32(&mut self.reader, &mut self.pkt_remaining).await?,
                )),
                SftpNum::SSH_FXP_STATUS => match self.recv_status_body().await? {
                    StatusCode::SSH_FX_EOF => Ok(None),
                    code => Err(SftpError::FileServerError(code)),
                },
                ty => {
                    debug!("Unexpected {:?} response to a readdir request", ty);
                    Err(SftpError::BadResponse)
                }
            }
        }
        .await;

        match r {
            Ok(Some(count)) => {
                // The entries are read by the iterator. The stream
                // position is known, so the client isn't left poisoned.
                self.poisoned = false;
                Ok(Some(DirIter::new(self, count)))
            }
            Ok(None) => self.finish(Ok(None)).await,
            Err(e) => self.finish(Err(e)).await,
        }
    }

    /// Returns the attributes of a path, following symbolic links.
    pub async fn stat(&mut self, path: &str) -> SftpResult<Attrs> {
        let id = self.begin().await?;
        let packet =
            SftpPacket::Stat(id, Stat { file_path: TextString(path.as_bytes()) });
        self.request_attrs(id, packet).await
    }

    /// Returns the attributes of a path, without following symbolic links.
    pub async fn lstat(&mut self, path: &str) -> SftpResult<Attrs> {
        let id = self.begin().await?;
        let packet =
            SftpPacket::LStat(id, LStat { file_path: TextString(path.as_bytes()) });
        self.request_attrs(id, packet).await
    }

    /// Returns the attributes of an open file.
    pub async fn fstat(&mut self, handle: &RemoteHandle) -> SftpResult<Attrs> {
        let id = self.begin().await?;
        let packet = SftpPacket::FStat(id, FStat { handle: handle.opaque() });
        self.request_attrs(id, packet).await
    }

    /// Modifies the attributes of a path.
    ///
    /// Only the attributes set in `attrs` are modified.
    pub async fn setstat(&mut self, path: &str, attrs: &Attrs) -> SftpResult<()> {
        let id = self.begin().await?;
        self.request_status(
            id,
            SftpPacket::SetStat(
                id,
                SetStat { file_path: TextString(path.as_bytes()), attrs: *attrs },
            ),
        )
        .await
    }

    /// Modifies the attributes of an open file.
    ///
    /// Only the attributes set in `attrs` are modified.
    pub async fn fsetstat(
        &mut self,
        handle: &RemoteHandle,
        attrs: &Attrs,
    ) -> SftpResult<()> {
        let id = self.begin().await?;
        self.request_status(
            id,
            SftpPacket::FSetStat(
                id,
                FSetStat { handle: handle.opaque(), attrs: *attrs },
            ),
        )
        .await
    }

    /// Removes a file. This will not remove directories.
    pub async fn remove(&mut self, path: &str) -> SftpResult<()> {
        let id = self.begin().await?;
        self.request_status(
            id,
            SftpPacket::Remove(
                id,
                Remove { file_path: TextString(path.as_bytes()) },
            ),
        )
        .await
    }

    /// Creates a directory.
    pub async fn mkdir(&mut self, path: &str, attrs: &Attrs) -> SftpResult<()> {
        let id = self.begin().await?;
        self.request_status(
            id,
            SftpPacket::MkDir(
                id,
                MkDir { dir_path: TextString(path.as_bytes()), attrs: *attrs },
            ),
        )
        .await
    }

    /// Removes an empty directory.
    pub async fn rmdir(&mut self, path: &str) -> SftpResult<()> {
        let id = self.begin().await?;
        self.request_status(
            id,
            SftpPacket::RmDir(id, RmDir { dir_path: TextString(path.as_bytes()) }),
        )
        .await
    }

    /// Renames a file or directory.
    ///
    /// SFTP version 3 requires this to fail if `new` already exists.
    /// [`posix_rename()`](Self::posix_rename) replaces the destination
    /// instead, where the server supports it.
    pub async fn rename(&mut self, old: &str, new: &str) -> SftpResult<()> {
        let id = self.begin().await?;
        self.request_status(
            id,
            SftpPacket::Rename(
                id,
                Rename {
                    old_path: TextString(old.as_bytes()),
                    new_path: TextString(new.as_bytes()),
                },
            ),
        )
        .await
    }

    /// Creates a symbolic link at `link_path` pointing to `target_path`.
    pub async fn symlink(
        &mut self,
        target_path: &str,
        link_path: &str,
    ) -> SftpResult<()> {
        let id = self.begin().await?;
        self.request_status(
            id,
            SftpPacket::Symlink(
                id,
                Symlink {
                    target_path: TextString(target_path.as_bytes()),
                    link_path: TextString(link_path.as_bytes()),
                },
            ),
        )
        .await
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
        let id = self.begin().await?;
        let packet =
            SftpPacket::PathInfo(id, PathInfo { path: TextString(path.as_bytes()) });
        self.request_name(id, packet, out).await
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
        let id = self.begin().await?;
        let packet = SftpPacket::ReadLink(
            id,
            ReadLink { file_path: TextString(path.as_bytes()) },
        );
        self.request_name(id, packet, out).await
    }

    // ======================= Extended requests ===========================

    /// Sends an extended request with `args` as its payload.
    async fn request_extended(
        &mut self,
        name: &str,
        args: &dyn SSHEncode,
    ) -> SftpResult<()> {
        let id = self.begin().await?;
        let r = async {
            {
                let mut sink = SftpSink::new(&mut self.buf);
                SSH_FXP_EXTENDED.enc(&mut sink)?;
                id.enc(&mut sink)?;
                TextString(name.as_bytes()).enc(&mut sink)?;
                args.enc(&mut sink)?;
                let out = sink.used_slice();
                self.writer
                    .write_all(out)
                    .await
                    .map_err(SftpError::from_embedded_io)?;
            }
            self.writer.flush().await.map_err(SftpError::from_embedded_io)?;

            match self.recv(id).await? {
                SftpNum::SSH_FXP_STATUS => {
                    Self::status_result(self.recv_status_body().await?)
                }
                ty => {
                    debug!("Unexpected {:?} response to {}", ty, name);
                    Err(SftpError::BadResponse)
                }
            }
        }
        .await;
        self.finish(r).await
    }

    /// Renames a file, replacing `new` if it exists.
    ///
    /// Uses the `posix-rename@openssh.com` extension, only available
    /// when [`extensions()`](Self::extensions) reports `posix_rename`.
    pub async fn posix_rename(&mut self, old: &str, new: &str) -> SftpResult<()> {
        if !self.extensions.posix_rename {
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
        if !self.extensions.hardlink {
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
        if !self.extensions.fsync {
            return Err(SftpError::NotSupported);
        }
        handle.check(HandleKind::File)?;
        self.request_extended("fsync@openssh.com", &handle.opaque()).await
    }

    // Used by `DirIter`, which reads the response body itself.

    pub(crate) fn reader_buf(&mut self) -> (&mut R, &mut usize, &mut [u8]) {
        (&mut self.reader, &mut self.pkt_remaining, &mut self.buf)
    }

    pub(crate) fn set_poisoned(&mut self, poisoned: bool) {
        self.poisoned = poisoned;
    }

    pub(crate) async fn drain_packet(&mut self) -> SftpResult<()> {
        drain(&mut self.reader, &mut self.pkt_remaining).await
    }
}
