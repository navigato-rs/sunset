//! A SFTP client that performs no IO.
//!
//! [`SftpRunner`] is the protocol on its own: requests go in, bytes
//! come out, bytes go in, events come out. It is the same shape as
//! [`sunset::Runner`], and for the same reasons. The caller decides how
//! the bytes move, so it works from a blocking loop, an async task, or
//! a test that feeds it vectors of bytes.
//!
//! [`SftpClient`](super::SftpClient) is the async wrapper over it.
//!
//! File data is never copied through the runner. A read or write in
//! progress is reported by [`recv_data()`](SftpRunner::recv_data) or
//! [`send_data()`](SftpRunner::send_data), and the caller moves those
//! bytes itself.

use sunset::sshwire::{self, BinString, SSHEncode, TextString};

use crate::error::{SftpError, SftpResult};
use crate::proto::{
    Attrs, AttrsFlags, Extensions, InitVersionClient, MAX_PATH_LEN, MAX_REQUEST_LEN,
    ReqId, SFTP_MAXIMUM_PACKET_LEN, SFTP_MINIMUM_PACKET_LEN, SFTP_VERSION, SftpNum,
    SftpPacket, StatusCode,
};
use crate::sftpsink::SftpSink;

#[allow(unused_imports)]
use log::{debug, error, info, log, trace, warn};

/// Largest directory entry the client can decode.
///
/// A filename, the server's `ls -l` style long name, and attributes.
pub const MAX_DIR_ENTRY_LEN: usize = 2 * (4 + MAX_PATH_LEN) + 128;

const fn larger(a: usize, b: usize) -> usize {
    if a > b { a } else { b }
}

/// Default response buffer size for a client.
///
/// Large enough for the largest directory entry a server can send,
/// which is the biggest thing that has to be buffered.
pub const DEFAULT_CLIENT_BUF: usize = larger(MAX_REQUEST_LEN, MAX_DIR_ENTRY_LEN);

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

/// Flags for [`SftpRunner::open`] and [`SftpClient::open`](super::SftpClient::open).
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

/// Something the peer said.
///
/// Names and handles borrow the runner's buffer, so they last until the
/// next call. Copy anything needed for longer.
#[derive(Debug)]
pub enum SftpEvent<'a> {
    /// The version handshake completed.
    Version {
        /// Always [`SFTP_VERSION`], other versions are refused
        version: u32,
    },
    /// A handle for an open file or directory.
    Handle {
        /// The request this answers
        id: ReqId,
        /// The server's opaque handle
        handle: &'a [u8],
    },
    /// File or directory attributes.
    Attrs {
        /// The request this answers
        id: ReqId,
        /// The attributes
        attrs: Attrs,
    },
    /// A status, which may be success or failure.
    Status {
        /// The request this answers
        id: ReqId,
        /// The result
        code: StatusCode,
    },
    /// File data follows.
    ///
    /// The caller takes `len` bytes from the stream itself, see
    /// [`SftpRunner::recv_data`].
    Data {
        /// The read this answers
        id: ReqId,
        /// Bytes of file data that follow
        len: usize,
    },
    /// A `SSH_FXP_NAME` reply begins.
    ///
    /// [`Name`](Self::Name) follows `count` times, then
    /// [`NameEnd`](Self::NameEnd).
    NameStart {
        /// The request this answers
        id: ReqId,
        /// Entries that follow
        count: u32,
    },
    /// One entry of a `SSH_FXP_NAME` reply.
    ///
    /// A realpath or readlink reply has exactly one.
    Name {
        /// The request this answers
        id: ReqId,
        /// The file name, with no encoding defined by the protocol
        filename: &'a [u8],
        /// The server's `ls -l` style description, which may be empty
        longname: &'a [u8],
        /// Attributes of the entry
        attrs: Attrs,
    },
    /// The end of a `SSH_FXP_NAME` reply.
    NameEnd {
        /// The request this answers
        id: ReqId,
    },
}

/// What to do after an event has been collected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Advance {
    /// Start the next reply
    Packet,
    /// Take the next name entry of this reply
    Name,
}

/// What the runner is assembling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum In {
    /// The length, type and request id
    Header,
    /// A whole small packet body
    Body,
    /// The length of a `SSH_FXP_DATA` payload
    DataLen,
    /// The entry count of a `SSH_FXP_NAME`
    NameCount,
    /// One name entry, whose length is learned as it arrives
    NameEntry,
    /// Discarding the rest of a packet
    Drain,
}

/// A SFTP client with no IO of its own.
///
/// `REQ_BUF` holds one encoded request, so it must be at least
/// [`MAX_REQUEST_LEN`](crate::proto::MAX_REQUEST_LEN). `RESP_BUF` holds
/// the parts of a reply that aren't file data: a handle, a status, one
/// directory entry. File data is not buffered here.
pub struct SftpRunner<const REQ_BUF: usize, const RESP_BUF: usize> {
    /// One encoded request
    out: [u8; REQ_BUF],
    out_len: usize,
    out_pos: usize,
    /// Write payload the caller still has to send
    send_data: usize,

    /// The reply being assembled
    inb: [u8; RESP_BUF],
    /// Bytes of `inb` filled
    in_pos: usize,
    /// Bytes wanted before the next step
    in_need: usize,
    in_state: In,

    /// Read payload the caller still has to take
    recv_data: usize,

    /// Unconsumed bytes of the reply being read, after the type and id
    pkt_remaining: usize,
    pkt_ty: SftpNum,
    pkt_id: ReqId,
    /// Name entries still to come in this reply
    names_left: u32,

    /// An event waiting to be collected
    ready: bool,
    /// What to do once that event has been handed out. Deferred so the
    /// event can borrow the buffer it was decoded from.
    advance: Option<Advance>,

    /// Requests sent whose reply hasn't finished arriving
    outstanding: usize,

    next_id: u32,
    version: Option<u32>,
    extensions: Extensions,
}

impl<const REQ_BUF: usize, const RESP_BUF: usize> Default
    for SftpRunner<REQ_BUF, RESP_BUF>
{
    fn default() -> Self {
        Self::new()
    }
}

impl<const REQ_BUF: usize, const RESP_BUF: usize> SftpRunner<REQ_BUF, RESP_BUF> {
    /// Creates a runner. Send [`init()`](Self::init) before anything else.
    pub const fn new() -> Self {
        assert!(
            REQ_BUF >= crate::proto::MAX_REQUEST_LEN,
            "REQ_BUF must be at least MAX_REQUEST_LEN"
        );
        assert!(RESP_BUF >= SFTP_MINIMUM_PACKET_LEN, "RESP_BUF is too small");
        Self {
            out: [0; REQ_BUF],
            out_len: 0,
            out_pos: 0,
            send_data: 0,
            inb: [0; RESP_BUF],
            in_pos: 0,
            in_need: SFTP_MINIMUM_PACKET_LEN,
            in_state: In::Header,
            recv_data: 0,
            pkt_remaining: 0,
            pkt_ty: SftpNum::Other(0),
            pkt_id: ReqId(0),
            names_left: 0,
            ready: false,
            advance: None,
            outstanding: 0,
            next_id: 1,
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

    /// The negotiated version, once the handshake has completed.
    pub fn version(&self) -> Option<u32> {
        self.version
    }

    /// Extensions the server announced.
    pub fn extensions(&self) -> Extensions {
        self.extensions
    }

    /// Requests sent whose reply hasn't finished arriving.
    ///
    /// More than one while a transfer is pipelining. Non-zero after an
    /// abandoned request, whose reply still has to be read off the
    /// stream before the next one can be understood.
    pub fn outstanding(&self) -> usize {
        self.outstanding
    }

    /// Records that a reply has been dealt with.
    fn reply_done(&mut self) {
        self.outstanding = self.outstanding.saturating_sub(1);
    }

    // ============================== Output ==============================

    /// Bytes to send to the peer.
    ///
    /// Empty when there is nothing to send. Tell the runner what was
    /// sent with [`consume_output()`](Self::consume_output).
    pub fn output_buf(&self) -> &[u8] {
        &self.out[self.out_pos..self.out_len]
    }

    /// Records that `n` bytes from [`output_buf()`](Self::output_buf)
    /// were sent.
    pub fn consume_output(&mut self, n: usize) {
        self.out_pos = (self.out_pos + n).min(self.out_len);
        if self.out_pos == self.out_len {
            self.out_pos = 0;
            self.out_len = 0;
        }
    }

    /// File data the caller must send, following a write request.
    ///
    /// The runner never holds this data. Send that many bytes of
    /// whatever was passed to [`write()`](Self::write), then call
    /// [`data_sent()`](Self::data_sent).
    pub fn send_data(&self) -> Option<usize> {
        (self.send_data > 0 && self.output_buf().is_empty())
            .then_some(self.send_data)
    }

    /// Records that `n` bytes of write payload were sent.
    pub fn data_sent(&mut self, n: usize) {
        self.send_data = self.send_data.saturating_sub(n);
    }

    /// True when everything queued has been handed over.
    pub fn output_done(&self) -> bool {
        self.output_buf().is_empty() && self.send_data == 0
    }

    // ============================== Input ===============================

    /// File data the caller must take, following a
    /// [`SftpEvent::Data`].
    ///
    /// The runner never holds this data. Read that many bytes from the
    /// peer into wherever they belong, then call
    /// [`data_taken()`](Self::data_taken).
    pub fn recv_data(&self) -> Option<usize> {
        (self.recv_data > 0).then_some(self.recv_data)
    }

    /// Records that `n` bytes of file data were taken.
    pub fn data_taken(&mut self, n: usize) {
        let n = n.min(self.recv_data);
        self.recv_data -= n;
        self.pkt_remaining -= n;
        if self.recv_data == 0 {
            self.end_packet();
        }
    }

    /// How many bytes the runner wants next, the length of
    /// [`want_buf()`](Self::want_buf).
    fn want(&self) -> usize {
        if self.ready || self.recv_data > 0 {
            return 0;
        }
        if self.in_state == In::Drain {
            return self.in_need.saturating_sub(self.in_pos).min(RESP_BUF);
        }
        // A reply too long for the buffer is drained instead, so this
        // fits by the time the state is entered.
        self.in_need.min(RESP_BUF).saturating_sub(self.in_pos)
    }

    /// Where to read the next bytes from the peer into.
    ///
    /// This is **exactly the bytes the runner wants next**, not spare
    /// capacity: its length is how much of the current reply is still
    /// missing, often just the 9 bytes of a header. Read at most that
    /// many bytes, into this slice, then say how many arrived with
    /// [`input_done()`](Self::input_done).
    ///
    /// Reading into somewhere else and reporting the count here loses
    /// those bytes, so pass this slice to the transport rather than
    /// copying into it afterwards. Nothing is copied on the way in, the
    /// reply is assembled where it lands.
    ///
    /// Empty when the runner has something for the caller to deal with
    /// first: an event waiting for [`event()`](Self::event), or file
    /// data waiting for [`recv_data()`](Self::recv_data). Reading in
    /// that case would block for something that has already arrived.
    #[must_use]
    pub fn want_buf(&mut self) -> &mut [u8] {
        self.apply_advance();
        let n = self.want();
        if self.in_state == In::Drain {
            // Overwritten and discarded, however much of it there is
            return &mut self.inb[..n];
        }
        let start = self.in_pos.min(RESP_BUF);
        &mut self.inb[start..start + n]
    }

    /// Records that `n` bytes arrived in
    /// [`want_buf()`](Self::want_buf).
    ///
    /// Fails with `BadUsage` if `n` is more than that slice was long.
    /// Silently ignoring the excess would drop bytes and desynchronise
    /// the stream some replies later.
    pub fn input_done(&mut self, n: usize) -> SftpResult<()> {
        self.apply_advance();
        if n == 0 {
            return Ok(());
        }
        let want = self.want();
        if n > want {
            debug!("input_done({}) but only {} bytes were wanted", n, want);
            return Err(sunset::error::BadUsage.build().into());
        }
        self.in_pos += n;
        if self.in_pos >= self.in_need {
            self.step()?;
        }
        Ok(())
    }

    /// Feeds bytes from the peer, returning how many were used.
    ///
    /// A copying convenience over [`want_buf()`](Self::want_buf) for
    /// callers that already hold the bytes.
    ///
    /// Returns 0 while an event is waiting to be collected with
    /// [`event()`](Self::event), or while file data is waiting to be
    /// taken with [`recv_data()`](Self::recv_data).
    pub fn input(&mut self, buf: &[u8]) -> SftpResult<usize> {
        let dest = self.want_buf();
        let n = dest.len().min(buf.len());
        if n == 0 {
            return Ok(0);
        }
        dest[..n].copy_from_slice(&buf[..n]);
        self.input_done(n)?;
        Ok(n)
    }

    /// Whether an event is waiting for [`event()`](Self::event).
    ///
    /// False doesn't mean the peer has said nothing: more input may be
    /// needed, or file data may be waiting to be taken.
    pub fn has_event(&mut self) -> bool {
        self.apply_advance();
        self.ready
    }

    /// The next thing the peer said, if any.
    ///
    /// Call this until it returns `None` before feeding more input,
    /// which is refused while an event is waiting.
    pub fn event(&mut self) -> Option<SftpEvent<'_>> {
        self.apply_advance();
        if !self.ready {
            return None;
        }
        self.ready = false;

        // Decided before the buffer is borrowed below, and applied on
        // the next call, so the event can borrow what it decoded from.
        let name_part =
            (self.pkt_ty == SftpNum::SSH_FXP_NAME).then_some(self.in_state);
        self.advance = match self.pkt_ty {
            // The caller takes the payload, which finishes the reply
            SftpNum::SSH_FXP_DATA => None,
            SftpNum::SSH_FXP_NAME
                if matches!(self.in_state, In::NameCount | In::NameEntry) =>
            {
                Some(Advance::Name)
            }
            _ => Some(Advance::Packet),
        };

        // A reply is finished once its last event is handed out. A name
        // reply's last event is its NameEnd, not each entry.
        if !matches!(name_part, Some(In::NameCount) | Some(In::NameEntry)) {
            self.reply_done();
        }

        let id = self.pkt_id;
        let body = &self.inb[..self.in_pos];

        let ev = match self.pkt_ty {
            SftpNum::SSH_FXP_VERSION => {
                // The version was checked in step(), extensions recorded
                SftpEvent::Version { version: SFTP_VERSION }
            }
            SftpNum::SSH_FXP_STATUS => {
                let code = match sshwire::read_ssh::<StatusCode>(body, None) {
                    Ok((c, _)) => c,
                    Err(_) => StatusCode::SSH_FX_FAILURE,
                };
                SftpEvent::Status { id, code }
            }
            SftpNum::SSH_FXP_HANDLE => {
                let handle = match sshwire::read_ssh::<BinString>(body, None) {
                    Ok((h, _)) => h.0,
                    Err(_) => &[],
                };
                SftpEvent::Handle { id, handle }
            }
            SftpNum::SSH_FXP_ATTRS => {
                let attrs = sshwire::read_ssh::<Attrs>(body, None)
                    .map(|(a, _)| a)
                    .unwrap_or_default();
                SftpEvent::Attrs { id, attrs }
            }
            SftpNum::SSH_FXP_DATA => SftpEvent::Data { id, len: self.recv_data },
            SftpNum::SSH_FXP_NAME if name_part == Some(In::NameCount) => {
                SftpEvent::NameStart { id, count: self.names_left }
            }
            SftpNum::SSH_FXP_NAME if name_part == Some(In::NameEntry) => {
                name_event(id, body)
            }
            SftpNum::SSH_FXP_NAME => SftpEvent::NameEnd { id },
            _ => SftpEvent::Status { id, code: StatusCode::SSH_FX_FAILURE },
        };
        Some(ev)
    }

    /// Carries out what the previous event decided.
    fn apply_advance(&mut self) {
        match self.advance.take() {
            Some(Advance::Packet) => self.end_packet(),
            Some(Advance::Name) => self.next_name(),
            None => (),
        }
    }

    /// Finishes the current reply, discarding anything left of it.
    ///
    /// A reply can be longer than what was decoded from it: a status
    /// message too long for the buffer, or padding the entry count
    /// didn't cover.
    fn end_packet(&mut self) {
        if self.pkt_remaining > 0 {
            trace!("Discarding {} trailing bytes", self.pkt_remaining);
            self.in_state = In::Drain;
            self.in_need = self.pkt_remaining;
            self.in_pos = 0;
        } else {
            self.start_packet();
        }
    }

    /// Begins assembling the next reply.
    fn start_packet(&mut self) {
        self.in_state = In::Header;
        self.in_need = SFTP_MINIMUM_PACKET_LEN;
        self.in_pos = 0;
        self.names_left = 0;
    }

    /// Advances once `in_need` bytes have arrived.
    fn step(&mut self) -> SftpResult<()> {
        match self.in_state {
            In::Header => self.step_header(),
            In::Body => {
                if self.pkt_ty == SftpNum::SSH_FXP_VERSION {
                    parse_extensions(&self.inb[..self.in_pos], &mut self.extensions);
                }
                // Only a prefix is kept when the body is longer than the
                // buffer, the rest is discarded by end_packet().
                self.pkt_remaining -= self.in_pos;
                self.ready = true;
                Ok(())
            }
            In::DataLen => {
                let len = be32(&self.inb, 0).unwrap_or(0) as usize;
                self.pkt_remaining = self.pkt_remaining.saturating_sub(4);
                if len > self.pkt_remaining {
                    debug!("Data length {} beyond the packet", len);
                    return Err(SftpError::MalformedPacket);
                }
                self.recv_data = len;
                self.in_pos = 0;
                self.ready = true;
                Ok(())
            }
            In::NameCount => {
                self.names_left = be32(&self.inb, 0).unwrap_or(0);
                self.pkt_remaining = self.pkt_remaining.saturating_sub(4);
                // NameStart, the entries follow
                self.ready = true;
                Ok(())
            }
            In::NameEntry => {
                // The entry's length is learned as it arrives
                match name_entry_needed(&self.inb[..self.in_pos]) {
                    Some(n) if n > self.in_pos => {
                        if n > RESP_BUF {
                            debug!("Name entry of {} doesn't fit RESP_BUF", n);
                            return Err(SftpError::NoRoom);
                        }
                        self.in_need = n;
                        Ok(())
                    }
                    Some(_) => {
                        self.pkt_remaining =
                            self.pkt_remaining.saturating_sub(self.in_pos);
                        self.names_left = self.names_left.saturating_sub(1);
                        self.ready = true;
                        Ok(())
                    }
                    None => Err(SftpError::MalformedPacket),
                }
            }
            In::Drain => {
                self.start_packet();
                Ok(())
            }
        }
    }

    /// Moves to the next name entry, or ends the reply.
    fn next_name(&mut self) {
        self.in_pos = 0;
        if self.names_left == 0 {
            // NameEnd. Any bytes the entry count didn't cover are
            // discarded by end_packet() afterwards.
            self.in_state = In::Body;
            self.in_need = 0;
            self.ready = true;
            return;
        }
        self.in_state = In::NameEntry;
        self.in_need = 4;
    }

    /// Handles a complete length, type and request id.
    fn step_header(&mut self) -> SftpResult<()> {
        let len = be32(&self.inb, 0).unwrap_or(0) as usize;
        // The type and request id are counted in the length
        if len < 5 {
            debug!("Reply length {} is too short", len);
            return Err(SftpError::MalformedPacket);
        }
        self.pkt_ty = SftpNum::from(self.inb[4]);
        self.pkt_id = ReqId(be32(&self.inb, 5).unwrap_or(0));
        self.pkt_remaining = len - 5;

        // A data or name reply is bounded by what the peer may send,
        // the rest have to fit the buffer.
        let streamed =
            matches!(self.pkt_ty, SftpNum::SSH_FXP_DATA | SftpNum::SSH_FXP_NAME);
        if !streamed && len > SFTP_MAXIMUM_PACKET_LEN {
            debug!("Reply {:?} of {} is too long", self.pkt_ty, len);
            return Err(SftpError::MalformedPacket);
        }

        self.in_pos = 0;
        match self.pkt_ty {
            SftpNum::SSH_FXP_VERSION => {
                // Version replies carry a version rather than an id, so
                // the id read above is really the version.
                let version = self.pkt_id.0;
                if version != SFTP_VERSION {
                    warn!("Server SFTP version {} is not supported", version);
                    return Err(SftpError::NotSupported);
                }
                self.version = Some(version);
                // Extension pairs fill the rest. Any beyond the buffer
                // are discarded, they are only advisory.
                self.in_state = In::Body;
                self.in_need = self.pkt_remaining.min(RESP_BUF);
                if self.in_need == 0 {
                    self.step()?;
                }
                Ok(())
            }
            SftpNum::SSH_FXP_DATA => {
                self.in_state = In::DataLen;
                self.in_need = 4;
                Ok(())
            }
            SftpNum::SSH_FXP_NAME => {
                self.in_state = In::NameCount;
                self.in_need = 4;
                Ok(())
            }
            SftpNum::SSH_FXP_STATUS
            | SftpNum::SSH_FXP_HANDLE
            | SftpNum::SSH_FXP_ATTRS => {
                // Only what fits is decoded. That is enough for the
                // status code and the attributes, which come first; a
                // long status message is discarded after it.
                self.in_state = In::Body;
                self.in_need = self.pkt_remaining.min(RESP_BUF);
                if self.in_need == 0 {
                    self.step()?;
                }
                Ok(())
            }
            ty => {
                debug!("Unexpected {:?} reply, discarding", ty);
                // Still answers a request, whatever it is
                self.reply_done();
                self.in_state = In::Drain;
                self.in_need = self.pkt_remaining;
                if self.in_need == 0 {
                    self.start_packet();
                }
                Ok(())
            }
        }
    }

    // ============================= Requests =============================

    fn next_id(&mut self) -> ReqId {
        let id = ReqId(self.next_id);
        self.next_id = self.next_id.wrapping_add(1);
        id
    }

    /// Queues the version handshake, which must be sent first.
    pub fn init(&mut self) -> SftpResult<()> {
        if self.version.is_some() {
            return Err(SftpError::AlreadyInitialized);
        }
        if !self.output_done() {
            return Err(sunset::error::BadUsage.build().into());
        }
        let init = SftpPacket::Init(InitVersionClient { version: SFTP_VERSION });
        let mut sink = SftpSink::new(&mut self.out);
        init.enc(&mut sink)?;
        self.out_len = sink.used_slice().len();
        self.out_pos = 0;
        self.outstanding += 1;
        Ok(())
    }

    /// Checks a request may be queued now.
    fn ready_to_send(&self) -> SftpResult<()> {
        if self.version.is_none() {
            return Err(SftpError::NotInitialized);
        }
        if !self.output_done() {
            // The previous request hasn't been handed over yet
            return Err(sunset::error::BadUsage.build().into());
        }
        Ok(())
    }

    /// Queues one request, returning its id.
    ///
    /// `'p` is the lifetime of the caller's arguments that the packet borrows;
    /// it is unrelated to the runner's own buffers.
    fn one<'p, F>(&mut self, f: F) -> SftpResult<ReqId>
    where
        F: FnOnce(ReqId) -> SftpPacket<'p>,
    {
        self.ready_to_send()?;
        let id = self.next_id();
        // The packet borrows the caller's arguments, not the runner
        let p = f(id);
        trace!("SFTP ----> {:?}", p);
        let mut sink = SftpSink::new(&mut self.out);
        p.encode_request(&mut sink)?;
        self.out_len = sink.used_slice().len();
        self.out_pos = 0;
        self.outstanding += 1;
        Ok(id)
    }

    /// Opens a file.
    pub fn open(
        &mut self,
        path: &str,
        flags: u32,
        attrs: &Attrs,
    ) -> SftpResult<ReqId> {
        self.one(|id| {
            SftpPacket::Open(
                id,
                crate::proto::Open {
                    filename: crate::proto::Filename::from(path),
                    pflags: crate::proto::PFlags::from(flags),
                    attrs: *attrs,
                },
            )
        })
    }

    /// Opens a directory for listing.
    pub fn opendir(&mut self, path: &str) -> SftpResult<ReqId> {
        self.one(|id| {
            SftpPacket::OpenDir(
                id,
                crate::proto::OpenDir {
                    dirname: crate::proto::Filename::from(path),
                },
            )
        })
    }

    /// Closes a file or directory handle.
    pub fn close(&mut self, handle: &[u8]) -> SftpResult<ReqId> {
        self.one(|id| {
            SftpPacket::Close(id, crate::proto::Close { handle: opaque(handle) })
        })
    }

    /// Requests `len` bytes of an open file.
    pub fn read(
        &mut self,
        handle: &[u8],
        offset: u64,
        len: u32,
    ) -> SftpResult<ReqId> {
        self.one(|id| {
            SftpPacket::Read(
                id,
                crate::proto::Read { handle: opaque(handle), offset, len },
            )
        })
    }

    /// Requests the next batch of directory entries.
    pub fn readdir(&mut self, handle: &[u8]) -> SftpResult<ReqId> {
        self.one(|id| {
            SftpPacket::ReadDir(id, crate::proto::ReadDir { handle: opaque(handle) })
        })
    }

    /// Attributes of a path, following symbolic links.
    pub fn stat(&mut self, path: &str) -> SftpResult<ReqId> {
        self.one(|id| {
            SftpPacket::Stat(
                id,
                crate::proto::Stat { file_path: TextString(path.as_bytes()) },
            )
        })
    }

    /// Attributes of a path, without following symbolic links.
    pub fn lstat(&mut self, path: &str) -> SftpResult<ReqId> {
        self.one(|id| {
            SftpPacket::LStat(
                id,
                crate::proto::LStat { file_path: TextString(path.as_bytes()) },
            )
        })
    }

    /// Attributes of an open file.
    pub fn fstat(&mut self, handle: &[u8]) -> SftpResult<ReqId> {
        self.one(|id| {
            SftpPacket::FStat(id, crate::proto::FStat { handle: opaque(handle) })
        })
    }

    /// Modifies the attributes of a path.
    pub fn setstat(&mut self, path: &str, attrs: &Attrs) -> SftpResult<ReqId> {
        self.one(|id| {
            SftpPacket::SetStat(
                id,
                crate::proto::SetStat {
                    file_path: TextString(path.as_bytes()),
                    attrs: *attrs,
                },
            )
        })
    }

    /// Modifies the attributes of an open file.
    pub fn fsetstat(&mut self, handle: &[u8], attrs: &Attrs) -> SftpResult<ReqId> {
        self.one(|id| {
            SftpPacket::FSetStat(
                id,
                crate::proto::FSetStat { handle: opaque(handle), attrs: *attrs },
            )
        })
    }

    /// Removes a file.
    pub fn remove(&mut self, path: &str) -> SftpResult<ReqId> {
        self.one(|id| {
            SftpPacket::Remove(
                id,
                crate::proto::Remove { file_path: TextString(path.as_bytes()) },
            )
        })
    }

    /// Creates a directory.
    pub fn mkdir(&mut self, path: &str, attrs: &Attrs) -> SftpResult<ReqId> {
        self.one(|id| {
            SftpPacket::MkDir(
                id,
                crate::proto::MkDir {
                    dir_path: TextString(path.as_bytes()),
                    attrs: *attrs,
                },
            )
        })
    }

    /// Removes an empty directory.
    pub fn rmdir(&mut self, path: &str) -> SftpResult<ReqId> {
        self.one(|id| {
            SftpPacket::RmDir(
                id,
                crate::proto::RmDir { dir_path: TextString(path.as_bytes()) },
            )
        })
    }

    /// Renames, failing if `new` exists.
    pub fn rename(&mut self, old: &str, new: &str) -> SftpResult<ReqId> {
        self.one(|id| {
            SftpPacket::Rename(
                id,
                crate::proto::Rename {
                    old_path: TextString(old.as_bytes()),
                    new_path: TextString(new.as_bytes()),
                },
            )
        })
    }

    /// Creates a symbolic link.
    pub fn symlink(&mut self, target: &str, link: &str) -> SftpResult<ReqId> {
        self.one(|id| {
            SftpPacket::Symlink(
                id,
                crate::proto::Symlink {
                    target_path: TextString(target.as_bytes()),
                    link_path: TextString(link.as_bytes()),
                },
            )
        })
    }

    /// Canonicalises a path.
    pub fn realpath(&mut self, path: &str) -> SftpResult<ReqId> {
        self.one(|id| {
            SftpPacket::PathInfo(
                id,
                crate::proto::PathInfo { path: TextString(path.as_bytes()) },
            )
        })
    }

    /// Reads a symbolic link's target.
    pub fn readlink(&mut self, path: &str) -> SftpResult<ReqId> {
        self.one(|id| {
            SftpPacket::ReadLink(
                id,
                crate::proto::ReadLink { file_path: TextString(path.as_bytes()) },
            )
        })
    }

    /// Queues a `SSH_FXP_WRITE` header for `len` bytes of data.
    ///
    /// The data itself is not held here. After the header has been sent,
    /// [`send_data()`](Self::send_data) reports how much payload the
    /// caller must send.
    ///
    /// `len` may be at most [`MAX_WRITE_LEN`], otherwise
    /// [`SftpError::NoRoom`] is returned. Split a longer write into
    /// several requests.
    pub fn write(
        &mut self,
        handle: &[u8],
        offset: u64,
        len: usize,
    ) -> SftpResult<ReqId> {
        if len > MAX_WRITE_LEN as usize {
            // Servers are only required to accept packets up to 34000
            // bytes, so a longer write is refused here rather than
            // having the peer drop the channel partway through it.
            debug!("Write of {} is beyond MAX_WRITE_LEN {}", len, MAX_WRITE_LEN);
            return Err(SftpError::NoRoom);
        }
        self.ready_to_send()?;
        let id = self.next_id();
        let body_len = 1 + 4 + 4 + handle.len() + 8 + 4 + len;
        let body_len: u32 = body_len.try_into().map_err(|_| SftpError::NoRoom)?;

        let mut sink = SftpSink::new(&mut self.out);
        // The length is written explicitly, the sink's own is skipped
        // by using payload_slice().
        body_len.enc(&mut sink)?;
        u8::from(SftpNum::SSH_FXP_WRITE).enc(&mut sink)?;
        id.enc(&mut sink)?;
        BinString(handle).enc(&mut sink)?;
        offset.enc(&mut sink)?;
        (len as u32).enc(&mut sink)?;
        self.out_len = sink.payload_len();
        // payload_slice() starts after the length field the sink adds
        self.out.copy_within(4..4 + self.out_len, 0);
        self.out_pos = 0;
        self.send_data = len;
        self.outstanding += 1;
        Ok(id)
    }

    /// Queues an extended request with `args` as its payload.
    pub fn extended(
        &mut self,
        name: &str,
        args: &dyn SSHEncode,
    ) -> SftpResult<ReqId> {
        self.ready_to_send()?;
        let id = self.next_id();
        let mut sink = SftpSink::new(&mut self.out);
        crate::proto::SSH_FXP_EXTENDED.enc(&mut sink)?;
        id.enc(&mut sink)?;
        TextString(name.as_bytes()).enc(&mut sink)?;
        args.enc(&mut sink)?;
        self.out_len = sink.used_slice().len();
        self.out_pos = 0;
        self.outstanding += 1;
        Ok(id)
    }
}

/// Wraps a raw handle for encoding.
fn opaque(handle: &[u8]) -> crate::proto::OpaqueHandle<'_> {
    crate::proto::OpaqueHandle(BinString(handle))
}

/// Decodes one assembled name entry.
fn name_event(id: ReqId, body: &[u8]) -> SftpEvent<'_> {
    // OK fallbacks, name_entry_needed() checked these lengths
    let flen = be32(body, 0).unwrap_or(0) as usize;
    let filename = body.get(4..4 + flen).unwrap_or(&[]);
    let llen = be32(body, 4 + flen).unwrap_or(0) as usize;
    let longname = body.get(8 + flen..8 + flen + llen).unwrap_or(&[]);
    let attrs = body
        .get(8 + flen + llen..)
        .and_then(|a| sshwire::read_ssh::<Attrs>(a, None).ok())
        .map(|(a, _)| a)
        .unwrap_or_default();
    SftpEvent::Name { id, filename, longname, attrs }
}

/// Records the extensions announced in a version reply.
fn parse_extensions(mut b: &[u8], ext: &mut Extensions) {
    // name/data pairs until the packet ends
    while b.len() >= 4 {
        let Some(nlen) = be32(b, 0).map(|l| l as usize) else { break };
        let Some(name) = b.get(4..4 + nlen) else { break };
        ext.set_by_name(name);
        b = &b[4 + nlen..];
        let Some(dlen) = be32(b, 0).map(|l| l as usize) else { break };
        let Some(rest) = b.get(4 + dlen..) else { break };
        b = rest;
    }
}

/// Reads a big endian `u32` at `off`.
fn be32(b: &[u8], off: usize) -> Option<u32> {
    b.get(off..off + 4).map(|v| u32::from_be_bytes(v.try_into().unwrap()))
}

/// Total length of a name entry, as far as it can be told from `b`.
///
/// Returns the smallest total that is known to be needed, which grows
/// as more of the entry arrives. `None` if `b` is malformed.
fn name_entry_needed(b: &[u8]) -> Option<usize> {
    let Some(flen) = be32(b, 0).map(|l| l as usize) else {
        return Some(4);
    };
    let after_name = 4usize.checked_add(flen)?.checked_add(4)?;
    let Some(llen) = be32(b, 4 + flen).map(|l| l as usize) else {
        return Some(after_name);
    };
    let attrs_at = after_name.checked_add(llen)?;
    attrs_needed(b, attrs_at)
}

/// Total length up to the end of the attributes starting at `off`.
fn attrs_needed(b: &[u8], off: usize) -> Option<usize> {
    let Some(flags) = be32(b, off) else {
        return off.checked_add(4);
    };
    let mut len = off.checked_add(4)?;
    if flags & AttrsFlags::SSH_FILEXFER_ATTR_SIZE != 0 {
        len = len.checked_add(8)?;
    }
    if flags & AttrsFlags::SSH_FILEXFER_ATTR_UIDGID != 0 {
        len = len.checked_add(8)?;
    }
    if flags & AttrsFlags::SSH_FILEXFER_ATTR_PERMISSIONS != 0 {
        len = len.checked_add(4)?;
    }
    if flags & AttrsFlags::SSH_FILEXFER_ATTR_ACMODTIME != 0 {
        len = len.checked_add(8)?;
    }
    if flags & AttrsFlags::SSH_FILEXFER_ATTR_EXTENDED != 0 {
        let Some(count) = be32(b, len) else {
            return len.checked_add(4);
        };
        len = len.checked_add(4)?;
        for _ in 0..count {
            for _ in 0..2 {
                let Some(l) = be32(b, len) else {
                    return len.checked_add(4);
                };
                len = len.checked_add(4)?.checked_add(l as usize)?;
            }
        }
    }
    Some(len)
}

#[cfg(test)]
mod tests {
    use super::*;

    extern crate std;
    use std::vec::Vec;

    const REQ: usize = crate::proto::MAX_REQUEST_LEN;
    const RESP: usize = 1024;
    type R = SftpRunner<REQ, RESP>;

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

    fn version_packet(exts: &[&str]) -> Vec<u8> {
        let mut body = std::vec![2u8];
        body.extend_from_slice(&3u32.to_be_bytes());
        for e in exts {
            body.extend_from_slice(&string(e.as_bytes()));
            body.extend_from_slice(&string(b"1"));
        }
        packet(body)
    }

    fn status_packet(id: u32, code: u32) -> Vec<u8> {
        let mut body = std::vec![101u8];
        body.extend_from_slice(&id.to_be_bytes());
        body.extend_from_slice(&code.to_be_bytes());
        body.extend_from_slice(&string(b""));
        body.extend_from_slice(&string(b""));
        packet(body)
    }

    /// Feeds every byte, handing events to `f` and returning any file
    /// data, which the runner never holds.
    ///
    /// This is the shape of any caller: move bytes, drain events.
    fn feed<F>(r: &mut R, mut b: &[u8], mut f: F) -> Vec<u8>
    where
        F: FnMut(&SftpEvent<'_>),
    {
        let mut data = Vec::new();
        loop {
            while let Some(ev) = r.event() {
                f(&ev);
            }
            if let Some(n) = r.recv_data() {
                let n = n.min(b.len());
                if n > 0 {
                    data.extend_from_slice(&b[..n]);
                    r.data_taken(n);
                    b = &b[n..];
                    continue;
                }
            }
            if b.is_empty() {
                return data;
            }
            let n = r.input(b).expect("input");
            assert!(n > 0, "stuck with {} bytes left", b.len());
            b = &b[n..];
        }
    }

    fn init(r: &mut R, exts: &[&str]) {
        r.init().unwrap();
        // SSH_FXP_INIT with version 3
        assert_eq!(r.output_buf(), packet(std::vec![1, 0, 0, 0, 3]).as_slice());
        let n = r.output_buf().len();
        r.consume_output(n);
        assert!(r.output_done());

        let mut seen = false;
        let _ = feed(r, &version_packet(exts), |e| {
            if matches!(e, SftpEvent::Version { .. }) {
                seen = true
            }
        });
        assert!(seen, "expected a version event");
        assert_eq!(r.version(), Some(3));
    }

    #[test]
    fn handshake_and_extensions() {
        let mut r = R::new();
        init(&mut r, &["posix-rename@openssh.com", "fsync@openssh.com"]);
        let e = r.extensions();
        assert!(e.posix_rename && e.fsync);
        assert!(!e.hardlink);
    }

    #[test]
    fn a_status_reply() {
        let mut r = R::new();
        init(&mut r, &[]);
        let mut got = None;
        let _ = feed(&mut r, &status_packet(7, 2), |e| {
            if let SftpEvent::Status { id, code } = e {
                got = Some((*id, *code));
            }
        });
        assert_eq!(got, Some((ReqId(7), StatusCode::SSH_FX_NO_SUCH_FILE)));
        assert!(r.event().is_none());
    }

    #[test]
    fn a_handle_reply() {
        let mut r = R::new();
        init(&mut r, &[]);
        let mut body = std::vec![102u8];
        body.extend_from_slice(&3u32.to_be_bytes());
        body.extend_from_slice(&string(b"abcd"));
        let mut got = None;
        let _ = feed(&mut r, &packet(body), |e| {
            if let SftpEvent::Handle { id, handle } = e {
                got = Some((*id, handle.to_vec()));
            }
        });
        assert_eq!(got, Some((ReqId(3), b"abcd".to_vec())));
    }

    #[test]
    fn file_data_is_not_copied_through_the_runner() {
        let mut r = R::new();
        init(&mut r, &[]);

        let content: Vec<u8> = (0..5000u32).map(|i| i as u8).collect();
        let mut body = std::vec![103u8];
        body.extend_from_slice(&9u32.to_be_bytes());
        body.extend_from_slice(&string(&content));

        // The data is handed back rather than buffered, so it works
        // with a RESP_BUF far smaller than the payload.
        let mut announced = 0;
        let got = feed(&mut r, &packet(body), |e| {
            if let SftpEvent::Data { len, .. } = e {
                announced += len;
            }
        });
        assert_eq!(announced, content.len(), "announced length");
        assert_eq!(got, content, "and the bytes arrived intact");
        assert!(RESP < content.len(), "the payload doesn't fit the buffer");
    }

    #[test]
    fn a_name_reply_with_several_entries() {
        let mut r = R::new();
        init(&mut r, &[]);

        let mut body = std::vec![104u8];
        body.extend_from_slice(&4u32.to_be_bytes());
        body.extend_from_slice(&2u32.to_be_bytes());
        for (name, long) in [(&b"one"[..], &b"-rw- one"[..]), (b"two", b"")] {
            body.extend_from_slice(&string(name));
            body.extend_from_slice(&string(long));
            // SSH_FILEXFER_ATTR_SIZE
            body.extend_from_slice(&1u32.to_be_bytes());
            body.extend_from_slice(&42u64.to_be_bytes());
        }
        let mut names = Vec::new();
        let mut started = None;
        let mut ended = false;
        let _ = feed(&mut r, &packet(body), |e| match e {
            SftpEvent::NameStart { id, count } => {
                assert_eq!(*id, ReqId(4));
                started = Some(*count);
            }
            SftpEvent::Name { filename, longname, attrs, .. } => {
                assert_eq!(attrs.size, Some(42));
                names.push((filename.to_vec(), longname.to_vec()));
            }
            SftpEvent::NameEnd { id } => {
                assert_eq!(*id, ReqId(4));
                ended = true;
            }
            e => panic!("unexpected {e:?}"),
        });
        assert_eq!(started, Some(2), "the entry count comes first");
        assert!(ended, "expected the reply to end");
        assert_eq!(names.len(), 2);
        assert_eq!(names[0].0, b"one");
        assert_eq!(names[0].1, b"-rw- one");
        assert_eq!(names[1].0, b"two");
        assert!(names[1].1.is_empty());
    }

    /// The peer's bytes arrive in whatever sized pieces the transport
    /// gives, which the async client could only be tested against over
    /// a real connection.
    #[test]
    fn replies_split_at_every_byte() {
        for chunk in [1usize, 2, 3, 5, 7, 13] {
            let mut r = R::new();
            r.init().unwrap();
            let n = r.output_buf().len();
            r.consume_output(n);

            let mut stream = version_packet(&["fsync@openssh.com"]);
            stream.extend_from_slice(&status_packet(1, 0));
            let mut body = std::vec![102u8];
            body.extend_from_slice(&2u32.to_be_bytes());
            body.extend_from_slice(&string(b"xy"));
            stream.extend_from_slice(&packet(body));

            let mut events = Vec::new();
            let mut b = &stream[..];
            while !b.is_empty() {
                let take = chunk.min(b.len());
                let mut piece = &b[..take];
                while !piece.is_empty() {
                    let n = r.input(piece).expect("input");
                    piece = &piece[n..];
                    while let Some(ev) = r.event() {
                        events.push(std::format!("{ev:?}"));
                    }
                    if n == 0 {
                        break;
                    }
                }
                b = &b[take..];
            }
            while let Some(ev) = r.event() {
                events.push(std::format!("{ev:?}"));
            }

            assert_eq!(events.len(), 3, "chunk {chunk}: {events:?}");
            assert!(events[0].starts_with("Version"), "chunk {chunk}");
            assert!(events[1].starts_with("Status"), "chunk {chunk}");
            assert!(events[2].starts_with("Handle"), "chunk {chunk}");
            assert!(r.extensions().fsync, "chunk {chunk}");
        }
    }

    #[test]
    fn a_write_header_leaves_the_payload_to_the_caller() {
        let mut r = R::new();
        init(&mut r, &[]);

        r.write(b"abcd", 64, 3000).unwrap();

        // type(1) id(4) handle(4+4) offset(8) len(4)
        let header = r.output_buf().to_vec();
        assert_eq!(header.len(), 4 + 25);
        let plen = u32::from_be_bytes(header[..4].try_into().unwrap());
        assert_eq!(plen as usize, 25 + 3000, "length covers the payload");
        assert_eq!(header[4], 6, "SSH_FXP_WRITE");

        // The payload isn't held here, it is the caller's to send
        assert_eq!(r.send_data(), None, "not until the header has gone");
        r.consume_output(header.len());
        assert_eq!(r.send_data(), Some(3000));
        r.data_sent(1000);
        assert_eq!(r.send_data(), Some(2000));
        r.data_sent(2000);
        assert!(r.output_done());
    }

    /// A reply longer than the buffer is answered from the prefix that
    /// fits and the rest discarded, rather than dropping the whole
    /// reply and leaving its request unanswered forever.
    #[test]
    fn a_reply_too_big_for_the_buffer_is_truncated_not_dropped() {
        let mut r = R::new();
        init(&mut r, &[]);

        // A handle longer than RESP_BUF
        let huge = std::vec![0x41u8; RESP + 100];
        let mut body = std::vec![102u8];
        body.extend_from_slice(&5u32.to_be_bytes());
        body.extend_from_slice(&string(&huge));
        let mut got = None;
        let _ = feed(&mut r, &packet(body), |e| {
            if let SftpEvent::Handle { id, handle } = e {
                got = Some((*id, handle.len()));
            }
        });
        assert_eq!(got, Some((ReqId(5), 0)), "answered, with nothing usable");
        assert_eq!(r.outstanding(), 0, "the request is no longer waiting");

        // The next reply is still understood
        let mut got = None;
        let _ = feed(&mut r, &status_packet(6, 0), |e| {
            if let SftpEvent::Status { id, .. } = e {
                got = Some(*id)
            }
        });
        assert_eq!(got, Some(ReqId(6)));
    }

    /// A status message longer than the buffer still yields its code.
    #[test]
    fn a_long_status_message_still_gives_its_code() {
        let mut r = R::new();
        init(&mut r, &[]);

        let mut body = std::vec![101u8];
        body.extend_from_slice(&7u32.to_be_bytes());
        // SSH_FX_PERMISSION_DENIED
        body.extend_from_slice(&3u32.to_be_bytes());
        body.extend_from_slice(&string(&std::vec![b'x'; RESP * 2]));
        body.extend_from_slice(&string(b"en"));

        let mut got = None;
        let _ = feed(&mut r, &packet(body), |e| {
            if let SftpEvent::Status { id, code } = e {
                got = Some((*id, *code));
            }
        });
        assert_eq!(got, Some((ReqId(7), StatusCode::SSH_FX_PERMISSION_DENIED)));

        // and the stream is still in step
        let mut next = None;
        let _ = feed(&mut r, &status_packet(8, 0), |e| {
            if let SftpEvent::Status { id, .. } = e {
                next = Some(*id)
            }
        });
        assert_eq!(next, Some(ReqId(8)));
    }

    /// A write beyond what servers must accept is refused here, rather
    /// than by the peer dropping the channel partway through it.
    #[test]
    fn an_oversized_write_is_refused() {
        let mut r = R::new();
        init(&mut r, &[]);

        let too_big = MAX_WRITE_LEN as usize + 1;
        assert!(matches!(r.write(b"abcd", 0, too_big), Err(SftpError::NoRoom)));
        // and nothing was queued for it
        assert!(r.output_done());
        assert_eq!(r.outstanding(), 0);

        // The largest allowed write is still fine
        r.write(b"abcd", 0, MAX_WRITE_LEN as usize).unwrap();
        let n = r.output_buf().len();
        r.consume_output(n);
        assert_eq!(r.send_data(), Some(MAX_WRITE_LEN as usize));
    }

    /// Claiming more input than was asked for used to be clamped, which
    /// dropped the excess and desynchronised the stream a few replies
    /// later rather than where the mistake was.
    #[test]
    fn over_reporting_input_is_refused() {
        let mut r = R::new();
        r.init().unwrap();
        let n = r.output_buf().len();
        r.consume_output(n);

        // The header is wanted first, and nothing more
        assert_eq!(r.want_buf().len(), SFTP_MINIMUM_PACKET_LEN);
        assert!(r.input_done(SFTP_MINIMUM_PACKET_LEN + 1).is_err());

        // The runner is unmoved, and a correct sequence still works
        assert_eq!(r.want_buf().len(), SFTP_MINIMUM_PACKET_LEN);
        let v = version_packet(&[]);
        let n = r.input(&v).expect("input");
        assert!(n > 0);
        let _ = feed(&mut r, &v[n..], |_| ());
        assert_eq!(r.version(), Some(3));
    }

    /// Requests are counted until their reply has been fully read, so
    /// an abandoned one can be drained before the next.
    #[test]
    fn outstanding_requests_are_counted() {
        let mut r = R::new();
        init(&mut r, &[]);
        assert_eq!(r.outstanding(), 0);

        r.stat("/one").unwrap();
        let n = r.output_buf().len();
        r.consume_output(n);
        r.lstat("/two").unwrap();
        let n = r.output_buf().len();
        r.consume_output(n);
        assert_eq!(r.outstanding(), 2);

        let _ = feed(&mut r, &status_packet(4, 2), |_| ());
        assert_eq!(r.outstanding(), 1);
        let _ = feed(&mut r, &status_packet(5, 2), |_| ());
        assert_eq!(r.outstanding(), 0);
    }
}
