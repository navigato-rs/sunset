//! SFTP (SSH File Transfer Protocol) implementation for [`sunset`].
//!
//! Implements SFTP v3 as defined in [draft-ietf-secsh-filexfer-02](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02).
//!
//! **Work in Progress**: please see the roadmap and use this crate carefully.
//!
//! Both sides are `no_std` and allocation free. While designed for use
//! with Sunset SSH, they should be usable with any transport.
//!
//! The client's protocol core does no IO of its own, so it needs
//! nothing of the transport at all; the layers that do read and write
//! use the `embedded_io_async` `Read`/`Write` traits, and are behind
//! the default `async` feature. With `default-features = false` this
//! crate has no async dependencies whatsoever.
//!
//! # Server
//!
//! [`SftpServerHandler`] dispatches SFTP packets to a struct implementing
//! the [`SftpServer`](server::SftpServer) trait, which the application
//! provides to describe its filesystem. The server side is async
//! throughout, so it needs the `async` feature.
//!
//! See example usage in the `../demo/sftp/std` directory.
//!
//! # Client
//!
//! [`SftpRunner`](client::SftpRunner) is the protocol on its own and
//! performs no IO: requests go in, bytes come out, bytes go in,
//! [events](client::SftpEvent) come out. That is the same shape as
//! [`sunset::Runner`], and for the same reasons — the caller decides
//! how the bytes move, so it works from a blocking loop, an interrupt
//! handler, or a test that feeds it byte by byte.
//!
//! ```
//! use sunset_sftp::client::{SftpEvent, SftpRunner};
//! use sunset_sftp::error::SftpResult;
//!
//! /// Asks for a path's attributes, moving the bytes with the two
//! /// closures. Neither the runner nor this function does any IO.
//! fn size<const B: usize>(
//!     sftp: &mut SftpRunner<B, B>,
//!     path: &str,
//!     mut send: impl FnMut(&[u8]),
//!     mut recv: impl FnMut(&mut [u8]) -> usize,
//! ) -> SftpResult<Option<u64>> {
//!     sftp.stat(path)?;
//!     while !sftp.output_buf().is_empty() {
//!         send(sftp.output_buf());
//!         let sent = sftp.output_buf().len();
//!         sftp.consume_output(sent);
//!     }
//!
//!     while !sftp.has_event() {
//!         let got = recv(sftp.want_buf());
//!         sftp.input_done(got)?;
//!     }
//!     Ok(match sftp.event() {
//!         Some(SftpEvent::Attrs { attrs, .. }) => attrs.size,
//!         _ => None,
//!     })
//! }
//! ```
//!
//! [`SftpClient`](client::SftpClient) is the `embedded_io_async` layer
//! over that, for a SSH channel that has had the `sftp` subsystem
//! started on it. With `sunset-async` that is a client session channel
//! opened with `SSHClient::open_session_nopty()`, with
//! `SessionCommand::Subsystem("sftp")` requested on it. It needs the
//! `async` feature, which is on by default; without it this crate has
//! no async dependencies at all.
//!
//! File contents and directory listings are streamed, so transfers
//! aren't limited by the client's buffer size. Reads and writes larger
//! than one packet are split into several requests, and reads are
//! pipelined so that a download isn't limited to one chunk per round
//! trip. Writes wait for each reply, see [`SftpClient::write`](client::SftpClient::write).
//!
//! # Roadmap
//!
//! The following list is an opinionated collection of the points that should be
//! completed to provide growing functionality.
//!
//! ## Basic features
//!
//! - [x] [SFTP Protocol Initialization](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02#section-4) (Only SFTP V3 supported)
//! - [x] [Canonicalizing the Server-Side Path Name](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02#section-6.11) support
//! - [x] [Open, close](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02#section-6.3)
//!   and [write](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02#section-6.4)
//! - [x] Directory [Browsing](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02#section-6.7)
//! - [x] File [read](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02#section-6.4)
//! - [x] File [write](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02#section-6.4)
//! - [x] File [stats](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02#section-6.8)
//!
//! ## Minimal features for convenient usability
//!
//! - [x] [Removing files](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02#section-6.5)
//! - [x] [Renaming files](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02#section-6.5)
//! - [x] [Creating directories](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02#section-6.6)
//! - [x] [Removing directories](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02#section-6.6)
//!
//! ## Extended features
//!
//! - [x] [Append, create and truncate files](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02#section-6.3)
//! - [x] [Reading](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02#section-6.8) files attributes
//! - [x] [Setting](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02#section-6.9) files attributes
//! - [x] [Dealing with Symbolic links](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02#section-6.10)
//! - [x] [Vendor Specific](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02#section-8)
//!   requests. The `posix-rename`, `hardlink` and `fsync` OpenSSH
//!   extensions are implemented on both sides; any other
//!   `SSH_FXP_EXTENDED` is answered with `SSH_FX_OP_UNSUPPORTED`.
//!
//! ## Client
//!
//! - [x] A commandline SFTP client, `sftpc` in `sunset-stdasync`
//! - [x] Pipelining reads, to avoid a round trip per block downloaded
//! - [x] A sans-io core, [`SftpRunner`](client::SftpRunner), so the
//!   protocol isn't tied to `embedded_io_async`
//!
//! ## Desirable
//!
//! - The same sans-io treatment for the server. The
//!   [`SftpServer`](server::SftpServer) trait is async by design, since
//!   a filesystem operation may well have to wait, so this would be a
//!   second way of writing a server rather than a rework of that one.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![no_std]
// Nested if statements are often more logical,
// or allow for future additions.
#![allow(clippy::collapsible_if)]

mod proto;
mod sftpclient;
mod sftperror;
mod sftpsink;

#[cfg(feature = "async")]
mod sftphandler;
#[cfg(feature = "async")]
mod sftpserver;
#[cfg(feature = "async")]
mod sftpsource;

// Main calling point for the library provided that the user implements
// a [`server::SftpServer`].
//
// Please see basic usage at `../demo/sftp/std`
#[cfg(feature = "async")]
pub use sftphandler::SftpServerHandler;

/// Structures and types used to add the details for the target system
///
/// Related to the implementation of the [`server::SftpServer`], which
/// is meant to be instantiated by the user and passed to [`SftpServerHandler`]
/// and has the task of executing client requests in the underlying system
#[cfg(feature = "async")]
pub mod server {

    pub use crate::sftpserver::{
        DirReadDataReply, DirReadHeaderReply, DirReadReplyFinished,
    };
    pub use crate::sftpserver::{ReadDataReply, ReadHeaderReply, ReadReplyFinished};

    pub use crate::proto::Extensions;
    pub use crate::sftpserver::ReadStatus;
    pub use crate::sftpserver::SftpOpResult;
    pub use crate::sftpserver::{DirHandle, FileHandle, SftpServer};
    /// Helpers to reduce error prone tasks and hide some details that
    /// add complexity when implementing an [`SftpServer`]
    pub mod helpers {
        pub use crate::sftpserver::helpers::*;
    }
    pub use crate::protocol::SftpSink;
    pub use sunset::sshwire::SSHEncode;

    pub use crate::proto::MAX_REQUEST_LEN;
}

/// SFTP client
///
/// [`SftpClient`](client::SftpClient) drives a SFTP session over a SSH
/// channel that has had the `sftp` subsystem started on it.
pub mod client {
    pub use crate::proto::Extensions;
    pub use crate::sftpclient::{
        DEFAULT_CLIENT_BUF, MAX_DIR_ENTRY_LEN, MAX_READ_LEN, MAX_WRITE_LEN,
        SftpEvent, SftpRunner, pflags,
    };

    #[cfg(feature = "async")]
    pub use crate::sftpclient::{DirEntry, DirIter};
    #[cfg(feature = "async")]
    pub use crate::sftpclient::{PIPELINE_DEPTH, RemoteHandle, SftpClient};
}

/// SFTP Protocol types and structures
pub mod protocol {
    pub use crate::proto::Attrs;
    pub use crate::proto::ExtendedRequest;
    pub use crate::proto::Extensions;
    pub use crate::proto::Filename;
    pub use crate::proto::Name;
    pub use crate::proto::NameEntry;
    pub use crate::proto::OpaqueHandle;
    pub use crate::proto::PFlags;
    pub use crate::proto::PathInfo;
    pub use crate::proto::Rename;
    pub use crate::proto::SftpPacket;
    pub use crate::proto::StatusCode;
    pub use crate::sftpsink::SftpSink;
    /// Constants that might be useful for SFTP developers
    pub mod constants {
        pub use crate::proto::MAX_HANDLE_LEN;
        pub use crate::proto::MAX_NAME_ENTRY_SIZE;
        pub use crate::proto::MAX_PATH_LEN;
        pub use crate::proto::SFTP_FIELD_LEN_LENGTH;
        pub use crate::proto::SFTP_VERSION;
    }
}

/// Errors and results
pub mod error {
    pub use crate::sftperror::SftpError;
    pub use crate::sftperror::SftpResult;
}

// Re-exports
pub use sunset;

#[cfg(feature = "async")]
pub use embedded_io_async;
