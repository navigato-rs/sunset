//! SFTP (SSH File Transfer Protocol) implementation for [`sunset`].
//!
//! Implements SFTP v3 as defined in [draft-ietf-secsh-filexfer-02](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02).
//!
//! **Work in Progress**: please see the roadmap and use this crate carefully.
//!
//! Both sides are `no_std` and allocation free. While designed for use
//! with Sunset SSH, they should be usable with any transport that
//! implements the `embedded_io_async` `Read`/`Write` traits.
//!
//! # Server
//!
//! [`SftpServerHandler`] dispatches SFTP packets to a struct implementing
//! the [`SftpServer`](server::SftpServer) trait, which the application
//! provides to describe its filesystem.
//!
//! See example usage in the `../demo/sftp/std` directory.
//!
//! # Client
//!
//! [`SftpClient`](client::SftpClient) makes requests over a SSH channel
//! that has had the `sftp` subsystem started on it. With `sunset-async`
//! that is a client session channel opened with
//! `SSHClient::open_session_nopty()`, with
//! `SessionCommand::Subsystem("sftp")` requested on it.
//!
//! ```
//! use sunset_sftp::client::SftpClient;
//! use sunset_sftp::embedded_io_async::{Read, Write};
//! use sunset_sftp::error::SftpResult;
//!
//! // chan_in and chan_out are the two halves of the SFTP channel.
//! async fn upload(
//!     chan_in: impl Read,
//!     chan_out: impl Write,
//!     data: &[u8],
//! ) -> SftpResult<()> {
//!     let mut client = SftpClient::new_default_buffer(chan_in, chan_out);
//!     client.init().await?;
//!
//!     let f = client.create("/tmp/hello").await?;
//!     for (i, chunk) in data.chunks(4096).enumerate() {
//!         client.write(&f, (i * 4096) as u64, chunk).await?;
//!     }
//!     client.close(&f).await
//! }
//! ```
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

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![no_std]
// Nested if statements are often more logical,
// or allow for future additions.
#![allow(clippy::collapsible_if)]

mod proto;
mod sftpclient;
mod sftperror;
mod sftphandler;
mod sftpserver;
mod sftpsink;
mod sftpsource;

// Main calling point for the library provided that the user implements
// a [`server::SftpServer`].
//
// Please see basic usage at `../demo/sftp/std`
pub use sftphandler::SftpServerHandler;

/// Structures and types used to add the details for the target system
///
/// Related to the implementation of the [`server::SftpServer`], which
/// is meant to be instantiated by the user and passed to [`SftpServerHandler`]
/// and has the task of executing client requests in the underlying system
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
    pub use crate::sftpsink::SftpSink;
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
        DEFAULT_CLIENT_BUF, MAX_READ_LEN, MAX_WRITE_LEN, PIPELINE_DEPTH,
        RemoteHandle, SftpClient, pflags,
    };
    pub use crate::sftpclient::{DirEntry, DirIter};
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
    pub use crate::proto::SftpPacket;
    pub use crate::proto::StatusCode;
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
pub use embedded_io_async;
pub use sunset;
