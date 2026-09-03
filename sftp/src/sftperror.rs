use crate::protocol::StatusCode;

use sunset::Error as SunsetError;
use sunset::sshwire::WireError;

use core::convert::From;
use log::warn;

/// Errors that are specific to this SFTP lib
#[derive(Debug)]
pub enum SftpError {
    /// The SFTP server has not been initialised. No SFTP version has been
    /// establish
    NotInitialized,
    /// An `SSH_FXP_INIT` packet was received after the server was already
    /// initialized
    AlreadyInitialized,
    /// A packet could not be decoded as it was malformed
    MalformedPacket,
    /// The server does not have an implementation for the current request.
    /// Some possible causes are:
    ///
    /// - The request has not been handled by an [`crate::sftpserver::SftpServer`]
    /// - Long request which its handling was not implemented
    NotSupported,
    /// The connection has been closed, either by the peer or a transport error.
    Disconnected,
    /// The peer sent a response that doesn't belong to the request that
    /// was made, or a response that isn't valid for that request.
    BadResponse,
    /// A buffer was too small to hold a value from the peer.
    ///
    /// The SFTP session is still usable, the value was discarded.
    NoRoom,
    /// A handle was used for the wrong kind of operation, for example
    /// reading from a directory handle.
    BadHandle,
    /// A previous request was interrupted, so the position in the stream
    /// is unknown.
    ///
    /// This happens when the future of a
    /// [`SftpClient`](crate::client::SftpClient) request is dropped
    /// before completing. The connection must be closed.
    Interrupted,
    /// The [`crate::sftpserver::SftpServer`] failed doing an IO operation
    FileServerError(StatusCode),
    /// A variant containing a [`WireError`]
    WireError(WireError),
    /// A variant containing a [`SunsetError`]
    SunsetError(SunsetError),
}

impl SftpError {
    /// Create a `SftpError` from an `embedded_io_async::Error`
    pub fn from_embedded_io<E: embedded_io_async::Error>(e: E) -> Self {
        SunsetError::EmbeddedIoError { kind: e.kind() }.into()
    }
}

impl From<WireError> for SftpError {
    fn from(value: WireError) -> Self {
        SftpError::WireError(value)
    }
}

impl From<SunsetError> for SftpError {
    fn from(value: SunsetError) -> Self {
        SftpError::SunsetError(value)
    }
}

impl From<StatusCode> for SftpError {
    fn from(value: StatusCode) -> Self {
        SftpError::FileServerError(value)
    }
}

// impl From<FileServerError> for SftpError {
//     fn from(value: FileServerError) -> Self {
//         SftpError::FileServerError(value)
//     }
// }

impl From<SftpError> for WireError {
    fn from(value: SftpError) -> Self {
        match value {
            SftpError::WireError(wire_error) => wire_error,
            _ => WireError::PacketWrong,
        }
    }
}

impl From<SftpError> for SunsetError {
    fn from(value: SftpError) -> Self {
        match value {
            SftpError::SunsetError(error) => error,
            SftpError::WireError(wire_error) => wire_error.into(),
            SftpError::NotInitialized
            | SftpError::NotSupported
            | SftpError::AlreadyInitialized
            | SftpError::MalformedPacket
            | SftpError::BadResponse
            | SftpError::NoRoom
            | SftpError::BadHandle
            | SftpError::Interrupted
            | SftpError::FileServerError(_) => {
                warn!("Casting error loosing information: {:?}", value);
                sunset::error::PacketWrong.build()
            }
            SftpError::Disconnected => SunsetError::ChannelEOF,
        }
    }
}

impl core::fmt::Display for SftpError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SftpError::NotInitialized => f.write_str("SFTP is not initialized"),
            SftpError::AlreadyInitialized => {
                f.write_str("SFTP is already initialized")
            }
            SftpError::MalformedPacket => f.write_str("malformed SFTP packet"),
            SftpError::NotSupported => f.write_str("not supported"),
            SftpError::Disconnected => f.write_str("disconnected"),
            SftpError::BadResponse => f.write_str("unexpected SFTP response"),
            SftpError::NoRoom => f.write_str("buffer too small"),
            SftpError::BadHandle => f.write_str("wrong kind of handle"),
            SftpError::Interrupted => {
                f.write_str("SFTP was interrupted, the session can't continue")
            }
            SftpError::FileServerError(code) => write!(f, "{code}"),
            SftpError::WireError(e) => write!(f, "encoding error: {e:?}"),
            SftpError::SunsetError(e) => write!(f, "{e}"),
        }
    }
}

impl core::error::Error for SftpError {}

/// result specific to this SFTP lib
pub type SftpResult<T> = Result<T, SftpError>;
