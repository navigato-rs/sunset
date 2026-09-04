mod runner;

#[cfg(feature = "async")]
mod dir;
#[cfg(feature = "async")]
#[allow(clippy::module_inception)]
mod sftpclient;

pub use runner::{
    DEFAULT_CLIENT_BUF, MAX_DIR_ENTRY_LEN, MAX_READ_LEN, MAX_WRITE_LEN, SftpEvent,
    SftpRunner, pflags,
};

#[cfg(feature = "async")]
pub use dir::{DirEntry, DirIter};
#[cfg(feature = "async")]
pub use sftpclient::{PIPELINE_DEPTH, RemoteHandle, SftpClient};
