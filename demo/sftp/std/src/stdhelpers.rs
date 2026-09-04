use embedded_io_async::Write;
use sunset_sftp::embedded_io_async;
/// Helpers structures intended to for environment with `std` available, specially linux.
///
/// The collection helps with directory and directory items enumeration, description
/// and organizing. Providing means to translate them into [`sunset-sftp`] structures
///
use sunset_sftp::{
    error::SftpError,
    protocol::{Attrs, Filename, NameEntry, StatusCode},
    server::{
        DirReadDataReply, DirReadReplyFinished, SftpOpResult, SftpSink, helpers,
        helpers::LONG_NAME_PREFIX_LEN,
    },
};

use sunset::sshwire::SSHEncode;

use log::{debug, error, info};
use std::{
    fs::{Metadata, ReadDir},
    os::{linux::fs::MetadataExt, unix::fs::PermissionsExt},
    time::SystemTime,
};

/// This is a helper structure to make ReadDir into something manageable for
/// [`DirReply`]
#[derive(Debug)]
pub struct DirEntriesCollection {
    /// Computed length of all the encoded elements
    encoded_length: u32,
    /// Entries, already translated to what goes on the wire
    entries: Vec<Entry>,
}

/// One directory entry, as it will be sent.
///
/// The names are kept rather than the `std` [`DirEntry`], so that the
/// length announced in the `SSH_FXP_NAME` header is computed from
/// exactly what is sent afterwards.
#[derive(Debug)]
struct Entry {
    filename: String,
    /// Not required to be UTF-8, so kept as bytes
    longname: Vec<u8>,
    attrs: Attrs,
}

impl Entry {
    fn name_entry(&self) -> NameEntry<'_> {
        NameEntry {
            filename: Filename::from(self.filename.as_str()),
            _longname: Filename::new(&self.longname),
            attrs: self.attrs,
        }
    }
}

impl DirEntriesCollection {
    /// Creates this DirEntriesCollection so linux std users do not need to
    /// translate `std` directory elements into Sftp structures before sending a response
    /// back to the client
    ///
    /// `max_entry_len` is the response buffer size of the
    /// `SftpServerHandler` these will be sent with. Entries that would
    /// not fit are skipped, since a failure partway through a response
    /// can't be recovered from.
    pub fn new(dir_iterator: ReadDir, max_entry_len: usize) -> SftpOpResult<Self> {
        let mut encoded_length: u32 = 0;
        let mut buffer = vec![0u8; max_entry_len];

        let entries: Vec<Entry> = dir_iterator
            .filter_map(|entry_result| {
                let entry = entry_result.ok()?;
                let filename = entry.file_name().to_string_lossy().into_owned();
                let metadata = entry.metadata().ok();
                let attrs = metadata
                    .as_ref()
                    .map(|m| get_file_attrs(m.clone()))
                    .unwrap_or_default();
                // An "ls -l" style line, which clients display
                let mut lbuf = vec![0u8; LONG_NAME_PREFIX_LEN + filename.len()];
                let longname =
                    helpers::write_long_name(&mut lbuf, filename.as_bytes(), &attrs)
                        .map(|l| l.to_vec())
                        .unwrap_or_default();

                let e = Entry { filename, longname, attrs };

                let mut sftp_sink = SftpSink::new(&mut buffer);
                if e.name_entry().enc(&mut sftp_sink).is_err() {
                    error!("Skipping over-long entry {:?}", e.filename);
                    return None;
                }
                encoded_length =
                    encoded_length.checked_add(sftp_sink.payload_len() as u32)?;
                Some(e)
            })
            .collect();

        let count =
            u32::try_from(entries.len()).map_err(|_| StatusCode::SSH_FX_FAILURE)?;

        info!(
            "Processed {} entries, estimated serialized length: {}",
            count, encoded_length
        );

        Ok(Self { encoded_length, entries })
    }

    pub(crate) fn encoded_length(&self) -> u32 {
        self.encoded_length
    }

    pub(crate) fn count(&self) -> u32 {
        // OK cast, checked in new()
        self.entries.len() as u32
    }

    pub(crate) async fn send_entries<W>(
        &self,
        data_reply: DirReadDataReply<'_, '_, W>,
    ) -> SftpOpResult<DirReadReplyFinished>
    where
        W: Write,
    {
        // Nothing may fail from here on: the header announcing these
        // entries has already been sent, so an error would put a second
        // reply on the wire for the same request.

        let Ok(token) = data_reply
            .send_data(|mut limited_dir_sender| async move {
                for entry in &self.entries {
                    let name_entry = entry.name_entry();
                    debug!("Sending new item: {:?}", name_entry);

                    limited_dir_sender.send_item(&name_entry).await?;
                }
                match limited_dir_sender.completed() {
                    Some(completed_token) => Ok(completed_token),
                    None => {
                        Err(SftpError::FileServerError(StatusCode::SSH_FX_FAILURE))
                    }
                }
            })
            .await
        else {
            error!("Failed to send directory entries");
            return Err(StatusCode::SSH_FX_FAILURE);
        };
        Ok(token)
    }
}

/// [`std`] helper function to get [`Attrs`] from a [`Metadata`].
pub fn get_file_attrs(metadata: Metadata) -> Attrs {
    let time_to_u32 = |time_result: std::io::Result<SystemTime>| {
        time_result
            .ok()?
            .duration_since(SystemTime::UNIX_EPOCH)
            .ok()?
            .as_secs()
            .try_into()
            .ok()
    };

    Attrs {
        size: Some(metadata.len()),
        uid: Some(metadata.st_uid()),
        gid: Some(metadata.st_gid()),
        permissions: Some(metadata.permissions().mode()),
        atime: time_to_u32(metadata.accessed()),
        mtime: time_to_u32(metadata.modified()),
        ext_count: None,
    }
}
