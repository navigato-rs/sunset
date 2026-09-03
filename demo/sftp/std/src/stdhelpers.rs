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
    server::{DirReadDataReply, DirReadReplyFinished, SftpOpResult, SftpSink},
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
    longname: String,
    attrs: Attrs,
}

impl Entry {
    fn name_entry(&self) -> NameEntry<'_> {
        NameEntry {
            filename: Filename::from(self.filename.as_str()),
            _longname: Filename::from(self.longname.as_str()),
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
                let longname = metadata
                    .as_ref()
                    .map(|m| long_name(&filename, m))
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
        if self.entries.is_empty() {
            return Err(StatusCode::SSH_FX_EOF);
        }

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

/// Formats an `ls -l` style line for a `SSH_FXP_NAME` long name.
///
/// SFTP version 3 leaves the format undefined and says clients should
/// not parse it, but OpenSSH's `sftp` displays it verbatim for `ls -l`.
/// A server that sends an empty long name gives blank lines there.
fn long_name(filename: &str, metadata: &Metadata) -> String {
    let mode = metadata.permissions().mode();

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

    let mut perms = String::with_capacity(9);
    for shift in [6, 3, 0] {
        let bits = (mode >> shift) & 0o7;
        perms.push(if bits & 0o4 != 0 { 'r' } else { '-' });
        perms.push(if bits & 0o2 != 0 { 'w' } else { '-' });
        perms.push(if bits & 0o1 != 0 { 'x' } else { '-' });
    }

    format!(
        "{}{} {:>3} {:<8} {:<8} {:>8} {} {}",
        kind,
        perms,
        metadata.st_nlink(),
        metadata.st_uid(),
        metadata.st_gid(),
        metadata.len(),
        format_time(metadata.st_mtime()),
        filename,
    )
}

/// Formats a unix timestamp as `ls -l` does, in UTC.
fn format_time(secs: i64) -> String {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov",
        "Dec",
    ];

    let days = secs.div_euclid(86400);
    let time_of_day = secs.rem_euclid(86400);

    // Days to a civil date, from Howard Hinnant's chrono algorithms
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let _year = yoe + era * 400 + i64::from(month <= 2);

    format!(
        "{} {:>2} {:02}:{:02}",
        MONTHS[(month - 1) as usize],
        day,
        time_of_day / 3600,
        (time_of_day % 3600) / 60,
    )
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
