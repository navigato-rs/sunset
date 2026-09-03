//! Streaming reads of SFTP packets.
//!
//! SFTP responses can be much larger than the buffers Sunset is willing
//! to allocate (file data, or a directory listing), so responses are
//! decoded a field at a time straight off the stream rather than being
//! read into a single buffer first.
//!
//! Every function takes the number of bytes remaining in the packet
//! currently being read, and keeps it up to date. The caller stores
//! that count so that a partially read packet can be drained later.

use embedded_io_async::{Read, ReadExactError};

use crate::error::{SftpError, SftpResult};
use crate::proto::{Attrs, AttrsFlags};

#[allow(unused_imports)]
use log::{debug, error, info, log, trace, warn};

/// Scratch size used when discarding unwanted packet content.
const SKIP_CHUNK: usize = 64;

/// Reads exactly `buf.len()` bytes, without any packet accounting.
pub(crate) async fn read_exact<R: Read>(
    r: &mut R,
    buf: &mut [u8],
) -> SftpResult<()> {
    r.read_exact(buf).await.map_err(|e| match e {
        ReadExactError::UnexpectedEof => SftpError::Disconnected,
        ReadExactError::Other(e) => SftpError::from_embedded_io(e),
    })
}

/// Reads `buf.len()` bytes of packet content.
pub(crate) async fn take<R: Read>(
    r: &mut R,
    rem: &mut usize,
    buf: &mut [u8],
) -> SftpResult<()> {
    if buf.len() > *rem {
        debug!("Packet short by {} bytes", buf.len() - *rem);
        return Err(SftpError::MalformedPacket);
    }
    read_exact(r, buf).await?;
    *rem -= buf.len();
    Ok(())
}

pub(crate) async fn take_u8<R: Read>(r: &mut R, rem: &mut usize) -> SftpResult<u8> {
    let mut b = [0u8; 1];
    take(r, rem, &mut b).await?;
    Ok(b[0])
}

pub(crate) async fn take_u32<R: Read>(
    r: &mut R,
    rem: &mut usize,
) -> SftpResult<u32> {
    let mut b = [0u8; 4];
    take(r, rem, &mut b).await?;
    Ok(u32::from_be_bytes(b))
}

pub(crate) async fn take_u64<R: Read>(
    r: &mut R,
    rem: &mut usize,
) -> SftpResult<u64> {
    let mut b = [0u8; 8];
    take(r, rem, &mut b).await?;
    Ok(u64::from_be_bytes(b))
}

/// Discards `len` bytes of packet content.
pub(crate) async fn skip<R: Read>(
    r: &mut R,
    rem: &mut usize,
    mut len: usize,
) -> SftpResult<()> {
    let mut scratch = [0u8; SKIP_CHUNK];
    while len > 0 {
        let l = len.min(SKIP_CHUNK);
        take(r, rem, &mut scratch[..l]).await?;
        len -= l;
    }
    Ok(())
}

/// Discards the remainder of the current packet.
pub(crate) async fn drain<R: Read>(r: &mut R, rem: &mut usize) -> SftpResult<()> {
    let l = *rem;
    if l > 0 {
        trace!("Draining {} bytes", l);
    }
    skip(r, rem, l).await
}

/// Reads a `u32` length prefixed string into `buf`.
///
/// Returns `None` if the string doesn't fit in `buf`, in which case the
/// string is skipped over so that the rest of the packet can still be
/// decoded.
pub(crate) async fn try_take_string<'b, R: Read>(
    r: &mut R,
    rem: &mut usize,
    buf: &'b mut [u8],
) -> SftpResult<Option<&'b [u8]>> {
    let len = take_u32(r, rem).await? as usize;
    if len > buf.len() {
        debug!("String of {} bytes doesn't fit in {}", len, buf.len());
        skip(r, rem, len).await?;
        return Ok(None);
    }
    let buf = &mut buf[..len];
    take(r, rem, buf).await?;
    Ok(Some(buf))
}

/// Reads a `u32` length prefixed string into `buf`.
///
/// Fails with [`SftpError::NoRoom`] if the string doesn't fit, having
/// skipped over the string so that the rest of the packet is still usable.
pub(crate) async fn take_string<'b, R: Read>(
    r: &mut R,
    rem: &mut usize,
    buf: &'b mut [u8],
) -> SftpResult<&'b [u8]> {
    try_take_string(r, rem, buf).await?.ok_or(SftpError::NoRoom)
}

/// Discards a `u32` length prefixed string.
pub(crate) async fn skip_string<R: Read>(
    r: &mut R,
    rem: &mut usize,
) -> SftpResult<()> {
    let len = take_u32(r, rem).await? as usize;
    skip(r, rem, len).await
}

/// Reads a [`Attrs`] structure.
///
/// Unlike the `SSHDecode` implementation this consumes any extended
/// attributes, leaving the stream positioned at the end of the
/// attributes. The extended attributes themselves are discarded.
pub(crate) async fn take_attrs<R: Read>(
    r: &mut R,
    rem: &mut usize,
) -> SftpResult<Attrs> {
    let flags = take_u32(r, rem).await?;
    let mut attrs = Attrs::default();

    if flags & AttrsFlags::SSH_FILEXFER_ATTR_SIZE != 0 {
        attrs.size = Some(take_u64(r, rem).await?);
    }
    if flags & AttrsFlags::SSH_FILEXFER_ATTR_UIDGID != 0 {
        attrs.uid = Some(take_u32(r, rem).await?);
        attrs.gid = Some(take_u32(r, rem).await?);
    }
    if flags & AttrsFlags::SSH_FILEXFER_ATTR_PERMISSIONS != 0 {
        attrs.permissions = Some(take_u32(r, rem).await?);
    }
    if flags & AttrsFlags::SSH_FILEXFER_ATTR_ACMODTIME != 0 {
        attrs.atime = Some(take_u32(r, rem).await?);
        attrs.mtime = Some(take_u32(r, rem).await?);
    }
    if flags & AttrsFlags::SSH_FILEXFER_ATTR_EXTENDED != 0 {
        // Extended attributes are skipped, but must be consumed to stay
        // in sync with the stream. A bogus count runs out of packet
        // quickly, `take()` limits it.
        let count = take_u32(r, rem).await?;
        trace!("Skipping {} extended attributes", count);
        for _ in 0..count {
            skip_string(r, rem).await?;
            skip_string(r, rem).await?;
        }
    }

    Ok(attrs)
}
