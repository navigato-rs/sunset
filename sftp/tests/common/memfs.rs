//! A small in-memory [`SftpServer`] used to exercise the client.

#![allow(dead_code)]

use std::collections::BTreeMap;

use sunset_sftp::embedded_io_async::Write;
use sunset_sftp::error::{SftpError, SftpResult};
use sunset_sftp::protocol::{
    Attrs, Extensions, Filename, NameEntry, PFlags, StatusCode,
};
use sunset_sftp::server::{
    DirHandle, DirReadHeaderReply, DirReadReplyFinished, FileHandle,
    ReadHeaderReply, ReadReplyFinished, SftpOpResult, SftpServer, helpers,
};

/// `S_IFREG`, `S_IFDIR` and `S_IFLNK` with default modes.
const FILE_PERMS: u32 = 0o100644;
const DIR_PERMS: u32 = 0o040755;
const LINK_PERMS: u32 = 0o120777;

#[derive(Debug, Clone)]
enum Node {
    File { data: Vec<u8>, perms: u32 },
    Dir { perms: u32 },
    Link { target: String, perms: u32 },
}

impl Node {
    fn perms(&self) -> u32 {
        match self {
            Node::File { perms, .. }
            | Node::Dir { perms }
            | Node::Link { perms, .. } => *perms,
        }
    }

    fn set_perms(&mut self, p: u32) {
        match self {
            Node::File { perms, .. }
            | Node::Dir { perms }
            | Node::Link { perms, .. } => *perms = p,
        }
    }

    fn size(&self) -> u64 {
        match self {
            Node::File { data, .. } => data.len() as u64,
            Node::Dir { .. } => 0,
            Node::Link { target, .. } => target.len() as u64,
        }
    }

    fn attrs(&self) -> Attrs {
        Attrs {
            size: Some(self.size()),
            permissions: Some(self.perms()),
            ..Default::default()
        }
    }
}

/// Normalises a path to an absolute form without a trailing slash.
fn norm(path: &str) -> String {
    let p = path.trim();
    let p = if p.is_empty() || p == "." { "/" } else { p };
    let mut s = if p.starts_with('/') { p.to_string() } else { format!("/{p}") };
    while s.len() > 1 && s.ends_with('/') {
        s.pop();
    }
    s
}

fn parent_of(path: &str) -> Option<String> {
    let i = path.rfind('/')?;
    Some(if i == 0 { "/".to_string() } else { path[..i].to_string() })
}

fn basename(path: &str) -> &str {
    match path.rfind('/') {
        Some(i) => &path[i + 1..],
        None => path,
    }
}

pub struct MemFs {
    nodes: BTreeMap<String, Node>,
    open_files: BTreeMap<u32, String>,
    /// Path, and whether the listing has been returned already
    open_dirs: BTreeMap<u32, (String, bool)>,
    next_handle: u32,
    /// Storage for the borrowed name in realpath/readlink replies
    scratch: String,
    /// What to announce in SSH_FXP_VERSION
    extensions: Extensions,
}

impl MemFs {
    pub fn new() -> Self {
        Self::with_extensions(Extensions {
            posix_rename: true,
            hardlink: true,
            fsync: true,
            ..Default::default()
        })
    }

    /// A server announcing no extensions at all.
    pub fn without_extensions() -> Self {
        Self::with_extensions(Extensions::default())
    }

    pub fn with_extensions(extensions: Extensions) -> Self {
        let mut nodes = BTreeMap::new();
        nodes.insert("/".to_string(), Node::Dir { perms: DIR_PERMS });
        Self {
            nodes,
            open_files: BTreeMap::new(),
            open_dirs: BTreeMap::new(),
            next_handle: 1,
            scratch: String::new(),
            extensions,
        }
    }

    fn handle(&mut self) -> u32 {
        let h = self.next_handle;
        self.next_handle += 1;
        h
    }

    /// Resolves one level of symlink.
    fn resolve(&self, path: &str) -> String {
        match self.nodes.get(path) {
            Some(Node::Link { target, .. }) => norm(target),
            _ => path.to_string(),
        }
    }

    fn parent_is_dir(&self, path: &str) -> bool {
        parent_of(path)
            .and_then(|p| self.nodes.get(&p).cloned())
            .is_some_and(|n| matches!(n, Node::Dir { .. }))
    }

    fn children(&self, dir: &str) -> Vec<(String, Attrs)> {
        self.nodes
            .iter()
            .filter(|(p, _)| {
                p.as_str() != dir && parent_of(p).as_deref() == Some(dir)
            })
            .map(|(p, n)| (basename(p).to_string(), n.attrs()))
            .collect()
    }
}

impl SftpServer for MemFs {
    async fn open(&mut self, path: &str, mode: &PFlags) -> SftpOpResult<FileHandle> {
        let path = norm(path);
        let flags = u32::from(mode);
        let creat = flags & 0x8 != 0;
        let trunc = flags & 0x10 != 0;
        let excl = flags & 0x20 != 0;

        match self.nodes.get_mut(&path) {
            Some(Node::File { data, .. }) => {
                if excl {
                    return Err(StatusCode::SSH_FX_FAILURE);
                }
                if trunc {
                    data.clear();
                }
            }
            Some(_) => return Err(StatusCode::SSH_FX_FAILURE),
            None => {
                if !creat {
                    return Err(StatusCode::SSH_FX_NO_SUCH_FILE);
                }
                if !self.parent_is_dir(&path) {
                    return Err(StatusCode::SSH_FX_NO_SUCH_FILE);
                }
                self.nodes.insert(
                    path.clone(),
                    Node::File { data: Vec::new(), perms: FILE_PERMS },
                );
            }
        }

        let h = self.handle();
        self.open_files.insert(h, path);
        Ok(FileHandle(h))
    }

    async fn close(&mut self, handle: FileHandle) -> SftpOpResult<()> {
        self.open_files
            .remove(&handle.0)
            .map(|_| ())
            .ok_or(StatusCode::SSH_FX_FAILURE)
    }

    async fn read<W: Write>(
        &mut self,
        handle: FileHandle,
        offset: u64,
        len: u32,
        mut reply: ReadHeaderReply<'_, '_, W>,
    ) -> SftpResult<ReadReplyFinished> {
        let path = self
            .open_files
            .get(&handle.0)
            .cloned()
            .ok_or(SftpError::from(StatusCode::SSH_FX_FAILURE))?;
        let Some(Node::File { data, .. }) = self.nodes.get(&path) else {
            return Err(StatusCode::SSH_FX_NO_SUCH_FILE.into());
        };

        if offset >= data.len() as u64 {
            return reply.send_eof().await;
        }
        let start = offset as usize;
        let end = (start + len as usize).min(data.len());
        let chunk = &data[start..end];

        let data_reply = reply.send_header(chunk.len() as u32).await?;
        data_reply
            .send_data(|mut sender| async move {
                // Sent in pieces, to check the client reassembles them.
                for part in chunk.chunks(64) {
                    sender.send_data(part).await?;
                }
                sender.completed().ok_or(SftpError::from(StatusCode::SSH_FX_FAILURE))
            })
            .await
    }

    async fn write(
        &mut self,
        handle: FileHandle,
        offset: u64,
        buf: &[u8],
    ) -> SftpOpResult<()> {
        let path = self
            .open_files
            .get(&handle.0)
            .cloned()
            .ok_or(StatusCode::SSH_FX_FAILURE)?;
        let Some(Node::File { data, .. }) = self.nodes.get_mut(&path) else {
            return Err(StatusCode::SSH_FX_NO_SUCH_FILE);
        };
        let end = offset as usize + buf.len();
        if data.len() < end {
            data.resize(end, 0);
        }
        data[offset as usize..end].copy_from_slice(buf);
        Ok(())
    }

    async fn opendir(&mut self, dir: &str) -> SftpOpResult<DirHandle> {
        let dir = norm(dir);
        match self.nodes.get(&dir) {
            Some(Node::Dir { .. }) => (),
            Some(_) => return Err(StatusCode::SSH_FX_FAILURE),
            None => return Err(StatusCode::SSH_FX_NO_SUCH_FILE),
        }
        let h = self.handle();
        self.open_dirs.insert(h, (dir, false));
        Ok(DirHandle(h))
    }

    async fn closedir(&mut self, handle: DirHandle) -> SftpOpResult<()> {
        self.open_dirs
            .remove(&handle.0)
            .map(|_| ())
            .ok_or(StatusCode::SSH_FX_FAILURE)
    }

    async fn readdir<W: Write>(
        &mut self,
        handle: DirHandle,
        mut reply: DirReadHeaderReply<'_, '_, W>,
    ) -> SftpOpResult<DirReadReplyFinished> {
        let (dir, done) = self
            .open_dirs
            .get(&handle.0)
            .cloned()
            .ok_or(StatusCode::SSH_FX_FAILURE)?;

        let items = if done { Vec::new() } else { self.children(&dir) };
        if items.is_empty() {
            // Either finished, or an empty directory
            self.open_dirs.insert(handle.0, (dir, true));
            return reply.send_eof().await.map_err(|_| StatusCode::SSH_FX_FAILURE);
        }
        self.open_dirs.insert(handle.0, (dir, true));

        let entries: Vec<NameEntry<'_>> = items
            .iter()
            .map(|(name, attrs)| NameEntry {
                filename: Filename::from(name.as_str()),
                _longname: Filename::from(name.as_str()),
                attrs: *attrs,
            })
            .collect();

        let mut total = 0u32;
        for e in entries.iter() {
            total += helpers::get_name_entry_len(e)
                .map_err(|_| StatusCode::SSH_FX_FAILURE)?;
        }

        reply
            .send_header(total, entries.len() as u32)
            .await
            .map_err(|_| StatusCode::SSH_FX_FAILURE)?
            .send_data(|mut sender| async move {
                for e in entries.iter() {
                    sender.send_item(e).await?;
                }
                sender.completed().ok_or(SftpError::from(StatusCode::SSH_FX_FAILURE))
            })
            .await
            .map_err(|_| StatusCode::SSH_FX_FAILURE)
    }

    async fn realpath(&mut self, dir: &str) -> SftpOpResult<NameEntry<'_>> {
        self.scratch = norm(dir);
        Ok(NameEntry {
            filename: Filename::from(self.scratch.as_str()),
            _longname: Filename::from(""),
            attrs: Attrs::default(),
        })
    }

    async fn readlink(&mut self, file_path: &str) -> SftpOpResult<NameEntry<'_>> {
        let path = norm(file_path);
        let Some(Node::Link { target, .. }) = self.nodes.get(&path) else {
            return Err(StatusCode::SSH_FX_NO_SUCH_FILE);
        };
        self.scratch = target.clone();
        Ok(NameEntry {
            filename: Filename::from(self.scratch.as_str()),
            _longname: Filename::from(""),
            attrs: Attrs::default(),
        })
    }

    async fn symlink(
        &mut self,
        target_path: &str,
        link_path: &str,
    ) -> SftpOpResult<()> {
        let link = norm(link_path);
        if self.nodes.contains_key(&link) {
            return Err(StatusCode::SSH_FX_FAILURE);
        }
        self.nodes.insert(
            link,
            Node::Link { target: target_path.to_string(), perms: LINK_PERMS },
        );
        Ok(())
    }

    async fn attrs(
        &mut self,
        follow_links: bool,
        file_path: &str,
    ) -> SftpOpResult<Attrs> {
        let mut path = norm(file_path);
        if follow_links {
            path = self.resolve(&path);
        }
        self.nodes
            .get(&path)
            .map(|n| n.attrs())
            .ok_or(StatusCode::SSH_FX_NO_SUCH_FILE)
    }

    async fn fattrs(&mut self, handle: FileHandle) -> SftpOpResult<Attrs> {
        let path = self
            .open_files
            .get(&handle.0)
            .cloned()
            .ok_or(StatusCode::SSH_FX_FAILURE)?;
        self.nodes
            .get(&path)
            .map(|n| n.attrs())
            .ok_or(StatusCode::SSH_FX_NO_SUCH_FILE)
    }

    async fn set_attrs(
        &mut self,
        file_path: &str,
        attrs: &Attrs,
    ) -> SftpOpResult<()> {
        let path = norm(file_path);
        let node =
            self.nodes.get_mut(&path).ok_or(StatusCode::SSH_FX_NO_SUCH_FILE)?;
        if let Some(p) = attrs.permissions {
            node.set_perms(p);
        }
        if let (Some(size), Node::File { data, .. }) = (attrs.size, node) {
            data.resize(size as usize, 0);
        }
        Ok(())
    }

    async fn set_fattrs(
        &mut self,
        handle: FileHandle,
        attrs: &Attrs,
    ) -> SftpOpResult<()> {
        let path = self
            .open_files
            .get(&handle.0)
            .cloned()
            .ok_or(StatusCode::SSH_FX_FAILURE)?;
        self.set_attrs(&path, attrs).await
    }

    async fn remove(&mut self, file_path: &str) -> SftpOpResult<()> {
        let path = norm(file_path);
        match self.nodes.get(&path) {
            Some(Node::Dir { .. }) => Err(StatusCode::SSH_FX_FAILURE),
            Some(_) => {
                self.nodes.remove(&path);
                Ok(())
            }
            None => Err(StatusCode::SSH_FX_NO_SUCH_FILE),
        }
    }

    async fn mkdir(&mut self, dir_path: &str, attrs: &Attrs) -> SftpOpResult<()> {
        let path = norm(dir_path);
        if self.nodes.contains_key(&path) {
            return Err(StatusCode::SSH_FX_FAILURE);
        }
        if !self.parent_is_dir(&path) {
            return Err(StatusCode::SSH_FX_NO_SUCH_FILE);
        }
        let perms = attrs.permissions.map_or(DIR_PERMS, |p| p | 0o040000);
        self.nodes.insert(path, Node::Dir { perms });
        Ok(())
    }

    async fn rmdir(&mut self, dir_path: &str) -> SftpOpResult<()> {
        let path = norm(dir_path);
        match self.nodes.get(&path) {
            Some(Node::Dir { .. }) => {
                if !self.children(&path).is_empty() {
                    return Err(StatusCode::SSH_FX_FAILURE);
                }
                self.nodes.remove(&path);
                Ok(())
            }
            Some(_) => Err(StatusCode::SSH_FX_FAILURE),
            None => Err(StatusCode::SSH_FX_NO_SUCH_FILE),
        }
    }

    fn extensions(&self) -> Extensions {
        self.extensions
    }

    async fn posix_rename(
        &mut self,
        old_path: &str,
        new_path: &str,
    ) -> SftpOpResult<()> {
        // Unlike rename(), this replaces the destination
        let old = norm(old_path);
        let new = norm(new_path);
        let node = self.nodes.remove(&old).ok_or(StatusCode::SSH_FX_NO_SUCH_FILE)?;
        self.nodes.insert(new, node);
        Ok(())
    }

    async fn hardlink(
        &mut self,
        old_path: &str,
        new_path: &str,
    ) -> SftpOpResult<()> {
        let old = norm(old_path);
        let new = norm(new_path);
        if self.nodes.contains_key(&new) {
            return Err(StatusCode::SSH_FX_FAILURE);
        }
        // A copy rather than a shared inode, which is enough here
        let node =
            self.nodes.get(&old).cloned().ok_or(StatusCode::SSH_FX_NO_SUCH_FILE)?;
        self.nodes.insert(new, node);
        Ok(())
    }

    async fn fsync(&mut self, handle: FileHandle) -> SftpOpResult<()> {
        // Nothing to flush, but the handle must be one of ours
        self.open_files
            .contains_key(&handle.0)
            .then_some(())
            .ok_or(StatusCode::SSH_FX_FAILURE)
    }

    async fn rename(&mut self, old_path: &str, new_path: &str) -> SftpOpResult<()> {
        let old = norm(old_path);
        let new = norm(new_path);
        if self.nodes.contains_key(&new) {
            // Version 3 rename must not replace the destination
            return Err(StatusCode::SSH_FX_FAILURE);
        }
        let node = self.nodes.remove(&old).ok_or(StatusCode::SSH_FX_NO_SUCH_FILE)?;
        self.nodes.insert(new, node);
        Ok(())
    }
}
