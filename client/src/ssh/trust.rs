//! A deliberately small, fail-closed subset of OpenSSH known_hosts.
//!
//! Exact hosts (including comma lists), port-qualified names, and hashed hosts
//! are supported. Markers and wildcard policies are rejected, never ignored.

use std::{fs, io, path};

use super::{Error, Kind, StrictHostKeyChecking};
use base64::Engine as _;
use hmac::{KeyInit as _, Mac as _};

const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_KEY_BYTES: usize = 16 * 1024;

pub(super) struct Store {
    entries: Vec<Entry>,
}

struct Entry {
    hosts: Hosts,
    key: Vec<u8>,
}

enum Hosts {
    Exact(Vec<String>),
    Hashed { salt: Vec<u8>, hash: Vec<u8> },
}

enum Status {
    Match(String),
    Unknown(String),
    Changed(String),
}

impl Store {
    pub fn load(path: &path::Path) -> Result<Self, Error> {
        let file = match fs::File::open(path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(Self { entries: Vec::new() });
            }
            other => other.map_err(configuration)?,
        };
        let mut data = Vec::new();
        io::Read::read_to_end(
            &mut io::Read::take(file, MAX_FILE_BYTES + 1),
            &mut data,
        )
        .map_err(configuration)?;
        if data.len() as u64 > MAX_FILE_BYTES {
            return Err(configuration("known-hosts file exceeds 4 MiB"));
        }
        Self::parse(std::str::from_utf8(&data).map_err(configuration)?)
    }

    fn parse(text: &str) -> Result<Self, Error> {
        let mut entries = Vec::new();
        for (index, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let parsed = (|| {
                let mut fields = line.split_whitespace();
                let names = fields.next().unwrap_or("");
                if names.starts_with('@') || names.contains(['*', '?', '!']) {
                    return Err(configuration(
                        "unsupported markers/patterns; refusing to ignore trust policy",
                    ));
                }
                let algorithm = fields
                    .next()
                    .ok_or_else(|| configuration("missing key algorithm"))?;
                let encoded = fields
                    .next()
                    .ok_or_else(|| configuration("missing public key"))?;
                if encoded.len() > MAX_KEY_BYTES * 2 {
                    return Err(configuration("public key exceeds budget"));
                }
                let key = base64::engine::general_purpose::STANDARD
                    .decode(encoded)
                    .map_err(configuration)?;
                if key.len() > MAX_KEY_BYTES {
                    return Err(configuration("public key exceeds budget"));
                }
                let parsed =
                    ssh_key::PublicKey::from_bytes(&key).map_err(configuration)?;
                if parsed.algorithm().as_str() != algorithm {
                    return Err(configuration(
                        "key algorithm does not match its encoded key",
                    ));
                }
                let hosts = if names.starts_with('|') {
                    let parts: Vec<_> = names.split('|').collect();
                    if parts.len() != 4 || parts[1] != "1" {
                        return Err(configuration("unsupported hashed-host format"));
                    }
                    let salt = base64::engine::general_purpose::STANDARD
                        .decode(parts[2])
                        .map_err(configuration)?;
                    let hash = base64::engine::general_purpose::STANDARD
                        .decode(parts[3])
                        .map_err(configuration)?;
                    if salt.len() != 20 || hash.len() != 20 {
                        return Err(configuration("invalid hashed-host length"));
                    }
                    Hosts::Hashed { salt, hash }
                } else {
                    let names: Vec<_> =
                        names.split(',').map(str::to_owned).collect();
                    if names.iter().any(|name| name.is_empty() || name.contains('|'))
                    {
                        return Err(configuration("invalid exact host list"));
                    }
                    Hosts::Exact(names)
                };
                Ok(Entry { hosts, key })
            })();
            entries.push(parsed.map_err(|error: Error| {
                configuration(format!(
                    "known-hosts line {}: {}",
                    index + 1,
                    error.detail
                ))
            })?);
        }
        Ok(Self { entries })
    }

    #[cfg(test)]
    pub fn verify(
        &self,
        host: &str,
        port: u16,
        key: &[u8],
    ) -> Result<String, Error> {
        match self.status(host, port, key)? {
            Status::Match(fingerprint) => Ok(fingerprint),
            Status::Unknown(fingerprint) => {
                Err(untrusted(Kind::UnknownHostKey, fingerprint))
            }
            Status::Changed(fingerprint) => {
                Err(untrusted(Kind::ChangedHostKey, fingerprint))
            }
        }
    }

    /// Apply `StrictHostKeyChecking`. Unknown keys may be appended; a changed
    /// key is accepted only for `no`.
    pub fn verify_with(
        &mut self,
        host: &str,
        port: u16,
        key: &[u8],
        checking: StrictHostKeyChecking,
        known_hosts: &path::Path,
    ) -> Result<String, Error> {
        match self.status(host, port, key)? {
            Status::Match(fingerprint) => Ok(fingerprint),
            Status::Unknown(fingerprint) if checking.records_unknown() => {
                self.record(known_hosts, host, port, key)?;
                Ok(fingerprint)
            }
            Status::Unknown(fingerprint) => {
                Err(untrusted(Kind::UnknownHostKey, fingerprint))
            }
            Status::Changed(fingerprint) if checking.allows_changed() => {
                Ok(fingerprint)
            }
            Status::Changed(fingerprint) => {
                Err(untrusted(Kind::ChangedHostKey, fingerprint))
            }
        }
    }

    fn status(&self, host: &str, port: u16, key: &[u8]) -> Result<Status, Error> {
        let public = ssh_key::PublicKey::from_bytes(key)
            .map_err(|_| Error::new(Kind::Transport, "invalid server public key"))?;
        let fingerprint = public.fingerprint(ssh_key::HashAlg::Sha256).to_string();
        // OpenSSH lowercases the host before matching known_hosts, and hashes the
        // lowercased name. Matching case-sensitively would reject a trusted entry
        // as unknown, which reads as a changed-key warning to the user.
        let lookup = lookup_name(host, port);
        let mut found_host = false;
        for entry in &self.entries {
            let matches = match entry.hosts {
                Hosts::Exact(ref names) => {
                    names.iter().any(|name| name.eq_ignore_ascii_case(&lookup))
                }
                Hosts::Hashed { ref salt, ref hash } => {
                    let mut mac = hmac::Hmac::<sha1::Sha1>::new_from_slice(salt)
                        .map_err(configuration)?;
                    mac.update(lookup.as_bytes());
                    mac.verify_slice(hash).is_ok()
                }
            };
            if matches {
                found_host = true;
                if entry.key == key {
                    return Ok(Status::Match(fingerprint));
                }
            }
        }
        Ok(if found_host {
            Status::Changed(fingerprint)
        } else {
            Status::Unknown(fingerprint)
        })
    }

    fn record(
        &mut self,
        path: &path::Path,
        host: &str,
        port: u16,
        key: &[u8],
    ) -> Result<(), Error> {
        let public = ssh_key::PublicKey::from_bytes(key)
            .map_err(|_| Error::new(Kind::Transport, "invalid server public key"))?;
        let lookup = lookup_name(host, port);
        let line = format!(
            "{lookup} {} {}\n",
            public.algorithm().as_str(),
            base64::engine::general_purpose::STANDARD.encode(key)
        );
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(configuration)?;
        io::Write::write_all(&mut file, line.as_bytes()).map_err(configuration)?;
        file.sync_all().map_err(configuration)?;
        self.entries
            .push(Entry { hosts: Hosts::Exact(vec![lookup]), key: key.to_vec() });
        Ok(())
    }
}

fn lookup_name(host: &str, port: u16) -> String {
    let host = host.to_ascii_lowercase();
    if port == 22 { host } else { format!("[{host}]:{port}") }
}

fn untrusted(kind: Kind, fingerprint: String) -> Error {
    Error::new(
        kind,
        format!(
            "host key is not trusted; refusing authentication; presented {fingerprint}"
        ),
    )
}

fn configuration(detail: impl std::fmt::Display) -> Error {
    Error::new(Kind::Configuration, detail)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(fill: u8) -> Vec<u8> {
        let mut key = b"\0\0\0\x0bssh-ed25519\0\0\0\x20".to_vec();
        key.extend_from_slice(&[fill; 32]);
        key
    }

    fn line(host: &str, key: &[u8]) -> String {
        format!(
            "{host} ssh-ed25519 {}\n",
            base64::engine::general_purpose::STANDARD.encode(key)
        )
    }

    struct TempDir(path::PathBuf);
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn temp_dir(prefix: &str) -> TempDir {
        let root = std::env::temp_dir().join(format!(
            "{prefix}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&root).unwrap();
        TempDir(root)
    }

    #[test]
    fn exact_hosts_and_ports_do_not_fall_back() {
        let key = key(7);
        let store =
            Store::parse(&line("[example.test]:2222,[alias.test]:2222", &key))
                .unwrap();
        assert!(store.verify("example.test", 2222, &key).is_ok());
        assert!(store.verify("alias.test", 2222, &key).is_ok());
        for (host, port) in
            [("example.test", 22), ("example.test", 2223), ("other.test", 2222)]
        {
            assert_eq!(
                store.verify(host, port, &key).unwrap_err().kind,
                Kind::UnknownHostKey
            );
        }
        assert_eq!(
            store.verify("example.test", 2222, &self::key(8)).unwrap_err().kind,
            Kind::ChangedHostKey
        );
        let bare = Store::parse(&line("example.test", &key)).unwrap();
        assert_eq!(
            bare.verify("example.test", 2222, &key).unwrap_err().kind,
            Kind::UnknownHostKey
        );
    }

    #[test]
    fn host_names_match_without_regard_to_case() {
        let key = key(11);
        let store = Store::parse(&line("Build.Example.Test", &key)).unwrap();
        assert!(store.verify("build.example.test", 22, &key).is_ok());
        assert!(store.verify("BUILD.example.TEST", 22, &key).is_ok());
        let salt = [23; 20];
        let mut mac = hmac::Hmac::<sha1::Sha1>::new_from_slice(&salt).unwrap();
        mac.update(b"[build.example.test]:2222");
        let names = format!(
            "|1|{}|{}",
            base64::engine::general_purpose::STANDARD.encode(salt),
            base64::engine::general_purpose::STANDARD
                .encode(mac.finalize().into_bytes())
        );
        let hashed = Store::parse(&line(&names, &key)).unwrap();
        assert!(hashed.verify("Build.Example.Test", 2222, &key).is_ok());
        // Case folding must not weaken which key is accepted for that host.
        assert_eq!(
            store.verify("BUILD.example.TEST", 22, &self::key(12)).unwrap_err().kind,
            Kind::ChangedHostKey
        );
    }

    #[test]
    fn hashed_hosts_use_exact_port_identity() {
        let key = key(9);
        let salt = [17; 20];
        let mut mac = hmac::Hmac::<sha1::Sha1>::new_from_slice(&salt).unwrap();
        mac.update(b"[example.test]:2222");
        let names = format!(
            "|1|{}|{}",
            base64::engine::general_purpose::STANDARD.encode(salt),
            base64::engine::general_purpose::STANDARD
                .encode(mac.finalize().into_bytes())
        );
        let store = Store::parse(&line(&names, &key)).unwrap();
        assert!(store.verify("example.test", 2222, &key).is_ok());
        assert_eq!(
            store.verify("example.test", 22, &key).unwrap_err().kind,
            Kind::UnknownHostKey
        );
    }

    #[test]
    fn malformed_and_unsupported_trust_rows_fail_closed() {
        for text in [
            "@revoked host ssh-ed25519 AAAA",
            "@cert-authority host key",
            "*.test key",
            "!bad,good key",
            "host",
            "host ssh-ed25519 invalid",
            "|2|salt|hash ssh-ed25519 AAAA",
        ] {
            assert_eq!(Store::parse(text).err().unwrap().kind, Kind::Configuration);
        }
        assert!(Store::parse("# comment\n\n").is_ok());
        let text = line("host", &key(1)).replace("ssh-ed25519 ", "ssh-rsa ");
        assert!(Store::parse(&text).is_err());
    }

    #[test]
    fn missing_known_hosts_is_unknown_not_a_configuration_fault() {
        let missing = std::env::temp_dir().join(format!(
            "sunset-missing-hosts-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let store = Store::load(&missing).unwrap();
        assert_eq!(
            store.verify("example.test", 22, &key(1)).unwrap_err().kind,
            Kind::UnknownHostKey
        );
    }

    #[test]
    fn accept_new_records_unknown_keys_and_still_refuses_changed_keys() {
        let root = temp_dir("sunset-accept-new");
        let path = root.0.join("known_hosts");
        let presented = key(3);
        let mut store = Store::load(&path).unwrap();
        assert!(
            store
                .verify_with(
                    "example.test",
                    22,
                    &presented,
                    StrictHostKeyChecking::AcceptNew,
                    &path,
                )
                .is_ok()
        );
        let recorded = fs::read_to_string(&path).unwrap();
        assert!(recorded.contains("example.test ssh-ed25519 "));
        let mut store = Store::load(&path).unwrap();
        assert!(store.verify("example.test", 22, &presented).is_ok());
        assert_eq!(
            store
                .verify_with(
                    "example.test",
                    22,
                    &key(4),
                    StrictHostKeyChecking::AcceptNew,
                    &path,
                )
                .unwrap_err()
                .kind,
            Kind::ChangedHostKey
        );
        assert_eq!(fs::read_to_string(&path).unwrap(), recorded);
    }

    #[test]
    fn ask_refuses_unknown_keys_without_writing() {
        let root = temp_dir("sunset-ask-hosts");
        let path = root.0.join("known_hosts");
        let presented = key(7);
        for checking in [StrictHostKeyChecking::Yes, StrictHostKeyChecking::Ask] {
            let mut store = Store::load(&path).unwrap();
            assert_eq!(
                store
                    .verify_with("example.test", 22, &presented, checking, &path)
                    .unwrap_err()
                    .kind,
                Kind::UnknownHostKey
            );
        }
        assert!(!path.exists());
    }

    #[test]
    fn no_accepts_a_changed_key_without_rewriting_known_hosts() {
        let presented = key(5);
        let mut store = Store::parse(&line("example.test", &key(6))).unwrap();
        let path = path::Path::new("/no-such-sunset-known-hosts");
        assert!(
            store
                .verify_with(
                    "example.test",
                    22,
                    &presented,
                    StrictHostKeyChecking::No,
                    path,
                )
                .is_ok()
        );
        assert_eq!(
            store
                .verify_with(
                    "example.test",
                    22,
                    &presented,
                    StrictHostKeyChecking::Yes,
                    path,
                )
                .unwrap_err()
                .kind,
            Kind::ChangedHostKey
        );
    }
}
