//! A SSH agent client over a Unix socket.
//!
//! The protocol itself is in [`sunset::agent`], which does no IO. This
//! is only the socket around it, so a different transport — a Windows
//! named pipe, say — is a matter of replacing the three calls below.

#[allow(unused_imports)]
use {
    log::{debug, error, info, log, trace, warn},
    sunset::{Error, Result},
};

use std::path::Path;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

use sunset::agent::{self, AgentResponse};
use sunset::{AuthSigMsg, OwnedSig, SignKey};

/// Enough for a request that carries no key or message.
const SMALL_REQUEST: usize = 64;

/// A SSH Agent client
pub struct AgentClient {
    conn: UnixStream,
    buf: Vec<u8>,
}

impl AgentClient {
    /// Create a new client
    ///
    /// `path` is a Unix socket to a ssh-agent, such as that from `$SSH_AUTH_SOCK`.
    pub async fn new(path: impl AsRef<Path>) -> Result<Self, std::io::Error> {
        let conn = UnixStream::connect(path).await?;
        Ok(Self { conn, buf: vec![] })
    }

    /// Sends the first `len` bytes of the buffer, and reads the reply
    /// back into it.
    async fn request(&mut self, len: usize) -> Result<()> {
        self.conn.write_all(&self.buf[..len]).await?;

        let mut frame = [0u8; 4];
        self.conn.read_exact(&mut frame).await?;
        let l = agent::response_len(&frame)?;
        self.buf.resize(l, 0);
        self.conn.read_exact(&mut self.buf).await?;
        Ok(())
    }

    pub async fn keys(&mut self) -> Result<Vec<SignKey>> {
        self.buf.resize(SMALL_REQUEST, 0);
        let n = agent::encode_request_identities(&mut self.buf)?;
        self.request(n).await?;

        match agent::parse_response(&self.buf)? {
            AgentResponse::Identities(ids) => {
                let mut keys = vec![];
                for id in ids {
                    let id = id?;
                    match id.sign_key() {
                        Ok(k) => keys.push(k),
                        Err(e) => {
                            debug!("skipping agent key {:?}: {e}", id.comment)
                        }
                    }
                }
                Ok(keys)
            }
            resp => {
                debug!("response: {resp:?}");
                Err(Error::msg("Unexpected agent response"))
            }
        }
    }

    pub async fn sign_auth(
        &mut self,
        key: &SignKey,
        msg: &AuthSigMsg<'_>,
    ) -> Result<OwnedSig> {
        self.buf.resize(agent::sign_request_len(key, msg)?, 0);
        let n = agent::encode_sign_request(&mut self.buf, key, msg)?;
        self.request(n).await?;

        match agent::parse_response(&self.buf)? {
            AgentResponse::Signature(sig) => sig.try_into(),
            resp => {
                debug!("response: {resp:?}");
                Err(Error::msg("Unexpected agent response"))
            }
        }
    }
}
