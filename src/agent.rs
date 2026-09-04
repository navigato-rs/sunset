//! SSH agent protocol, without any IO.
//!
//! The agent protocol is a request and a response, each framed by a
//! `u32` length. This encodes requests into a buffer and decodes
//! responses from one; moving those bytes over a Unix socket, a Windows
//! named pipe, or anything else is the caller's.
//!
//! ```
//! use sunset::agent;
//!
//! /// Asks an agent for its keys, given something that can carry the
//! /// bytes. Nothing here does IO of its own.
//! fn list(
//!     mut send: impl FnMut(&[u8]),
//!     mut recv: impl FnMut(&mut [u8]),
//!     buf: &mut [u8],
//! ) -> sunset::Result<()> {
//!     let n = agent::encode_request_identities(buf)?;
//!     send(&buf[..n]);
//!
//!     // A response is a u32 length, then that many bytes
//!     let mut len = [0u8; 4];
//!     recv(&mut len);
//!     let len = agent::response_len(&len)?;
//!     let Some(body) = buf.get_mut(..len) else {
//!         return Err(sunset::Error::msg("agent response doesn't fit"));
//!     };
//!     recv(body);
//!
//!     if let agent::AgentResponse::Identities(ids) = agent::parse_response(body)? {
//!         for id in ids {
//!             let _key = id?.key;
//!         }
//!     }
//!     Ok(())
//! }
//! ```

use core::fmt::Debug;

#[allow(unused_imports)]
use log::{debug, error, info, log, trace, warn};

use sunset_sshwire_derive::{SSHDecode, SSHEncode};

use crate::sshnames::*;
use crate::sshwire::{
    self, Blob, SSHEncode, SSHSink, TextString, WireError, WireResult,
};
use crate::{AuthSigMsg, Error, PubKey, Result, SignKey, Signature, error};

/// Largest agent response that will be accepted.
///
/// Must be enough for a list of every public key the agent holds.
pub const MAX_RESPONSE: usize = 200_000;

#[derive(Debug, SSHEncode)]
struct SignRequest<'a> {
    key_blob: Blob<PubKey<'a>>,
    msg: Blob<&'a AuthSigMsg<'a>>,
    flags: u32,
}

#[derive(Debug, SSHDecode)]
struct SignResponse<'a> {
    sig: Blob<Signature<'a>>,
}

#[derive(Debug)]
enum Request<'a> {
    SignRequest(SignRequest<'a>),
    RequestIdentities,
}

impl SSHEncode for Request<'_> {
    fn enc(&self, s: &mut dyn SSHSink) -> WireResult<()> {
        match self {
            Self::SignRequest(a) => {
                let n = AgentMessageNum::SSH_AGENTC_SIGN_REQUEST as u8;
                n.enc(s)?;
                a.enc(s)?;
            }
            Self::RequestIdentities => {
                let n = AgentMessageNum::SSH_AGENTC_REQUEST_IDENTITIES as u8;
                n.enc(s)?;
            }
        }
        Ok(())
    }
}

/// One key an agent holds.
#[derive(Debug, SSHDecode)]
pub struct Identity<'a> {
    /// The public key
    pub key: Blob<PubKey<'a>>,
    /// The agent's description of it, often a file name
    pub comment: TextString<'a>,
}

impl Identity<'_> {
    /// A [`SignKey`] that signs through the agent.
    ///
    /// Fails for a key type Sunset can't use.
    pub fn sign_key(&self) -> Result<SignKey> {
        SignKey::from_agent_pubkey(&self.key.0)
    }
}

/// The keys in a `SSH_AGENT_IDENTITIES_ANSWER`.
///
/// Decoded one at a time as they are walked, so a large list doesn't
/// have to be held anywhere.
#[derive(Debug, Clone)]
pub struct Identities<'a> {
    rest: &'a [u8],
    left: u32,
}

impl Identities<'_> {
    /// Keys still to be walked.
    ///
    /// The agent's whole count before iterating, decreasing as entries
    /// are taken.
    pub fn remaining(&self) -> u32 {
        self.left
    }
}

impl<'a> Iterator for Identities<'a> {
    type Item = Result<Identity<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.left == 0 {
            return None;
        }
        self.left -= 1;
        Some(match sshwire::read_ssh::<Identity>(self.rest, None) {
            Ok((id, used)) => {
                // OK slice, read_ssh() consumed `used` of it
                self.rest = &self.rest[used..];
                Ok(id)
            }
            Err(e) => {
                // A malformed entry loses the position in the list
                self.left = 0;
                Err(e)
            }
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let l = self.left as usize;
        (l, Some(l))
    }
}

/// The agent's answer to a request.
#[derive(Debug)]
pub enum AgentResponse<'a> {
    /// The keys the agent holds
    Identities(Identities<'a>),
    /// A signature over the request's message
    Signature(Signature<'a>),
}

/// Encodes a `SSH_AGENTC_REQUEST_IDENTITIES`, returning its length.
///
/// The length frame the agent expects is included.
pub fn encode_request_identities(buf: &mut [u8]) -> Result<usize> {
    sshwire::write_ssh(buf, &Blob(Request::RequestIdentities))
}

/// Encodes a `SSH_AGENTC_SIGN_REQUEST`, returning its length.
///
/// The length frame the agent expects is included. `key` must be one of
/// the agent's own keys, from [`Identity::sign_key()`].
pub fn encode_sign_request(
    buf: &mut [u8],
    key: &SignKey,
    msg: &AuthSigMsg<'_>,
) -> Result<usize> {
    let flags = match key {
        #[cfg(feature = "rsa")]
        SignKey::AgentRSA(_) => SSH_AGENT_FLAG_RSA_SHA2_256,
        _ => 0,
    };
    let r = Request::SignRequest(SignRequest {
        key_blob: Blob(key.pubkey()),
        msg: Blob(msg),
        flags,
    });
    sshwire::write_ssh(buf, &Blob(r))
}

/// How long a buffer [`encode_sign_request()`] needs.
///
/// The size depends on the key and the message, so a caller with a
/// fixed buffer can check before encoding rather than after.
pub fn sign_request_len(key: &SignKey, msg: &AuthSigMsg<'_>) -> Result<usize> {
    let r = Request::SignRequest(SignRequest {
        key_blob: Blob(key.pubkey()),
        msg: Blob(msg),
        flags: 0,
    });
    Ok(sshwire::length_enc(&Blob(r))? as usize)
}

/// The length of the response body that follows a `u32` length frame.
///
/// Read four bytes from the agent, pass them here, then read that many
/// more into a buffer for [`parse_response()`].
pub fn response_len(frame: &[u8; 4]) -> Result<usize> {
    let l = u32::from_be_bytes(*frame) as usize;
    if l > MAX_RESPONSE {
        error!("Agent response is {l} bytes long");
        return Err(Error::msg("Agent response too large"));
    }
    Ok(l)
}

/// Decodes a response body, without its length frame.
pub fn parse_response(body: &[u8]) -> Result<AgentResponse<'_>> {
    let Some((number, rest)) = body.split_first() else {
        return error::RanOut.fail();
    };
    if *number == AgentMessageNum::SSH_AGENT_IDENTITIES_ANSWER as u8 {
        let (count, used) = sshwire::read_ssh::<u32>(rest, None)?;
        // OK slice, read_ssh() consumed `used` of it
        Ok(AgentResponse::Identities(Identities {
            rest: &rest[used..],
            left: count,
        }))
    } else if *number == AgentMessageNum::SSH_AGENT_SIGN_RESPONSE as u8 {
        let (r, _) = sshwire::read_ssh::<SignResponse>(rest, None)?;
        Ok(AgentResponse::Signature(r.sig.0))
    } else if *number == AgentMessageNum::SSH_AGENT_FAILURE as u8 {
        debug!("Agent refused the request");
        Err(Error::msg("Agent refused the request"))
    } else {
        Err(WireError::UnknownPacket { number: *number }.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    extern crate std;
    use std::io::{Read as _, Write as _};
    use std::os::unix::net::UnixStream;
    use std::vec;
    use std::vec::Vec;

    use crate::packets::{AuthMethod, MethodPubKey, UserauthRequest};
    use crate::sshnames::SSH_SERVICE_CONNECTION;

    /// One request and response over a blocking socket.
    ///
    /// This is the whole of the IO an agent client needs, which is the
    /// point: nothing above knows what the transport is.
    fn round_trip(sock: &mut UnixStream, req: &[u8]) -> Vec<u8> {
        sock.write_all(req).expect("write");
        let mut frame = [0u8; 4];
        sock.read_exact(&mut frame).expect("read length");
        let len = response_len(&frame).expect("length");
        let mut body = vec![0u8; len];
        sock.read_exact(&mut body).expect("read body");
        body
    }

    /// Runs against whatever agent `$SSH_AUTH_SOCK` points at.
    ///
    /// A real agent is the only way to know the encoding is right, so
    /// this is skipped rather than mocked when there isn't one.
    #[test]
    fn a_real_agent() {
        let Some(path) = std::env::var_os("SSH_AUTH_SOCK") else {
            std::eprintln!("No SSH_AUTH_SOCK, skipping");
            return;
        };
        let Ok(mut sock) = UnixStream::connect(&path) else {
            std::eprintln!("Can't reach the agent, skipping");
            return;
        };

        // Ask for the keys it holds
        let mut buf = vec![0u8; 256];
        let n = encode_request_identities(&mut buf).expect("encode");
        let body = round_trip(&mut sock, &buf[..n]);

        let AgentResponse::Identities(ids) = parse_response(&body).expect("parse")
        else {
            panic!("expected identities");
        };
        let count = ids.remaining();
        let keys: Vec<_> = ids.map(|i| i.expect("identity")).collect();
        assert_eq!(keys.len(), count as usize, "as many keys as announced");
        if keys.is_empty() {
            std::eprintln!("The agent holds no keys, skipping the signature");
            return;
        }

        // Sign something with the first key Sunset can use
        let Some(key) = keys.iter().find_map(|i| i.sign_key().ok()) else {
            std::eprintln!("No usable key, skipping the signature");
            return;
        };

        let sess_id = crate::kex::SessId::from_slice(&[7u8; 32]).unwrap();
        let mut mp = MethodPubKey::new(key.pubkey(), None).unwrap();
        mp.force_sig = true;
        let u = UserauthRequest {
            username: "someone".into(),
            service: SSH_SERVICE_CONNECTION,
            method: AuthMethod::PubKey(mp),
        };
        let msg = crate::auth::AuthSigMsg::new(u, &sess_id);

        let want = sign_request_len(&key, &msg).expect("length");
        let mut buf = vec![0u8; want];
        let n = encode_sign_request(&mut buf, &key, &msg).expect("encode");
        assert_eq!(n, want, "sign_request_len() sizes the buffer exactly");

        let body = round_trip(&mut sock, &buf[..n]);
        let AgentResponse::Signature(sig) = parse_response(&body).expect("parse")
        else {
            panic!("expected a signature");
        };

        // The agent signed the message we asked it to, and it checks
        // out against the key the agent named.
        let sig_type = sig.sig_type().expect("signature type");
        sig_type.verify(&key.pubkey(), &msg, &sig).expect("signature verifies");
    }

    /// The buffer a caller offers may be too small for the reply.
    #[test]
    fn an_over_long_response_is_refused() {
        assert!(response_len(&[0, 0, 0, 8]).is_ok());
        assert!(response_len(&0xffff_ffffu32.to_be_bytes()).is_err());
    }

    /// A failure reply is a failure, not a decode error.
    #[test]
    fn agent_failure_is_reported() {
        let body = [AgentMessageNum::SSH_AGENT_FAILURE as u8];
        assert!(parse_response(&body).is_err());
    }

    /// An empty identities answer is a valid, empty list.
    #[test]
    fn no_identities() {
        let mut body = vec![AgentMessageNum::SSH_AGENT_IDENTITIES_ANSWER as u8];
        body.extend_from_slice(&0u32.to_be_bytes());
        let AgentResponse::Identities(mut ids) =
            parse_response(&body).expect("parse")
        else {
            panic!("expected identities");
        };
        assert_eq!(ids.remaining(), 0);
        assert!(ids.next().is_none());
    }
}
