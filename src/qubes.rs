//! Preparation for a future qrexec broker, deliberately separate from the
//! desktop worker protocol. No RPC service or policy is installed by PGPCrypt.
use anyhow::{Result, ensure};
use serde::Deserialize;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const MAX_REMOTE_FRAME: usize = 1024 * 1024;

/// Identity must come from qrexec's trusted environment, never request JSON.
#[derive(Debug, PartialEq, Eq)]
pub struct Caller(String);
impl Caller {
    pub fn from_qrexec_domain(domain: &str) -> Result<Self> {
        ensure!(
            !domain.is_empty()
                && domain.len() <= 31
                && domain.as_bytes()[0].is_ascii_alphabetic()
                && domain
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
                && domain != "dom0",
            "Invalid or forbidden qrexec caller"
        );
        Ok(Self(domain.into()))
    }
    pub fn domain(&self) -> &str {
        &self.0
    }
}

/// A request is data, not authorization. A future broker must obtain fresh
/// local approval displaying the authenticated caller, operation and key.
/// Passwords, vault paths, settings, imports, exports and enumeration have no
/// representation in this protocol. No fields are forwarded to a shell.
#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum RemoteRequest {
    Sign {
        version: u32,
        fingerprint: String,
        text: String,
    },
    Decrypt {
        version: u32,
        text: String,
    },
}
impl RemoteRequest {
    pub fn parse(frame: &[u8]) -> Result<Self> {
        ensure!(
            frame.len() <= MAX_REMOTE_FRAME
                && frame.last() == Some(&b'\n')
                && !frame[..frame.len() - 1].contains(&b'\n'),
            "Expected one bounded qrexec JSON line"
        );
        let request: Self = serde_json::from_slice(frame)?;
        match &request {
            Self::Sign {
                version,
                fingerprint,
                ..
            } => {
                ensure!(*version == 1, "Unsupported qrexec protocol version");
                ensure!(
                    matches!(fingerprint.len(), 40 | 64)
                        && fingerprint.bytes().all(|b| b.is_ascii_hexdigit()),
                    "Expected a full key fingerprint"
                );
            }
            Self::Decrypt { version, .. } => {
                ensure!(*version == 1, "Unsupported qrexec protocol version")
            }
        }
        Ok(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn remote_requests_cannot_acquire_desktop_privileges() {
        for frame in [
            "{\"operation\":\"open\",\"version\":1,\"path\":\"/home/user/vault\"}\n",
            "{\"operation\":\"decrypt\",\"version\":1,\"text\":\"ciphertext\",\"password\":\"secret\"}\n",
            "{\"operation\":\"decrypt\",\"version\":1,\"text\":\"ciphertext\",\"domain\":\"trusted\"}\n",
            "{\"operation\":\"decrypt\",\"version\":2,\"text\":\"ciphertext\"}\n",
            "{}\n{}\n",
        ] {
            assert!(RemoteRequest::parse(frame.as_bytes()).is_err());
        }
        assert!(
            RemoteRequest::parse(
                b"{\"operation\":\"decrypt\",\"version\":1,\"text\":\"ciphertext\"}\n"
            )
            .is_ok()
        );
        assert!(RemoteRequest::parse(&vec![b'x'; MAX_REMOTE_FRAME + 1]).is_err());
    }
    #[test]
    fn caller_names_cannot_be_shell_arguments_or_dom0() {
        for domain in ["dom0", "", "a/b", "a;id", "-option", "1invalid", "test\n"] {
            assert!(Caller::from_qrexec_domain(domain).is_err());
        }
        assert_eq!(
            Caller::from_qrexec_domain("work-mail").unwrap().domain(),
            "work-mail"
        );
    }
}
