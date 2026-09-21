//! The invite (SPEC.md section 5.5): a docs ticket of the chosen mode, the
//! attenuated token and the Biscuit root public key, in one string.
//!
//! An invite is a secret. A bound invite is useless to anyone but the named
//! endpoint; a delegatable (bearer) invite admits whoever holds it until it
//! expires, so it must be passed over a channel the owner trusts.

use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use biscuit_auth::PublicKey;
use iroh_docs::DocTicket;
use serde::{Deserialize, Serialize};

use crate::auth;

/// The invite string prefix, versioned.
pub const PREFIX: &str = "vaultsync1.";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Invite {
    /// The docs ticket (read or write capability plus addresses).
    pub ticket: String,
    /// The Biscuit token, base64url without padding.
    pub token: String,
    /// The Biscuit root public key, hex.
    pub root: String,
    /// Whether the token carries no audience check and may be delegated.
    #[serde(default)]
    pub delegatable: bool,
}

impl Invite {
    pub fn new(ticket: &DocTicket, token: &[u8], root: &PublicKey, delegatable: bool) -> Self {
        Self {
            ticket: ticket.to_string(),
            token: data_encoding::BASE64URL_NOPAD.encode(token),
            root: auth::public_to_hex(root),
            delegatable,
        }
    }

    pub fn encode(&self) -> String {
        let json = serde_json::to_vec(self).expect("invite serializes");
        format!("{PREFIX}{}", data_encoding::BASE64URL_NOPAD.encode(&json))
    }

    pub fn decode(text: &str) -> Result<Invite> {
        let body = text
            .trim()
            .strip_prefix(PREFIX)
            .ok_or_else(|| anyhow!("not a vaultsync invite (expected the {PREFIX} prefix)"))?;
        let json = data_encoding::BASE64URL_NOPAD
            .decode(body.as_bytes())
            .context("invite is not valid base64url")?;
        serde_json::from_slice(&json).context("invite has an unexpected structure")
    }

    pub fn doc_ticket(&self) -> Result<DocTicket> {
        self.ticket
            .parse()
            .map_err(|err| anyhow!("invite ticket: {err}"))
    }

    pub fn token_bytes(&self) -> Result<Vec<u8>> {
        data_encoding::BASE64URL_NOPAD
            .decode(self.token.as_bytes())
            .context("invite token is not valid base64url")
    }

    pub fn root_key(&self) -> Result<PublicKey> {
        auth::public_from_hex(&self.root)
    }
}

impl std::fmt::Display for Invite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.encode())
    }
}

impl std::str::FromStr for Invite {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        Invite::decode(s)
    }
}

/// Parse a time to live: a number of seconds, or a number with one of the
/// suffixes `s`, `m`, `h`, `d`, `w`.
pub fn parse_duration(text: &str) -> Result<Duration> {
    let text = text.trim();
    if text.is_empty() {
        bail!("empty duration");
    }
    let (digits, unit) = match text.find(|c: char| !c.is_ascii_digit()) {
        Some(index) => text.split_at(index),
        None => (text, "s"),
    };
    let amount: u64 = digits
        .parse()
        .with_context(|| format!("duration {text:?}: not a number"))?;
    let seconds = match unit.trim() {
        "s" | "sec" | "secs" => amount,
        "m" | "min" | "mins" => amount * 60,
        "h" | "hr" | "hrs" => amount * 3600,
        "d" | "day" | "days" => amount * 86_400,
        "w" | "week" | "weeks" => amount * 7 * 86_400,
        other => bail!("duration {text:?}: unknown unit {other:?} (use s, m, h, d or w)"),
    };
    if seconds == 0 {
        bail!("duration must be positive");
    }
    Ok(Duration::from_secs(seconds))
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::{EndpointAddr, SecretKey};
    use iroh_docs::Capability;

    #[test]
    fn invite_round_trips() {
        let root = auth::generate_root();
        let ticket = DocTicket::new(
            Capability::Read(iroh_docs::NamespaceId::from(&[3u8; 32])),
            vec![EndpointAddr::new(
                SecretKey::from_bytes(&[1u8; 32]).public(),
            )],
        );
        let invite = Invite::new(&ticket, b"token-bytes", &root.public(), true);
        let text = invite.encode();
        assert!(text.starts_with(PREFIX));
        let back: Invite = text.parse().unwrap();
        assert_eq!(back, invite);
        assert_eq!(back.token_bytes().unwrap(), b"token-bytes");
        assert_eq!(back.root_key().unwrap(), root.public());
        assert_eq!(
            back.doc_ticket().unwrap().capability.id(),
            ticket.capability.id()
        );
        assert!(Invite::decode("docaaa...").is_err());
        assert!(Invite::decode("vaultsync1.!!!").is_err());
        // A plain docs ticket is not an invite.
        assert!(Invite::decode(&ticket.to_string()).is_err());
    }

    #[test]
    fn durations_parse() {
        assert_eq!(parse_duration("90").unwrap(), Duration::from_secs(90));
        assert_eq!(parse_duration("30s").unwrap(), Duration::from_secs(30));
        assert_eq!(parse_duration("15m").unwrap(), Duration::from_secs(900));
        assert_eq!(parse_duration("12h").unwrap(), Duration::from_secs(43_200));
        assert_eq!(parse_duration("7d").unwrap(), Duration::from_secs(604_800));
        assert_eq!(
            parse_duration("2w").unwrap(),
            Duration::from_secs(1_209_600)
        );
        assert!(parse_duration("").is_err());
        assert!(parse_duration("0h").is_err());
        assert!(parse_duration("5y").is_err());
        assert!(parse_duration("h").is_err());
    }
}
