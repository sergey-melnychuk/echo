//! Capability tokens: [`CapabilityClaims`], [`CapabilityToken`], [`AuthError`]
//! and [`Permission`]. Implements SEC-1 to SEC-5.
//!
//! A token is a signed grant of read and/or write on one document to one peer
//! (`audience`) for a time window. Checking one is two mandatory steps:
//! [`CapabilityToken::verify`] (issuer, signature, window) and then
//! [`CapabilityToken::authorize`] (document, audience, permission).

use crate::Hash;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

/// Domain separator prefixed to every signed token payload (SEC-5).
pub const CAP_DOMAIN: &[u8] = b"p2p-sync-poc/cap/v1";
/// Clock skew tolerated on both ends of the validity window (SEC-4).
pub const CLOCK_SKEW_SECS: u64 = 60;
/// Length of the fixed signing payload.
pub const PAYLOAD_LEN: usize = CAP_DOMAIN.len() + 32 + 32 + 1 + 8 + 8 + 32;

/// What a request needs from a token. `can_write` does not imply `can_read`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Permission {
    /// Fetch manifests, chunks, heads and versions; announce `Have`.
    Read,
    /// Announce `NewVersion`.
    Write,
}

/// The unsigned content of a token.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct CapabilityClaims {
    /// The one document this token applies to (SEC-3).
    pub doc_id: Hash,
    /// `NodeId` of the only peer allowed to present it (SEC-2).
    pub audience: [u8; 32],
    /// Grants [`Permission::Read`].
    pub can_read: bool,
    /// Grants [`Permission::Write`].
    pub can_write: bool,
    /// Unix seconds. Valid from here, minus skew.
    pub not_before: u64,
    /// Unix seconds. Valid until here, plus skew.
    pub expires_at: u64,
}

impl CapabilityClaims {
    /// The fixed-layout bytes that are signed:
    /// domain ‖ `doc_id` ‖ `audience` ‖ flags (bit 0 read, bit 1 write) ‖
    /// `not_before` LE ‖ `expires_at` LE ‖ `issuer`.
    pub fn signing_payload(&self, issuer: &[u8; 32]) -> [u8; PAYLOAD_LEN] {
        let mut out = [0u8; PAYLOAD_LEN];
        let mut i = 0;
        let mut put = |bytes: &[u8]| {
            out[i..i + bytes.len()].copy_from_slice(bytes);
            i += bytes.len();
        };
        put(CAP_DOMAIN);
        put(&self.doc_id);
        put(&self.audience);
        let flags = u8::from(self.can_read) | (u8::from(self.can_write) << 1);
        put(&[flags]);
        put(&self.not_before.to_le_bytes());
        put(&self.expires_at.to_le_bytes());
        put(issuer);
        out
    }
}

/// A signed capability. Only trustworthy after [`CapabilityToken::verify`]
/// succeeds against the owner key configured for its document.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct CapabilityToken {
    /// The grant.
    pub claims: CapabilityClaims,
    /// Public key of the signer. Must equal the document's owner key (SEC-1).
    pub issuer: [u8; 32],
    /// Ed25519 signature over [`CapabilityClaims::signing_payload`].
    pub signature: Signature,
}

/// Why a token was refused. Sent to peers only as a coarse code (SEC-10);
/// the variant itself goes to local logs.
#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
pub enum AuthError {
    /// `issuer` is not the owner key configured for the document (SEC-1).
    #[error("token issuer is not the trusted owner key")]
    UntrustedIssuer,
    /// `issuer` is not a valid Ed25519 public key.
    #[error("token issuer is not a valid public key")]
    InvalidPublicKey,
    /// The signature does not verify over the fixed payload (SEC-5).
    #[error("token signature is invalid")]
    InvalidSignature,
    /// `now` is before `not_before` minus skew (SEC-4).
    #[error("token is not yet valid")]
    NotYetValid,
    /// `now` is after `expires_at` plus skew (SEC-4).
    #[error("token expired at {expires_at}, now is {now}")]
    Expired {
        /// The token's `expires_at`.
        expires_at: u64,
        /// The `now` that was checked.
        now: u64,
    },
    /// The token names a different document (SEC-3).
    #[error("token is for a different document")]
    WrongDocument,
    /// The token is bound to a different peer (SEC-2).
    #[error("token is bound to a different peer")]
    WrongAudience,
    /// The token lacks the requested permission.
    #[error("token does not grant the requested permission")]
    InsufficientPermission,
}

impl CapabilityToken {
    /// Sign `claims` with the owner key. `issuer` is set from the key.
    pub fn issue(claims: CapabilityClaims, owner_key: &SigningKey) -> Self {
        let issuer = owner_key.verifying_key().to_bytes();
        let payload = claims.signing_payload(&issuer);
        let signature = owner_key.sign(&payload);
        CapabilityToken {
            claims,
            issuer,
            signature,
        }
    }

    /// SEC-1, SEC-4, SEC-5: `issuer` is the trusted owner key, the signature
    /// verifies with `verify_strict`, and `now` (unix seconds) lies within
    /// `[not_before - skew, expires_at + skew]`.
    ///
    /// This does not check the document, audience or permission; call
    /// [`CapabilityToken::authorize`] for those. Both steps are mandatory.
    pub fn verify(
        &self,
        trusted_issuer: &[u8; 32],
        now: u64,
    ) -> Result<&CapabilityClaims, AuthError> {
        if &self.issuer != trusted_issuer {
            return Err(AuthError::UntrustedIssuer);
        }
        let key =
            VerifyingKey::from_bytes(&self.issuer).map_err(|_| AuthError::InvalidPublicKey)?;
        let payload = self.claims.signing_payload(&self.issuer);
        key.verify_strict(&payload, &self.signature)
            .map_err(|_| AuthError::InvalidSignature)?;
        let c = &self.claims;
        if now.saturating_add(CLOCK_SKEW_SECS) < c.not_before {
            return Err(AuthError::NotYetValid);
        }
        if now > c.expires_at.saturating_add(CLOCK_SKEW_SECS) {
            return Err(AuthError::Expired {
                expires_at: c.expires_at,
                now,
            });
        }
        Ok(c)
    }

    /// SEC-2, SEC-3: the token names `doc_id`, its audience is the
    /// authenticated `peer`, and it grants `need`.
    pub fn authorize(
        &self,
        doc_id: &Hash,
        peer: &[u8; 32],
        need: Permission,
    ) -> Result<(), AuthError> {
        let c = &self.claims;
        if &c.doc_id != doc_id {
            return Err(AuthError::WrongDocument);
        }
        if &c.audience != peer {
            return Err(AuthError::WrongAudience);
        }
        let granted = match need {
            Permission::Read => c.can_read,
            Permission::Write => c.can_write,
        };
        if !granted {
            return Err(AuthError::InsufficientPermission);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::generate_signing_key;

    const DOC: Hash = [7u8; 32];
    const PEER: [u8; 32] = [9u8; 32];
    const NOW: u64 = 1_700_000_000;

    fn claims(read: bool, write: bool) -> CapabilityClaims {
        CapabilityClaims {
            doc_id: DOC,
            audience: PEER,
            can_read: read,
            can_write: write,
            not_before: NOW - 100,
            expires_at: NOW + 100,
        }
    }

    fn issue(owner: &SigningKey, c: CapabilityClaims) -> (CapabilityToken, [u8; 32]) {
        let t = CapabilityToken::issue(c, owner);
        let issuer = owner.verifying_key().to_bytes();
        (t, issuer)
    }

    #[test]
    fn valid_token_verifies_and_authorizes_read_and_write_independently() {
        let owner = generate_signing_key();
        let (rw, issuer) = issue(&owner, claims(true, true));
        assert_eq!(rw.verify(&issuer, NOW).unwrap(), &rw.claims);
        rw.authorize(&DOC, &PEER, Permission::Read).unwrap();
        rw.authorize(&DOC, &PEER, Permission::Write).unwrap();

        let (ro, _) = issue(&owner, claims(true, false));
        ro.verify(&issuer, NOW).unwrap();
        ro.authorize(&DOC, &PEER, Permission::Read).unwrap();
        assert_eq!(
            ro.authorize(&DOC, &PEER, Permission::Write),
            Err(AuthError::InsufficientPermission)
        );

        // Write does not imply read.
        let (wo, _) = issue(&owner, claims(false, true));
        wo.verify(&issuer, NOW).unwrap();
        wo.authorize(&DOC, &PEER, Permission::Write).unwrap();
        assert_eq!(
            wo.authorize(&DOC, &PEER, Permission::Read),
            Err(AuthError::InsufficientPermission)
        );
    }

    /// SEC-4: skew boundary on both sides.
    #[test]
    fn expiry_and_not_before_with_skew_boundaries() {
        let owner = generate_signing_key();
        let c = claims(true, false);
        let (t, issuer) = issue(&owner, c.clone());

        // Expiry: expires_at + skew is the last accepted second.
        assert!(t.verify(&issuer, c.expires_at).is_ok());
        assert!(t.verify(&issuer, c.expires_at + CLOCK_SKEW_SECS).is_ok());
        assert_eq!(
            t.verify(&issuer, c.expires_at + CLOCK_SKEW_SECS + 1),
            Err(AuthError::Expired {
                expires_at: c.expires_at,
                now: c.expires_at + CLOCK_SKEW_SECS + 1
            })
        );

        // Not before: not_before - skew is the first accepted second.
        assert!(t.verify(&issuer, c.not_before).is_ok());
        assert!(t.verify(&issuer, c.not_before - CLOCK_SKEW_SECS).is_ok());
        assert_eq!(
            t.verify(&issuer, c.not_before - CLOCK_SKEW_SECS - 1),
            Err(AuthError::NotYetValid)
        );
    }

    /// SEC-1: a token signed by any key other than the trusted issuer fails,
    /// even though its signature is internally consistent.
    #[test]
    fn sec1_untrusted_issuer_is_rejected() {
        let owner = generate_signing_key();
        let attacker = generate_signing_key();
        let trusted = owner.verifying_key().to_bytes();
        let forged = CapabilityToken::issue(claims(true, true), &attacker);
        assert_eq!(
            forged.verify(&trusted, NOW),
            Err(AuthError::UntrustedIssuer)
        );

        // Claiming the owner as issuer while signing with another key fails
        // on the signature instead.
        let mut spoofed = forged.clone();
        spoofed.issuer = trusted;
        assert_eq!(
            spoofed.verify(&trusted, NOW),
            Err(AuthError::InvalidSignature)
        );
    }

    /// SEC-2 and SEC-3: wrong audience and wrong document fail in `authorize`.
    #[test]
    fn sec2_sec3_wrong_audience_and_document_fail() {
        let owner = generate_signing_key();
        let (t, issuer) = issue(&owner, claims(true, true));
        t.verify(&issuer, NOW).unwrap();
        assert_eq!(
            t.authorize(&[8u8; 32], &PEER, Permission::Read),
            Err(AuthError::WrongDocument)
        );
        assert_eq!(
            t.authorize(&DOC, &[1u8; 32], Permission::Read),
            Err(AuthError::WrongAudience)
        );
    }

    /// SEC-5: changing any claim after signing fails verification.
    #[test]
    fn sec5_any_claim_change_breaks_signature() {
        let owner = generate_signing_key();
        let (t, issuer) = issue(&owner, claims(true, false));
        type Mutation = Box<dyn Fn(&mut CapabilityClaims)>;
        let mutations: Vec<Mutation> = vec![
            Box::new(|c| c.doc_id[0] ^= 1),
            Box::new(|c| c.doc_id[31] ^= 1),
            Box::new(|c| c.audience[0] ^= 1),
            Box::new(|c| c.audience[31] ^= 1),
            Box::new(|c| c.can_read = !c.can_read),
            Box::new(|c| c.can_write = !c.can_write),
            Box::new(|c| c.not_before += 1),
            Box::new(|c| c.expires_at += 1),
        ];
        for (i, m) in mutations.iter().enumerate() {
            let mut bad = t.clone();
            m(&mut bad.claims);
            assert_eq!(
                bad.verify(&issuer, NOW),
                Err(AuthError::InvalidSignature),
                "mutation {i} should invalidate the signature"
            );
        }
        // Tampering with the signature itself.
        let mut bad = t.clone();
        let mut sig = bad.signature.to_bytes();
        sig[5] ^= 0x10;
        bad.signature = Signature::from_bytes(&sig);
        assert_eq!(bad.verify(&issuer, NOW), Err(AuthError::InvalidSignature));
    }

    #[test]
    fn invalid_public_key_issuer_is_reported() {
        // 0x02 repeated is not a valid compressed Edwards point.
        let bad_issuer = [0x02u8; 32];
        let owner = generate_signing_key();
        let mut t = CapabilityToken::issue(claims(true, false), &owner);
        t.issuer = bad_issuer;
        assert_eq!(t.verify(&bad_issuer, NOW), Err(AuthError::InvalidPublicKey));
    }

    #[test]
    fn signing_payload_has_fixed_layout() {
        let c = claims(true, true);
        let issuer = [3u8; 32];
        let p = c.signing_payload(&issuer);
        assert_eq!(p.len(), PAYLOAD_LEN);
        assert_eq!(&p[..CAP_DOMAIN.len()], CAP_DOMAIN);
        let mut i = CAP_DOMAIN.len();
        assert_eq!(&p[i..i + 32], &DOC);
        i += 32;
        assert_eq!(&p[i..i + 32], &PEER);
        i += 32;
        assert_eq!(p[i], 0b11);
        i += 1;
        assert_eq!(&p[i..i + 8], &c.not_before.to_le_bytes());
        i += 8;
        assert_eq!(&p[i..i + 8], &c.expires_at.to_le_bytes());
        i += 8;
        assert_eq!(&p[i..i + 32], &issuer);
    }

    #[test]
    fn token_round_trips_through_bincode() {
        let owner = generate_signing_key();
        let (t, issuer) = issue(&owner, claims(true, true));
        let bytes = crate::protocol::encode(&t, 1024).unwrap();
        let back: CapabilityToken = crate::protocol::decode(&bytes, 1024).unwrap();
        assert_eq!(back, t);
        back.verify(&issuer, NOW).unwrap();
    }
}
