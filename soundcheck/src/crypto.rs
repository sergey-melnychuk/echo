//! Domain-separated hashing (chunk hash, manifest ID, version ID, topic ID)
//! and key generation helpers.
//!
//! Every hash here uses a distinct BLAKE3 mode or context string, so a value
//! from one role can never be confused with a value from another.

use crate::clock::Hlc;
use crate::{Hash, VersionId};
use ed25519_dalek::SigningKey;
use rand::Rng;

/// Derive-key context for manifest IDs (section 5).
pub const MANIFEST_CONTEXT: &str = "p2p-sync-poc manifest v1";
/// Derive-key context for version IDs (section 5).
pub const VERSION_CONTEXT: &str = "p2p-sync-poc version v1";
/// Domain string fed into the keyed topic hash (section 5).
pub const TOPIC_DOMAIN: &[u8] = b"p2p-sync-poc/topic/v1";

/// Content address of a chunk: plain `blake3::hash` over its bytes.
pub fn chunk_hash(data: &[u8]) -> Hash {
    *blake3::hash(data).as_bytes()
}

/// Gossip topic for a document: keyed BLAKE3 with the secret salt as the key.
/// Only holders of the salt can compute it.
pub fn derive_topic_id(salt: &[u8; 32], doc_id: &Hash) -> Hash {
    let mut h = blake3::Hasher::new_keyed(salt);
    h.update(TOPIC_DOMAIN);
    h.update(doc_id);
    *h.finalize().as_bytes()
}

/// Identifier of a version: derive-key BLAKE3 over the document, manifest,
/// parent (presence byte, then the ID if present), clock value and author.
///
/// Two versions with identical content but different parents, clocks or
/// authors get different IDs, so a revert to old content is a new version.
pub fn version_id(
    doc_id: &Hash,
    manifest_id: &Hash,
    parent: Option<&VersionId>,
    hlc: Hlc,
    author: &[u8; 32],
) -> VersionId {
    let mut h = blake3::Hasher::new_derive_key(VERSION_CONTEXT);
    h.update(doc_id);
    h.update(manifest_id);
    match parent {
        Some(p) => {
            h.update(&[1u8]);
            h.update(p);
        }
        None => {
            h.update(&[0u8]);
        }
    }
    h.update(&hlc.to_bytes());
    h.update(author);
    *h.finalize().as_bytes()
}

/// A fresh Ed25519 signing key from a cryptographically secure generator
/// (the thread-local RNG, reseeded from the OS).
pub fn generate_signing_key() -> SigningKey {
    SigningKey::generate(&mut rand::rng())
}

/// 32 random bytes from a cryptographically secure generator, for document
/// IDs and salts.
pub fn random_bytes32() -> [u8; 32] {
    let mut out = [0u8; 32];
    rand::rng().fill_bytes(&mut out);
    out
}

/// First 8 hex characters of a hash, for logs. Never log full secrets.
pub fn short_hex(bytes: &[u8]) -> String {
    hex::encode(&bytes[..bytes.len().min(4)])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn topic_id_is_deterministic_and_input_sensitive() {
        let salt = [1u8; 32];
        let doc = [2u8; 32];
        let a = derive_topic_id(&salt, &doc);
        assert_eq!(a, derive_topic_id(&salt, &doc));
        assert_ne!(a, derive_topic_id(&[3u8; 32], &doc));
        assert_ne!(a, derive_topic_id(&salt, &[4u8; 32]));
    }

    #[test]
    fn topic_id_differs_from_plain_hash_of_inputs() {
        let salt = [1u8; 32];
        let doc = [2u8; 32];
        let mut plain = Vec::new();
        plain.extend_from_slice(&salt);
        plain.extend_from_slice(TOPIC_DOMAIN);
        plain.extend_from_slice(&doc);
        assert_ne!(derive_topic_id(&salt, &doc), chunk_hash(&plain));
    }

    #[test]
    fn version_id_is_deterministic_and_changes_with_every_input() {
        let doc = [1u8; 32];
        let man = [2u8; 32];
        let parent = [3u8; 32];
        let author = [4u8; 32];
        let hlc = Hlc::new(10, 1);
        let base = version_id(&doc, &man, Some(&parent), hlc, &author);
        assert_eq!(base, version_id(&doc, &man, Some(&parent), hlc, &author));
        assert_ne!(
            base,
            version_id(&[9u8; 32], &man, Some(&parent), hlc, &author)
        );
        assert_ne!(
            base,
            version_id(&doc, &[9u8; 32], Some(&parent), hlc, &author)
        );
        assert_ne!(base, version_id(&doc, &man, Some(&[9u8; 32]), hlc, &author));
        assert_ne!(base, version_id(&doc, &man, None, hlc, &author));
        assert_ne!(
            base,
            version_id(&doc, &man, Some(&parent), Hlc::new(10, 2), &author)
        );
        assert_ne!(
            base,
            version_id(&doc, &man, Some(&parent), Hlc::new(11, 1), &author)
        );
        assert_ne!(base, version_id(&doc, &man, Some(&parent), hlc, &[9u8; 32]));
    }

    #[test]
    fn version_id_differs_when_manifest_repeats_after_revert() {
        // v1 has manifest M, v2 has manifest M2, v3 reverts to M on top of v2.
        let doc = [1u8; 32];
        let m = [2u8; 32];
        let m2 = [3u8; 32];
        let author = [4u8; 32];
        let v1 = version_id(&doc, &m, None, Hlc::new(1, 0), &author);
        let v2 = version_id(&doc, &m2, Some(&v1), Hlc::new(2, 0), &author);
        let v3 = version_id(&doc, &m, Some(&v2), Hlc::new(3, 0), &author);
        assert_ne!(v1, v3);
    }

    #[test]
    fn parent_presence_byte_prevents_confusion() {
        // A version with no parent must not collide with one whose parent is
        // "all zeros", and the domain must differ from a chunk hash.
        let doc = [1u8; 32];
        let m = [2u8; 32];
        let author = [4u8; 32];
        let none = version_id(&doc, &m, None, Hlc::new(1, 0), &author);
        let zero = version_id(&doc, &m, Some(&[0u8; 32]), Hlc::new(1, 0), &author);
        assert_ne!(none, zero);
    }

    #[test]
    fn generated_keys_differ() {
        let a = generate_signing_key();
        let b = generate_signing_key();
        assert_ne!(a.to_bytes(), b.to_bytes());
        assert_ne!(random_bytes32(), random_bytes32());
    }

    #[test]
    fn short_hex_is_eight_chars() {
        assert_eq!(short_hex(&[0xab, 0xcd, 0xef, 0x01, 0x23]), "abcdef01");
        assert_eq!(short_hex(&[0xab]), "ab");
    }
}
