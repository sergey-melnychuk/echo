//! `p2p-sync-poc`: a serverless directory sync proof of concept built on
//! content-defined chunking, capability tokens and QUIC transport.
//!
//! See `SPEC.md` for the full design. Each module below owns one concern
//! and no module reaches around another.

#![forbid(unsafe_code)]

pub mod capabilities;
pub mod chunker;
pub mod cli;
pub mod clock;
pub mod crypto;
pub mod gossip;
pub mod manifest;
pub mod protocol;
pub mod storage;
pub mod sync;
pub mod transport;
pub mod watcher;

/// A 32-byte BLAKE3 digest. Used for chunk hashes, manifest IDs, document IDs
/// and topic IDs.
pub type Hash = [u8; 32];

/// Identifier of one signed version of a file. Derived by
/// [`crypto::version_id`] from the document, manifest, parent, clock and
/// author, so reverting a file to old content never repeats an ID.
pub type VersionId = [u8; 32];
