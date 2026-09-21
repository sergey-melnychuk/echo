//! Wire types, limits, size-limited `encode` and `decode`, and frame helpers
//! (SEC-7, SEC-10).
//!
//! Every bincode encoding in the crate goes through [`encode`] and [`decode`]
//! so that one configuration (varint, little endian, size limit, no trailing
//! bytes) is used everywhere. Other bincode configurations (for example the
//! fixed-int `legacy` one) must not be mixed in: they would not round-trip.

use crate::capabilities::CapabilityToken;
use crate::gossip::SyncMessage;
use crate::manifest::FileManifest;
use crate::{Hash, VersionId};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// ALPN of the sync protocol.
pub const ALPN: &[u8] = b"p2p-sync-poc/sync/v1";

/// Largest request frame a server reads (section 6 limits).
pub const REQUEST_FRAME_LIMIT: usize = 1024;
/// Largest response frame a client reads.
pub const RESPONSE_FRAME_LIMIT: usize = 2 * 1024 * 1024;
/// Largest chunk payload.
pub const CHUNK_PAYLOAD_LIMIT: usize = 32 * 1024;
/// Largest gossip message accepted (section 7 check 1).
pub const GOSSIP_FRAME_LIMIT: usize = 1024;
/// Time allowed to read one frame.
pub const FRAME_READ_TIMEOUT: Duration = Duration::from_secs(10);
/// Time allowed for one whole request.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Time allowed to establish a connection to a peer.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Concurrent bidirectional streams a server accepts per connection.
pub const MAX_STREAMS_PER_CONNECTION: u32 = 64;
/// Connections a server accepts in total.
pub const MAX_CONNECTIONS: usize = 256;
/// Connections a server accepts from one peer.
pub const MAX_CONNECTIONS_PER_PEER: usize = 4;
/// QUIC idle timeout.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
/// Most entries in a `Heads` response.
pub const MAX_HEADS: usize = 1024;

/// One request, sent as a single frame on its own bidirectional stream.
/// Every variant carries the presenter's token, so streams need no session
/// state and may arrive in any order.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum Request {
    /// Fetch a manifest of `doc_id`.
    GetManifest {
        /// The presenter's capability.
        token: CapabilityToken,
        /// The document.
        doc_id: Hash,
        /// The manifest wanted.
        manifest_id: Hash,
    },
    /// Fetch a chunk that some manifest of `doc_id` references.
    GetChunk {
        /// The presenter's capability.
        token: CapabilityToken,
        /// The document.
        doc_id: Hash,
        /// The chunk wanted.
        hash: Hash,
    },
    /// Fetch the latest signed `NewVersion` per file.
    GetHeads {
        /// The presenter's capability.
        token: CapabilityToken,
        /// The document.
        doc_id: Hash,
    },
    /// Fetch one stored signed `NewVersion`, accepted or rejected.
    GetVersion {
        /// The presenter's capability.
        token: CapabilityToken,
        /// The document.
        doc_id: Hash,
        /// The version wanted.
        version_id: VersionId,
    },
}

impl Request {
    /// The token presented with the request.
    pub fn token(&self) -> &CapabilityToken {
        match self {
            Request::GetManifest { token, .. }
            | Request::GetChunk { token, .. }
            | Request::GetHeads { token, .. }
            | Request::GetVersion { token, .. } => token,
        }
    }

    /// The document the request is scoped to.
    pub fn doc_id(&self) -> &Hash {
        match self {
            Request::GetManifest { doc_id, .. }
            | Request::GetChunk { doc_id, .. }
            | Request::GetHeads { doc_id, .. }
            | Request::GetVersion { doc_id, .. } => doc_id,
        }
    }

    /// Short name for logs and metrics.
    pub fn kind(&self) -> &'static str {
        match self {
            Request::GetManifest { .. } => "GetManifest",
            Request::GetChunk { .. } => "GetChunk",
            Request::GetHeads { .. } => "GetHeads",
            Request::GetVersion { .. } => "GetVersion",
        }
    }
}

/// One response, sent as a single frame and followed by `finish()`.
// `Version(SyncMessage)` is several hundred bytes while `Error` is one. A
// response lives only until it is encoded, so the size gap costs nothing,
// and boxing the variant would change the section 6 contract.
#[allow(clippy::large_enum_variant)]
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum Response {
    /// The requested manifest. Receivers recompute its ID (SEC-8).
    Manifest(FileManifest),
    /// The requested chunk bytes. Receivers re-hash them (SEC-8).
    Chunk(Vec<u8>),
    /// Latest signed `NewVersion` per file, at most [`MAX_HEADS`].
    Heads(Vec<SyncMessage>),
    /// One stored signed `NewVersion`, by ID.
    Version(SyncMessage),
    /// A coarse failure code (SEC-10).
    Error(ErrorCode),
}

/// Coarse error codes returned to peers (SEC-10). Details stay in local logs.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ErrorCode {
    /// Bad signature, untrusted issuer, expired, not yet valid, or unknown document.
    Unauthorized,
    /// Wrong document, wrong audience, or missing permission.
    Forbidden,
    /// Chunk, manifest or version not held for this document.
    NotFound,
    /// Decode failure, trailing bytes or an invalid field.
    BadRequest,
    /// Connection or stream capacity exceeded.
    Busy,
    /// Storage or other internal failure.
    Internal,
}

impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

/// Encoding and framing failures. Never carries peer-supplied text.
#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    /// A frame length exceeded the limit for its direction (SEC-7).
    #[error("frame of {len} bytes exceeds the {limit} byte limit")]
    FrameTooLarge {
        /// Announced or actual length.
        len: usize,
        /// The applicable limit.
        limit: usize,
    },
    /// Serialization failed or exceeded the limit.
    #[error("encode failed: {0}")]
    Encode(String),
    /// Deserialization failed, including trailing bytes.
    #[error("decode failed: {0}")]
    Decode(String),
    /// Reading or writing a frame failed.
    #[error("frame io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Write one frame: a 4-byte big-endian length, then `payload`. Refuses
/// payloads over `limit` so a bug cannot produce a frame the peer must drop.
pub async fn write_frame<W: AsyncWrite + Unpin>(
    w: &mut W,
    payload: &[u8],
    limit: usize,
) -> Result<(), ProtocolError> {
    if payload.len() > limit {
        return Err(ProtocolError::FrameTooLarge {
            len: payload.len(),
            limit,
        });
    }
    let len = u32::try_from(payload.len()).map_err(|_| ProtocolError::FrameTooLarge {
        len: payload.len(),
        limit,
    })?;
    w.write_all(&len.to_be_bytes()).await?;
    w.write_all(payload).await?;
    Ok(())
}

/// Read one frame. The announced length is checked against `limit` before
/// any buffer is allocated (SEC-7).
pub async fn read_frame<R: AsyncRead + Unpin>(
    r: &mut R,
    limit: usize,
) -> Result<Vec<u8>, ProtocolError> {
    let mut header = [0u8; 4];
    r.read_exact(&mut header).await?;
    let len = u32::from_be_bytes(header) as usize;
    if len > limit {
        return Err(ProtocolError::FrameTooLarge { len, limit });
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    Ok(buf)
}

/// Hard ceiling on any single encoded value, enforced inside bincode so a
/// length prefix can never trigger a larger allocation. Per-direction limits
/// are checked on top of it by [`encode`] and [`decode`].
pub const CODEC_LIMIT: usize = RESPONSE_FRAME_LIMIT;

/// The one bincode configuration used everywhere: little endian, varint
/// integers, and a read/write limit of [`CODEC_LIMIT`].
const CONFIG: bincode::config::Configuration<
    bincode::config::LittleEndian,
    bincode::config::Varint,
    bincode::config::Limit<CODEC_LIMIT>,
> = bincode::config::standard()
    .with_little_endian()
    .with_variable_int_encoding()
    .with_limit::<CODEC_LIMIT>();

/// Serialize `value` with the shared configuration, failing if the result
/// exceeds `limit` bytes.
pub fn encode<T: Serialize>(value: &T, limit: usize) -> Result<Vec<u8>, ProtocolError> {
    let bytes = bincode::serde::encode_to_vec(value, CONFIG)
        .map_err(|e| ProtocolError::Encode(e.to_string()))?;
    if bytes.len() > limit {
        return Err(ProtocolError::Encode(format!(
            "encoded {} bytes, more than the {limit} byte limit",
            bytes.len()
        )));
    }
    Ok(bytes)
}

/// Deserialize `bytes` with the shared configuration. Rejects input longer
/// than `limit` before touching it, and rejects trailing bytes.
pub fn decode<T: DeserializeOwned>(bytes: &[u8], limit: usize) -> Result<T, ProtocolError> {
    if bytes.len() > limit {
        return Err(ProtocolError::FrameTooLarge {
            len: bytes.len(),
            limit,
        });
    }
    let (value, read): (T, usize) = bincode::serde::decode_from_slice(bytes, CONFIG)
        .map_err(|e| ProtocolError::Decode(e.to_string()))?;
    if read != bytes.len() {
        return Err(ProtocolError::Decode(format!(
            "{} trailing bytes",
            bytes.len() - read
        )));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_round_trip() {
        let v: (u64, String, Vec<u8>) = (7, "x".into(), vec![1, 2, 3]);
        let bytes = encode(&v, 1024).unwrap();
        let back: (u64, String, Vec<u8>) = decode(&bytes, 1024).unwrap();
        assert_eq!(back, v);
    }

    #[test]
    fn decode_rejects_trailing_and_truncated_and_oversize() {
        let bytes = encode(&42u64, 64).unwrap();
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(matches!(
            decode::<u64>(&trailing, 64),
            Err(ProtocolError::Decode(_))
        ));
        let v = encode(&vec![1u32, 2, 3], 64).unwrap();
        assert!(matches!(
            decode::<Vec<u32>>(&v[..v.len() - 1], 64),
            Err(ProtocolError::Decode(_))
        ));
        assert!(matches!(
            decode::<Vec<u8>>(&[0u8; 65], 64),
            Err(ProtocolError::FrameTooLarge { len: 65, limit: 64 })
        ));
    }

    #[test]
    fn encode_respects_limit() {
        let big = vec![0u8; 100];
        assert!(matches!(encode(&big, 50), Err(ProtocolError::Encode(_))));
        encode(&big, 200).unwrap();
    }

    #[tokio::test]
    async fn frame_round_trip_and_oversize_header_is_rejected_before_read() {
        let mut buf = Vec::new();
        write_frame(&mut buf, b"hello", 16).await.unwrap();
        assert_eq!(&buf[..4], &5u32.to_be_bytes());
        let mut cursor: &[u8] = &buf;
        assert_eq!(read_frame(&mut cursor, 16).await.unwrap(), b"hello");

        // Header claims 5000 bytes but no body follows: the limit check must
        // fire before any read of the body (otherwise we would see EOF).
        let header = 5000u32.to_be_bytes();
        let mut cursor: &[u8] = &header;
        assert!(matches!(
            read_frame(&mut cursor, 1024).await,
            Err(ProtocolError::FrameTooLarge {
                len: 5000,
                limit: 1024
            })
        ));

        // Truncated body is an io error.
        let mut short = 8u32.to_be_bytes().to_vec();
        short.extend_from_slice(b"abc");
        let mut cursor: &[u8] = &short;
        assert!(matches!(
            read_frame(&mut cursor, 1024).await,
            Err(ProtocolError::Io(_))
        ));

        // write_frame refuses an oversize payload.
        let mut out = Vec::new();
        assert!(matches!(
            write_frame(&mut out, &[0u8; 20], 16).await,
            Err(ProtocolError::FrameTooLarge { len: 20, limit: 16 })
        ));
        assert!(out.is_empty());
    }

    #[test]
    fn request_fits_in_request_frame_limit() {
        use crate::capabilities::{CapabilityClaims, CapabilityToken};
        let owner = crate::crypto::generate_signing_key();
        let token = CapabilityToken::issue(
            CapabilityClaims {
                doc_id: [1u8; 32],
                audience: [2u8; 32],
                can_read: true,
                can_write: true,
                not_before: u64::MAX / 2,
                expires_at: u64::MAX,
            },
            &owner,
        );
        let req = Request::GetChunk {
            token,
            doc_id: [1u8; 32],
            hash: [3u8; 32],
        };
        let bytes = encode(&req, REQUEST_FRAME_LIMIT).unwrap();
        assert!(bytes.len() < 400, "{}", bytes.len());
        let back: Request = decode(&bytes, REQUEST_FRAME_LIMIT).unwrap();
        assert_eq!(back, req);
    }

    #[test]
    fn decode_limits_inner_allocation_claims() {
        // A varint length prefix claiming a huge Vec must fail on the size
        // limit, not attempt an allocation.
        let mut bytes = Vec::new();
        // bincode varint: 253 marker + u64 LE for lengths > u32::MAX
        bytes.push(253);
        bytes.extend_from_slice(&u64::MAX.to_le_bytes());
        assert!(decode::<Vec<u8>>(&bytes, 64).is_err());
        // A claim just above CODEC_LIMIT fails inside bincode even when the
        // caller's limit would allow it.
        let mut bytes = Vec::new();
        bytes.push(252);
        bytes.extend_from_slice(&((CODEC_LIMIT as u32) + 1).to_le_bytes());
        assert!(decode::<Vec<u8>>(&bytes, usize::MAX).is_err());
    }
}
