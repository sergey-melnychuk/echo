//! [`SyncMessage`], announcement signing and verification, and the gossip topic
//! subscription wrapper (SEC-6).
//!
//! Gossip announces that a new version exists or that a peer can serve a
//! manifest; it never carries file bytes. Every message is signed by its
//! sender's endpoint key and carries the sender's token, so a receiver
//! validates it with [`validate_message`] without trusting the peers that
//! relayed it. Gossip forwards messages before this code sees them, so every
//! node validates independently.

use crate::capabilities::{AuthError, CapabilityToken, Permission};
use crate::clock::{Hlc, MAX_DRIFT_MS};
use crate::crypto::{self, short_hex};
use crate::protocol::{self, ProtocolError, GOSSIP_FRAME_LIMIT};
use crate::{Hash, VersionId};
use bytes::Bytes;
use ed25519_dalek::Signature;
use futures_lite::StreamExt;
use iroh::{Endpoint, EndpointId, SecretKey};
use iroh_gossip::api::{Event, GossipReceiver, GossipSender};
use iroh_gossip::net::Gossip;
use iroh_gossip::TopicId;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::hash::Hash as StdHash;
use tracing::{debug, trace};

/// Domain separator prefixed to every signed announcement payload.
pub const MSG_DOMAIN: &[u8] = b"p2p-sync-poc/msg/v1";

/// Sign with an endpoint key and return the wire (`ed25519_dalek`) signature.
/// iroh has its own `Signature` type with the same 64-byte encoding.
pub fn sign_with_endpoint_key(key: &SecretKey, payload: &[u8]) -> Signature {
    Signature::from_bytes(&key.sign(payload).to_bytes())
}

/// Verify a wire signature under an endpoint identity.
pub fn verify_with_endpoint_id(
    id: &EndpointId,
    payload: &[u8],
    signature: &Signature,
) -> Result<(), GossipError> {
    id.verify(payload, &iroh::Signature::from_bytes(&signature.to_bytes()))
        .map_err(|_| GossipError::InvalidSignature)
}
/// Number of recently handled message keys remembered for de-duplication.
pub const DEDUP_CAPACITY: usize = 4_096;

/// An announcement on a document's gossip topic. Never carries file bytes.
///
/// Both variants are signed by their sender's endpoint key and carry the
/// sender's token, so any receiver validates them without trusting relays.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum SyncMessage {
    /// A signed version of a file, built on `parent`.
    NewVersion {
        /// The document.
        doc_id: Hash,
        /// Manifest of this version's content.
        manifest_id: Hash,
        /// Version this one was built on. `None` only when the file is created.
        parent: Option<VersionId>,
        /// Commit time on the author's hybrid logical clock.
        hlc: Hlc,
        /// `NodeId` of the signer.
        author: [u8; 32],
        /// Needs `can_write`, audience equal to `author`.
        token: CapabilityToken,
        /// Over the signing payload, by the author's endpoint key.
        signature: Signature,
    },
    /// The sender holds this manifest and all its chunks, and can serve them.
    Have {
        /// The document.
        doc_id: Hash,
        /// The manifest held.
        manifest_id: Hash,
        /// `NodeId` of the signer.
        provider: [u8; 32],
        /// Needs `can_read`, audience equal to `provider`.
        token: CapabilityToken,
        /// Over the signing payload, by the provider's endpoint key.
        signature: Signature,
    },
}

impl SyncMessage {
    /// Build and sign a `NewVersion` with this node's endpoint key.
    /// `token` must be this node's write token; validation on the receiver
    /// requires `token.audience == author`.
    pub fn new_version(
        key: &SecretKey,
        doc_id: Hash,
        manifest_id: Hash,
        parent: Option<VersionId>,
        hlc: Hlc,
        token: CapabilityToken,
    ) -> Self {
        let mut msg = SyncMessage::NewVersion {
            doc_id,
            manifest_id,
            parent,
            hlc,
            author: *key.public().as_bytes(),
            token,
            signature: Signature::from_bytes(&[0u8; 64]),
        };
        let sig = sign_with_endpoint_key(key, &msg.signing_payload());
        if let SyncMessage::NewVersion { signature, .. } = &mut msg {
            *signature = sig;
        }
        msg
    }

    /// Build and sign a `Have` with this node's endpoint key. `token` must be
    /// this node's read token.
    pub fn have(key: &SecretKey, doc_id: Hash, manifest_id: Hash, token: CapabilityToken) -> Self {
        let mut msg = SyncMessage::Have {
            doc_id,
            manifest_id,
            provider: *key.public().as_bytes(),
            token,
            signature: Signature::from_bytes(&[0u8; 64]),
        };
        let sig = sign_with_endpoint_key(key, &msg.signing_payload());
        if let SyncMessage::Have { signature, .. } = &mut msg {
            *signature = sig;
        }
        msg
    }

    /// The document the message is about.
    pub fn doc_id(&self) -> &Hash {
        match self {
            SyncMessage::NewVersion { doc_id, .. } | SyncMessage::Have { doc_id, .. } => doc_id,
        }
    }

    /// The manifest the message names.
    pub fn manifest_id(&self) -> &Hash {
        match self {
            SyncMessage::NewVersion { manifest_id, .. } | SyncMessage::Have { manifest_id, .. } => {
                manifest_id
            }
        }
    }

    /// `NodeId` of the peer that signed the message.
    pub fn signer(&self) -> &[u8; 32] {
        match self {
            SyncMessage::NewVersion { author, .. } => author,
            SyncMessage::Have { provider, .. } => provider,
        }
    }

    /// The token the sender attached.
    pub fn token(&self) -> &CapabilityToken {
        match self {
            SyncMessage::NewVersion { token, .. } | SyncMessage::Have { token, .. } => token,
        }
    }

    /// The signature the sender attached.
    pub fn signature(&self) -> &Signature {
        match self {
            SyncMessage::NewVersion { signature, .. } | SyncMessage::Have { signature, .. } => {
                signature
            }
        }
    }

    /// The permission the sender must hold: write to publish a version, read
    /// to advertise a copy.
    pub fn required_permission(&self) -> Permission {
        match self {
            SyncMessage::NewVersion { .. } => Permission::Write,
            SyncMessage::Have { .. } => Permission::Read,
        }
    }

    /// The version this message defines, for `NewVersion`; `None` for `Have`.
    pub fn version_id(&self) -> Option<VersionId> {
        match self {
            SyncMessage::NewVersion {
                doc_id,
                manifest_id,
                parent,
                hlc,
                author,
                ..
            } => Some(crypto::version_id(
                doc_id,
                manifest_id,
                parent.as_ref(),
                *hlc,
                author,
            )),
            SyncMessage::Have { .. } => None,
        }
    }

    /// The bytes that are signed: [`MSG_DOMAIN`] ‖ variant tag (0 for
    /// `NewVersion`, 1 for `Have`) ‖ every field except `token` and
    /// `signature`, in declared order. `parent` is a presence byte followed
    /// by the ID if present; `hlc` is its fixed 12-byte encoding.
    pub fn signing_payload(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(MSG_DOMAIN.len() + 1 + 32 + 32 + 33 + 12 + 32);
        out.extend_from_slice(MSG_DOMAIN);
        match self {
            SyncMessage::NewVersion {
                doc_id,
                manifest_id,
                parent,
                hlc,
                author,
                ..
            } => {
                out.push(0);
                out.extend_from_slice(doc_id);
                out.extend_from_slice(manifest_id);
                match parent {
                    Some(p) => {
                        out.push(1);
                        out.extend_from_slice(p);
                    }
                    None => out.push(0),
                }
                out.extend_from_slice(&hlc.to_bytes());
                out.extend_from_slice(author);
            }
            SyncMessage::Have {
                doc_id,
                manifest_id,
                provider,
                ..
            } => {
                out.push(1);
                out.extend_from_slice(doc_id);
                out.extend_from_slice(manifest_id);
                out.extend_from_slice(provider);
            }
        }
        out
    }

    /// SEC-6: check the signature under the signer's `NodeId`.
    pub fn verify_signature(&self) -> Result<(), GossipError> {
        let signer =
            EndpointId::from_bytes(self.signer()).map_err(|_| GossipError::InvalidSigner)?;
        verify_with_endpoint_id(&signer, &self.signing_payload(), self.signature())
    }

    /// The key used to detect a message that was handled already: the
    /// `VersionId` for `NewVersion`, (`manifest_id`, signer) for `Have`.
    pub fn dedup_key(&self) -> DedupKey {
        match self {
            SyncMessage::NewVersion { .. } => {
                // A NewVersion always has a version id.
                DedupKey::Version(self.version_id().unwrap_or([0u8; 32]))
            }
            SyncMessage::Have {
                manifest_id,
                provider,
                ..
            } => DedupKey::Have(*manifest_id, *provider),
        }
    }

    /// Encode for broadcast, refusing anything over the gossip frame limit.
    pub fn encode(&self) -> Result<Vec<u8>, GossipError> {
        Ok(protocol::encode(self, GOSSIP_FRAME_LIMIT)?)
    }
}

/// De-duplication key of a message (section 7, check 6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, StdHash)]
pub enum DedupKey {
    /// A `NewVersion`, by its version ID.
    Version(VersionId),
    /// A `Have`, by manifest and signer.
    Have(Hash, [u8; 32]),
}

/// Why an announcement was dropped. Logged at `debug`; never sent to peers.
#[derive(Debug, thiserror::Error)]
pub enum GossipError {
    /// The frame exceeds [`GOSSIP_FRAME_LIMIT`] (check 1).
    #[error("gossip message of {0} bytes exceeds the {GOSSIP_FRAME_LIMIT} byte limit")]
    Oversize(usize),
    /// The frame does not decode (check 1).
    #[error("gossip message does not decode: {0}")]
    Decode(String),
    /// The message names another document (check 2).
    #[error("gossip message is for another document")]
    WrongDocument,
    /// The attached token failed `verify` or `authorize` (check 3).
    #[error("gossip message token rejected: {0}")]
    Token(#[from] AuthError),
    /// The signer bytes are not a valid public key (check 4).
    #[error("gossip message signer is not a valid public key")]
    InvalidSigner,
    /// The signature does not verify under the signer (check 4, SEC-6).
    #[error("gossip message signature is invalid")]
    InvalidSignature,
    /// The `hlc` is more than 5 minutes ahead of local time (check 5).
    #[error(
        "gossip message clock {remote_wall_ms} ms is too far ahead of local {physical_now_ms} ms"
    )]
    ClockTooFarAhead {
        /// The message's `hlc.wall_ms`.
        remote_wall_ms: u64,
        /// Local physical time.
        physical_now_ms: u64,
    },
    /// The message was handled already (check 6).
    #[error("gossip message was handled already")]
    Duplicate,
    /// Subscribing to or leaving a topic failed.
    #[error("gossip subscription failed: {0}")]
    Subscribe(String),
    /// Broadcasting failed.
    #[error("gossip broadcast failed: {0}")]
    Broadcast(String),
    /// The gossip event stream ended or lagged past recovery.
    #[error("gossip stream error: {0}")]
    Stream(String),
}

impl From<ProtocolError> for GossipError {
    fn from(e: ProtocolError) -> Self {
        match e {
            ProtocolError::FrameTooLarge { len, .. } => GossipError::Oversize(len),
            other => GossipError::Decode(other.to_string()),
        }
    }
}

/// Run the six receiver checks from section 7 in order and return the
/// message if all pass. `now_secs` is for the token window, `physical_now_ms`
/// for the clock drift check, and `seen` is this topic's de-duplication set.
///
/// Parent and ordering checks are not made here: they need the local version
/// chain and belong to the apply rules in `sync.rs`.
pub fn validate_message(
    bytes: &[u8],
    doc_id: &Hash,
    owner_key: &[u8; 32],
    now_secs: u64,
    physical_now_ms: u64,
    seen: &mut LruSet<DedupKey>,
) -> Result<SyncMessage, GossipError> {
    // 1. Size and decoding.
    if bytes.len() > GOSSIP_FRAME_LIMIT {
        return Err(GossipError::Oversize(bytes.len()));
    }
    let msg: SyncMessage = protocol::decode(bytes, GOSSIP_FRAME_LIMIT)?;
    // 2 to 5.
    validate_decoded(&msg, doc_id, owner_key, now_secs, physical_now_ms)?;
    // 6. Not handled already.
    if !seen.insert(msg.dedup_key()) {
        return Err(GossipError::Duplicate);
    }
    Ok(msg)
}

/// Checks 2 to 5 of section 7 on an already decoded message: document,
/// token (trusted issuer, window, scope, audience, permission), signature
/// under the signer's `NodeId`, and clock drift for versions. Used for
/// gossip frames after decoding and for `GetHeads` / `GetVersion` results,
/// which must be validated exactly like live announcements.
pub fn validate_decoded(
    msg: &SyncMessage,
    doc_id: &Hash,
    owner_key: &[u8; 32],
    now_secs: u64,
    physical_now_ms: u64,
) -> Result<(), GossipError> {
    if msg.doc_id() != doc_id {
        return Err(GossipError::WrongDocument);
    }
    let token = msg.token();
    token.verify(owner_key, now_secs)?;
    token.authorize(doc_id, msg.signer(), msg.required_permission())?;
    msg.verify_signature()?;
    if let SyncMessage::NewVersion { hlc, .. } = msg {
        if hlc.wall_ms > physical_now_ms.saturating_add(MAX_DRIFT_MS) {
            return Err(GossipError::ClockTooFarAhead {
                remote_wall_ms: hlc.wall_ms,
                physical_now_ms,
            });
        }
    }
    Ok(())
}

/// A bounded set that forgets its least recently seen keys. `insert` of a
/// present key refreshes it and reports a duplicate.
#[derive(Debug)]
pub struct LruSet<K> {
    capacity: usize,
    next: u64,
    by_key: HashMap<K, u64>,
    by_age: BTreeMap<u64, K>,
}

impl<K: Clone + Eq + StdHash> LruSet<K> {
    /// An empty set holding at most `capacity` keys (at least 1).
    pub fn new(capacity: usize) -> Self {
        LruSet {
            capacity: capacity.max(1),
            next: 0,
            by_key: HashMap::new(),
            by_age: BTreeMap::new(),
        }
    }

    /// Insert `key`. Returns `true` if it was new, `false` if it was already
    /// present (in which case it becomes the most recently seen).
    pub fn insert(&mut self, key: K) -> bool {
        let seq = self.next;
        self.next += 1;
        if let Some(old) = self.by_key.insert(key.clone(), seq) {
            self.by_age.remove(&old);
            self.by_age.insert(seq, key);
            return false;
        }
        self.by_age.insert(seq, key);
        while self.by_key.len() > self.capacity {
            if let Some((_, oldest)) = self.by_age.pop_first() {
                self.by_key.remove(&oldest);
            }
        }
        true
    }

    /// Whether `key` is present. Does not refresh it.
    pub fn contains(&self, key: &K) -> bool {
        self.by_key.contains_key(key)
    }

    /// Number of keys held.
    pub fn len(&self) -> usize {
        self.by_key.len()
    }

    /// Whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.by_key.is_empty()
    }
}

impl Default for LruSet<DedupKey> {
    fn default() -> Self {
        LruSet::new(DEDUP_CAPACITY)
    }
}

// ---------------------------------------------------------------------------
// Subscription wrapper over iroh-gossip
// ---------------------------------------------------------------------------

/// The gossip actor for one endpoint. Register [`GossipNode::handler`] on the
/// router under [`GossipNode::alpn`] alongside the sync protocol.
#[derive(Debug, Clone)]
pub struct GossipNode {
    gossip: Gossip,
}

impl GossipNode {
    /// Spawn the gossip actor on `endpoint`.
    pub fn spawn(endpoint: Endpoint) -> Self {
        let gossip = Gossip::builder().spawn(endpoint);
        GossipNode { gossip }
    }

    /// The ALPN to register the handler under.
    pub fn alpn() -> &'static [u8] {
        iroh_gossip::ALPN
    }

    /// The protocol handler for the router.
    pub fn handler(&self) -> Gossip {
        self.gossip.clone()
    }

    /// Subscribe to a document topic, dialing `bootstrap` peers (their
    /// addresses must be in the endpoint's address book). Returns at once;
    /// use [`TopicSubscription::joined`] to wait for a neighbor.
    pub async fn subscribe(
        &self,
        topic: Hash,
        bootstrap: Vec<EndpointId>,
    ) -> Result<TopicSubscription, GossipError> {
        let sub = self
            .gossip
            .subscribe(TopicId::from_bytes(topic), bootstrap)
            .await
            .map_err(|e| GossipError::Subscribe(e.to_string()))?;
        let (sender, receiver) = sub.split();
        Ok(TopicSubscription {
            topic,
            sender,
            receiver,
        })
    }

    /// Stop the gossip actor.
    pub async fn shutdown(&self) {
        if let Err(e) = self.gossip.shutdown().await {
            debug!("gossip shutdown: {e}");
        }
    }
}

/// A raw announcement received on a topic, before validation.
#[derive(Debug, Clone)]
pub struct RawAnnouncement {
    /// The encoded [`SyncMessage`].
    pub bytes: Bytes,
    /// The neighbor that delivered it. Not the author: gossip relays.
    pub delivered_from: EndpointId,
}

/// One node's membership in one document topic.
pub struct TopicSubscription {
    topic: Hash,
    sender: GossipSender,
    receiver: GossipReceiver,
}

impl TopicSubscription {
    /// The topic ID.
    pub fn topic(&self) -> &Hash {
        &self.topic
    }

    /// Wait until at least one neighbor is connected.
    pub async fn joined(&mut self) -> Result<(), GossipError> {
        self.receiver
            .joined()
            .await
            .map_err(|e| GossipError::Subscribe(e.to_string()))
    }

    /// Current neighbors on this topic.
    pub fn neighbors(&self) -> Vec<EndpointId> {
        self.receiver.neighbors().collect()
    }

    /// Encode and broadcast a signed message to the topic.
    pub async fn broadcast(&self, msg: &SyncMessage) -> Result<(), GossipError> {
        let bytes = msg.encode()?;
        trace!(topic = %short_hex(&self.topic), len = bytes.len(), "broadcast");
        self.sender
            .broadcast(Bytes::from(bytes))
            .await
            .map_err(|e| GossipError::Broadcast(e.to_string()))
    }

    /// The next announcement delivered on this topic. Membership events are
    /// logged and skipped. `None` when the subscription has ended.
    pub async fn next_announcement(&mut self) -> Option<Result<RawAnnouncement, GossipError>> {
        loop {
            match self.receiver.next().await? {
                Ok(Event::Received(m)) => {
                    return Some(Ok(RawAnnouncement {
                        bytes: m.content,
                        delivered_from: m.delivered_from,
                    }));
                }
                Ok(Event::NeighborUp(id)) => {
                    debug!(topic = %short_hex(&self.topic), peer = %id.fmt_short(), "neighbor up");
                }
                Ok(Event::NeighborDown(id)) => {
                    debug!(topic = %short_hex(&self.topic), peer = %id.fmt_short(), "neighbor down");
                }
                Ok(Event::Lagged) => {
                    debug!(topic = %short_hex(&self.topic), "gossip receiver lagged; messages dropped");
                }
                Err(e) => return Some(Err(GossipError::Stream(e.to_string()))),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capabilities::CapabilityClaims;
    use crate::crypto::generate_signing_key;
    use ed25519_dalek::SigningKey;

    const DOC: Hash = [1u8; 32];
    const MAN: Hash = [2u8; 32];
    const NOW: u64 = 1_700_000_000;
    const NOW_MS: u64 = NOW * 1000;

    struct Owner {
        key: SigningKey,
        pubkey: [u8; 32],
    }

    fn owner() -> Owner {
        let key = generate_signing_key();
        let pubkey = key.verifying_key().to_bytes();
        Owner { key, pubkey }
    }

    fn token(owner: &Owner, audience: [u8; 32], read: bool, write: bool) -> CapabilityToken {
        CapabilityToken::issue(
            CapabilityClaims {
                doc_id: DOC,
                audience,
                can_read: read,
                can_write: write,
                not_before: NOW - 10,
                expires_at: NOW + 10,
            },
            &owner.key,
        )
    }

    fn peer() -> SecretKey {
        SecretKey::generate()
    }

    fn validate(bytes: &[u8], owner: &Owner) -> Result<SyncMessage, GossipError> {
        validate_message(
            bytes,
            &DOC,
            &owner.pubkey,
            NOW,
            NOW_MS,
            &mut LruSet::default(),
        )
    }

    fn new_version(owner: &Owner, key: &SecretKey) -> SyncMessage {
        let t = token(owner, *key.public().as_bytes(), true, true);
        SyncMessage::new_version(key, DOC, MAN, Some([3u8; 32]), Hlc::new(NOW_MS, 1), t)
    }

    fn have(owner: &Owner, key: &SecretKey) -> SyncMessage {
        let t = token(owner, *key.public().as_bytes(), true, false);
        SyncMessage::have(key, DOC, MAN, t)
    }

    #[test]
    fn sign_verify_round_trip_for_both_variants() {
        let o = owner();
        let k = peer();
        for msg in [new_version(&o, &k), have(&o, &k)] {
            msg.verify_signature().unwrap();
            let bytes = msg.encode().unwrap();
            assert!(bytes.len() <= GOSSIP_FRAME_LIMIT, "{}", bytes.len());
            let back = validate(&bytes, &o).unwrap();
            assert_eq!(back, msg);
        }
    }

    /// SEC-6: changing any signed field, including `parent` and `hlc`, or
    /// swapping in another peer's token, fails.
    #[test]
    fn sec6_any_signed_field_change_or_foreign_token_fails() {
        let o = owner();
        let k = peer();
        let other = peer();
        let base = new_version(&o, &k);

        let mut cases: Vec<(&str, SyncMessage)> = Vec::new();
        macro_rules! mutate {
            ($name:expr, |$m:ident| $body:block) => {{
                let mut m = base.clone();
                if let SyncMessage::NewVersion {
                    doc_id: _doc_id,
                    manifest_id: _manifest_id,
                    parent: _parent,
                    hlc: _hlc,
                    author: _author,
                    token: _token,
                    signature: _signature,
                } = &mut m
                {
                    let $m = (
                        _doc_id,
                        _manifest_id,
                        _parent,
                        _hlc,
                        _author,
                        _token,
                        _signature,
                    );
                    $body
                }
                cases.push(($name, m));
            }};
        }
        mutate!("manifest", |f| {
            f.1[0] ^= 1;
        });
        mutate!("parent flip", |f| {
            *f.2 = None;
        });
        mutate!("parent byte", |f| {
            *f.2 = Some([4u8; 32]);
        });
        mutate!("hlc wall", |f| {
            f.3.wall_ms += 1;
        });
        mutate!("hlc counter", |f| {
            f.3.counter += 1;
        });
        mutate!("author", |f| {
            *f.4 = *other.public().as_bytes();
        });
        mutate!("signature", |f| {
            let mut b = f.6.to_bytes();
            b[3] ^= 1;
            *f.6 = Signature::from_bytes(&b);
        });
        for (name, m) in cases {
            let bytes = m.encode().unwrap();
            let err = validate(&bytes, &o).unwrap_err();
            assert!(
                matches!(
                    err,
                    GossipError::InvalidSignature | GossipError::Token(AuthError::WrongAudience)
                ),
                "{name}: {err:?}"
            );
        }

        // Another peer's (valid) write token swapped in: the token's audience
        // is not the signer, so check 3 fails before the signature is looked at.
        let mut swapped = base.clone();
        if let SyncMessage::NewVersion { token: t, .. } = &mut swapped {
            *t = token(&o, *other.public().as_bytes(), true, true);
        }
        let err = validate(&swapped.encode().unwrap(), &o).unwrap_err();
        assert!(
            matches!(err, GossipError::Token(AuthError::WrongAudience)),
            "{err:?}"
        );

        // A message re-signed by another peer but still claiming the original
        // author fails on the signature.
        let mut resigned = base.clone();
        let payload = resigned.signing_payload();
        if let SyncMessage::NewVersion { signature, .. } = &mut resigned {
            *signature = sign_with_endpoint_key(&other, &payload);
        }
        let err = validate(&resigned.encode().unwrap(), &o).unwrap_err();
        assert!(matches!(err, GossipError::InvalidSignature), "{err:?}");

        // Have: changing the manifest or provider breaks it too.
        let h = have(&o, &k);
        let mut bad = h.clone();
        if let SyncMessage::Have { manifest_id, .. } = &mut bad {
            manifest_id[5] ^= 1;
        }
        assert!(matches!(
            validate(&bad.encode().unwrap(), &o).unwrap_err(),
            GossipError::InvalidSignature
        ));
    }

    #[test]
    fn new_version_with_read_only_token_is_rejected_and_have_needs_read() {
        let o = owner();
        let k = peer();
        let ro = token(&o, *k.public().as_bytes(), true, false);
        let m = SyncMessage::new_version(&k, DOC, MAN, None, Hlc::new(NOW_MS, 0), ro);
        let err = validate(&m.encode().unwrap(), &o).unwrap_err();
        assert!(
            matches!(err, GossipError::Token(AuthError::InsufficientPermission)),
            "{err:?}"
        );
        // Write-only token cannot announce Have.
        let wo = token(&o, *k.public().as_bytes(), false, true);
        let h = SyncMessage::have(&k, DOC, MAN, wo);
        let err = validate(&h.encode().unwrap(), &o).unwrap_err();
        assert!(
            matches!(err, GossipError::Token(AuthError::InsufficientPermission)),
            "{err:?}"
        );
    }

    #[test]
    fn other_document_oversize_and_far_future_are_rejected() {
        let o = owner();
        let k = peer();

        // Another document (signed correctly for it).
        let t = token(&o, *k.public().as_bytes(), true, true);
        let m = SyncMessage::new_version(&k, [9u8; 32], MAN, None, Hlc::new(NOW_MS, 0), t);
        assert!(matches!(
            validate(&m.encode().unwrap(), &o).unwrap_err(),
            GossipError::WrongDocument
        ));

        // Oversize frame is refused before decoding.
        let big = vec![0u8; GOSSIP_FRAME_LIMIT + 1];
        assert!(matches!(
            validate(&big, &o).unwrap_err(),
            GossipError::Oversize(len) if len == GOSSIP_FRAME_LIMIT + 1
        ));
        // Garbage within the limit fails to decode.
        assert!(matches!(
            validate(&[0xFFu8; 100], &o).unwrap_err(),
            GossipError::Decode(_)
        ));

        // Clock more than 5 minutes ahead; exactly 5 minutes is accepted.
        let t = token(&o, *k.public().as_bytes(), true, true);
        let edge = SyncMessage::new_version(
            &k,
            DOC,
            MAN,
            None,
            Hlc::new(NOW_MS + MAX_DRIFT_MS, 0),
            t.clone(),
        );
        validate(&edge.encode().unwrap(), &o).unwrap();
        let ahead = SyncMessage::new_version(
            &k,
            DOC,
            MAN,
            None,
            Hlc::new(NOW_MS + MAX_DRIFT_MS + 1, 0),
            t,
        );
        assert!(matches!(
            validate(&ahead.encode().unwrap(), &o).unwrap_err(),
            GossipError::ClockTooFarAhead { .. }
        ));

        // Token issued by someone other than the owner.
        let stranger = owner();
        let t = token(&stranger, *k.public().as_bytes(), true, true);
        let m = SyncMessage::new_version(&k, DOC, MAN, None, Hlc::new(NOW_MS, 0), t);
        assert!(matches!(
            validate(&m.encode().unwrap(), &o).unwrap_err(),
            GossipError::Token(AuthError::UntrustedIssuer)
        ));
        // Expired token.
        let t = CapabilityToken::issue(
            CapabilityClaims {
                doc_id: DOC,
                audience: *k.public().as_bytes(),
                can_read: true,
                can_write: true,
                not_before: 0,
                expires_at: NOW - 1000,
            },
            &o.key,
        );
        let m = SyncMessage::new_version(&k, DOC, MAN, None, Hlc::new(NOW_MS, 0), t);
        assert!(matches!(
            validate(&m.encode().unwrap(), &o).unwrap_err(),
            GossipError::Token(AuthError::Expired { .. })
        ));
    }

    #[test]
    fn lru_drops_repeated_version_and_repeated_have_pair() {
        let o = owner();
        let k = peer();
        let k2 = peer();
        let mut seen = LruSet::default();
        let v = new_version(&o, &k);
        let bytes = v.encode().unwrap();
        validate_message(&bytes, &DOC, &o.pubkey, NOW, NOW_MS, &mut seen).unwrap();
        assert!(matches!(
            validate_message(&bytes, &DOC, &o.pubkey, NOW, NOW_MS, &mut seen).unwrap_err(),
            GossipError::Duplicate
        ));
        // Same content re-signed (fresh signature bytes are identical for
        // Ed25519, but even a different encoding would share the VersionId).
        let again = new_version(&o, &k);
        assert!(matches!(
            validate_message(
                &again.encode().unwrap(),
                &DOC,
                &o.pubkey,
                NOW,
                NOW_MS,
                &mut seen
            )
            .unwrap_err(),
            GossipError::Duplicate
        ));

        let h = have(&o, &k);
        validate_message(
            &h.encode().unwrap(),
            &DOC,
            &o.pubkey,
            NOW,
            NOW_MS,
            &mut seen,
        )
        .unwrap();
        assert!(matches!(
            validate_message(
                &h.encode().unwrap(),
                &DOC,
                &o.pubkey,
                NOW,
                NOW_MS,
                &mut seen
            )
            .unwrap_err(),
            GossipError::Duplicate
        ));
        // Same manifest from a different provider is new.
        let h2 = have(&o, &k2);
        validate_message(
            &h2.encode().unwrap(),
            &DOC,
            &o.pubkey,
            NOW,
            NOW_MS,
            &mut seen,
        )
        .unwrap();
        // A Have never collides with a NewVersion.
        assert_ne!(v.dedup_key(), h.dedup_key());
    }

    #[test]
    fn lru_set_evicts_least_recently_seen() {
        let mut s = LruSet::new(3);
        assert!(s.insert(1));
        assert!(s.insert(2));
        assert!(s.insert(3));
        assert!(!s.insert(1)); // refresh 1
        assert!(s.insert(4)); // evicts 2, the least recently seen
        assert!(!s.contains(&2));
        assert!(s.contains(&1));
        assert!(s.contains(&3));
        assert!(s.contains(&4));
        assert_eq!(s.len(), 3);
        assert!(s.insert(2)); // 2 is new again; evicts 3
        assert!(!s.contains(&3));
        let mut big = LruSet::<u32>::new(DEDUP_CAPACITY);
        for i in 0..(DEDUP_CAPACITY as u32 + 10) {
            assert!(big.insert(i));
        }
        assert_eq!(big.len(), DEDUP_CAPACITY);
        assert!(!big.contains(&0));
        assert!(big.contains(&10));
    }

    #[test]
    fn signing_payload_layout() {
        let o = owner();
        let k = peer();
        let m = new_version(&o, &k);
        let p = m.signing_payload();
        assert_eq!(&p[..MSG_DOMAIN.len()], MSG_DOMAIN);
        let mut i = MSG_DOMAIN.len();
        assert_eq!(p[i], 0);
        i += 1;
        assert_eq!(&p[i..i + 32], &DOC);
        i += 32;
        assert_eq!(&p[i..i + 32], &MAN);
        i += 32;
        assert_eq!(p[i], 1);
        i += 1;
        assert_eq!(&p[i..i + 32], &[3u8; 32]);
        i += 32;
        assert_eq!(&p[i..i + 12], &Hlc::new(NOW_MS, 1).to_bytes());
        i += 12;
        assert_eq!(&p[i..i + 32], k.public().as_bytes());
        assert_eq!(p.len(), i + 32);

        let h = have(&o, &k);
        let p = h.signing_payload();
        assert_eq!(p[MSG_DOMAIN.len()], 1);
        assert_eq!(p.len(), MSG_DOMAIN.len() + 1 + 32 + 32 + 32);
    }
}
