//! Stage 6: signed announcements over a real iroh-gossip topic on loopback.

mod common;

use common::*;
use p2p_sync_poc::capabilities::AuthError;
use p2p_sync_poc::clock::{physical_now_ms, unix_now_secs, Hlc};
use p2p_sync_poc::crypto::{derive_topic_id, random_bytes32};
use p2p_sync_poc::gossip::{validate_message, GossipError, LruSet, SyncMessage, TopicSubscription};
use p2p_sync_poc::Hash;

/// Receive the next announcement and require it to validate.
async fn next_valid(
    sub: &mut TopicSubscription,
    doc: &Doc,
    seen: &mut LruSet<p2p_sync_poc::gossip::DedupKey>,
) -> SyncMessage {
    let raw = with_timeout(sub.next_announcement())
        .await
        .expect("subscription ended")
        .expect("gossip stream error");
    validate_message(
        &raw.bytes,
        &doc.id,
        &doc.owner_pub,
        unix_now_secs(),
        physical_now_ms(),
        seen,
    )
    .unwrap_or_else(|e| panic!("unexpected invalid announcement: {e}"))
}

#[tokio::test]
async fn two_nodes_join_one_topic_and_exchange_signed_announcements() {
    let a = TestNode::spawn().await;
    let b = TestNode::spawn().await;
    a.know(&b);
    b.know(&a);
    let doc = Doc::new();
    let salt = random_bytes32();
    let topic: Hash = derive_topic_id(&salt, &doc.id);

    let mut sub_a = a.gossip.subscribe(topic, vec![]).await.unwrap();
    let mut sub_b = b.gossip.subscribe(topic, vec![a.id()]).await.unwrap();
    with_timeout(sub_b.joined()).await.unwrap();
    with_timeout(sub_a.joined()).await.unwrap();
    assert!(sub_a.neighbors().contains(&b.id()));
    assert!(sub_b.neighbors().contains(&a.id()));

    // A announces a version with its write token.
    let manifest_id = [7u8; 32];
    let version = SyncMessage::new_version(
        a.secret(),
        doc.id,
        manifest_id,
        None,
        Hlc::new(physical_now_ms(), 0),
        doc.token(a.id_bytes(), true, true),
    );
    with_timeout(sub_a.broadcast(&version)).await.unwrap();

    let mut seen_b = LruSet::default();
    let got = next_valid(&mut sub_b, &doc, &mut seen_b).await;
    assert_eq!(got, version);
    assert_eq!(got.version_id(), version.version_id());

    // B answers with Have under its read token; A validates it.
    let have = SyncMessage::have(
        b.secret(),
        doc.id,
        manifest_id,
        doc.token(b.id_bytes(), true, false),
    );
    with_timeout(sub_b.broadcast(&have)).await.unwrap();
    let mut seen_a = LruSet::default();
    let got = next_valid(&mut sub_a, &doc, &mut seen_a).await;
    assert_eq!(got, have);

    a.shutdown().await;
    b.shutdown().await;
}

/// Gossip delivers whatever a member sends; the receiver's own validation is
/// what rejects a version announced with a read-only token (SEC-6).
#[tokio::test]
async fn receiver_validates_independently_of_the_gossip_layer() {
    let a = TestNode::spawn().await;
    let b = TestNode::spawn().await;
    a.know(&b);
    b.know(&a);
    let doc = Doc::new();
    let topic = derive_topic_id(&random_bytes32(), &doc.id);
    let sub_a = a.gossip.subscribe(topic, vec![]).await.unwrap();
    let mut sub_b = b.gossip.subscribe(topic, vec![a.id()]).await.unwrap();
    with_timeout(sub_b.joined()).await.unwrap();

    let bad = SyncMessage::new_version(
        a.secret(),
        doc.id,
        [1u8; 32],
        None,
        Hlc::new(physical_now_ms(), 0),
        doc.token(a.id_bytes(), true, false), // read-only
    );
    with_timeout(sub_a.broadcast(&bad)).await.unwrap();
    let raw = with_timeout(sub_b.next_announcement())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(raw.delivered_from, a.id());
    let err = validate_message(
        &raw.bytes,
        &doc.id,
        &doc.owner_pub,
        unix_now_secs(),
        physical_now_ms(),
        &mut LruSet::default(),
    )
    .unwrap_err();
    assert!(
        matches!(err, GossipError::Token(AuthError::InsufficientPermission)),
        "{err:?}"
    );

    // A message for another document on this topic is dropped too.
    let other = Doc::new();
    let foreign = SyncMessage::have(
        a.secret(),
        other.id,
        [2u8; 32],
        other.token(a.id_bytes(), true, false),
    );
    with_timeout(sub_a.broadcast(&foreign)).await.unwrap();
    let raw = with_timeout(sub_b.next_announcement())
        .await
        .unwrap()
        .unwrap();
    let err = validate_message(
        &raw.bytes,
        &doc.id,
        &doc.owner_pub,
        unix_now_secs(),
        physical_now_ms(),
        &mut LruSet::default(),
    )
    .unwrap_err();
    assert!(matches!(err, GossipError::WrongDocument), "{err:?}");

    a.shutdown().await;
    b.shutdown().await;
}

/// Three nodes in a chain: C only bootstraps from B, yet receives A's
/// announcement through gossip relay, and validates it against A's
/// signature rather than trusting B.
#[tokio::test]
async fn announcement_relays_through_an_intermediate_node() {
    let a = TestNode::spawn().await;
    let b = TestNode::spawn().await;
    let c = TestNode::spawn().await;
    a.know(&b);
    b.know(&a);
    b.know(&c);
    c.know(&b);
    let doc = Doc::new();
    let topic = derive_topic_id(&random_bytes32(), &doc.id);

    let sub_a = a.gossip.subscribe(topic, vec![]).await.unwrap();
    let mut sub_b = b.gossip.subscribe(topic, vec![a.id()]).await.unwrap();
    with_timeout(sub_b.joined()).await.unwrap();
    let mut sub_c = c.gossip.subscribe(topic, vec![b.id()]).await.unwrap();
    with_timeout(sub_c.joined()).await.unwrap();

    let version = SyncMessage::new_version(
        a.secret(),
        doc.id,
        [9u8; 32],
        Some([8u8; 32]),
        Hlc::new(physical_now_ms(), 3),
        doc.token(a.id_bytes(), true, true),
    );
    with_timeout(sub_a.broadcast(&version)).await.unwrap();

    let mut seen_c = LruSet::default();
    let got = next_valid(&mut sub_c, &doc, &mut seen_c).await;
    assert_eq!(got, version);
    assert_eq!(*got.signer(), a.id_bytes());
    let mut seen_b = LruSet::default();
    let got_b = next_valid(&mut sub_b, &doc, &mut seen_b).await;
    assert_eq!(got_b, version);

    a.shutdown().await;
    b.shutdown().await;
    c.shutdown().await;
}
