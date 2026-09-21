//! Stage 10: the success criteria from SPEC section 1 with three nodes in one
//! process, plus the late joiner and a provider stopped mid-transfer.

mod common;

use common::*;
use iroh::EndpointId;
use p2p_sync_poc::capabilities::CapabilityToken;
use p2p_sync_poc::clock::{physical_now_ms, Hlc};
use p2p_sync_poc::crypto::random_bytes32;
use p2p_sync_poc::gossip::SyncMessage;
use p2p_sync_poc::protocol::ErrorCode;
use p2p_sync_poc::sync::{ApplyOutcome, PublishOutcome, SyncEvent};
use p2p_sync_poc::transport::{get_chunk, ServerMetrics, TransportError};
use p2p_sync_poc::VersionId;
use std::path::Path;
use std::time::{Duration, Instant};
use tokio::sync::broadcast;

const LONG: Duration = Duration::from_secs(90);

async fn wait_for_file(path: &Path, expected: &[u8], deadline: Duration) {
    let end = Instant::now() + deadline;
    loop {
        if let Ok(bytes) = std::fs::read(path) {
            if bytes == expected {
                return;
            }
        }
        assert!(
            Instant::now() < end,
            "timed out waiting for {}",
            path.display()
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn wait_for_head(
    h: &Harness,
    file: &str,
    pred: impl Fn(&VersionId) -> bool,
    deadline: Duration,
) -> VersionId {
    let end = Instant::now() + deadline;
    loop {
        if let Some(head) = h
            .node
            .store
            .head(&h.engine.ctx().doc_id, file)
            .expect("head")
        {
            if pred(&head.version_id) {
                return head.version_id;
            }
        }
        assert!(Instant::now() < end, "timed out waiting for head of {file}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// The `Applied` event for `version` on this receiver.
async fn wait_for_applied(
    rx: &mut broadcast::Receiver<SyncEvent>,
    version: VersionId,
    deadline: Duration,
) -> usize {
    tokio::time::timeout(deadline, async {
        loop {
            match rx.recv().await {
                Ok(SyncEvent::Applied {
                    version_id,
                    fetched_chunks,
                    ..
                }) if version_id == version => return fetched_chunks,
                Ok(_) => {}
                Err(broadcast::error::RecvError::Lagged(_)) => {}
                Err(e) => panic!("{e}"),
            }
        }
    })
    .await
    .expect("timed out waiting for Applied")
}

fn served(h: &Harness) -> u64 {
    ServerMetrics::get(&h.node.sync.metrics().chunks_served)
}

struct Net {
    doc: Doc,
    salt: [u8; 32],
    a: Harness,
    b: Harness,
    c: Harness,
}

/// Three nodes with write tokens, all mutually reachable, joined to one
/// topic, each with a running file watcher.
async fn three_nodes() -> Net {
    let doc = Doc::new();
    let salt = random_bytes32();
    let mut a = Harness::new(&doc, true).await;
    let mut b = Harness::new(&doc, true).await;
    let mut c = Harness::new(&doc, true).await;
    for (x, y) in [(&a, &b), (&a, &c), (&b, &a), (&b, &c), (&c, &a), (&c, &b)] {
        x.node.know(&y.node);
    }
    a.go_online(&salt, vec![]).await;
    b.go_online(&salt, vec![a.id()]).await;
    c.go_online(&salt, vec![a.id(), b.id()]).await;
    a.start_watcher();
    b.start_watcher();
    c.start_watcher();
    Net { doc, salt, a, b, c }
}

/// Success criteria 1 and 2: a 10 MiB file added on A appears byte-identical
/// on B and C; a one-byte mid-file edit makes each peer fetch at most 3
/// chunks plus the new manifest.
#[tokio::test]
async fn criterion_1_and_2_ten_mib_file_then_one_byte_edit() {
    let net = three_nodes().await;
    let mut ev_b = net.b.engine.subscribe_events();
    let mut ev_c = net.c.engine.subscribe_events();

    let data = seeded_bytes(1, 10 << 20);
    net.a.write("big.bin", &data);
    let v1 = wait_for_head(&net.a, "big.bin", |_| true, LONG).await;
    wait_for_file(&net.b.path("big.bin"), &data, LONG).await;
    wait_for_file(&net.c.path("big.bin"), &data, LONG).await;
    let first_b = wait_for_applied(&mut ev_b, v1, LONG).await;
    let first_c = wait_for_applied(&mut ev_c, v1, LONG).await;
    assert!(first_b > 300 && first_c > 300, "{first_b} {first_c}");

    let mut edited = data.clone();
    edited[5 << 20] ^= 0xFF;
    net.a.write("big.bin", &edited);
    let v2 = wait_for_head(&net.a, "big.bin", |id| *id != v1, LONG).await;
    let fetched_b = wait_for_applied(&mut ev_b, v2, LONG).await;
    let fetched_c = wait_for_applied(&mut ev_c, v2, LONG).await;
    assert!(fetched_b <= 3, "B fetched {fetched_b} chunks");
    assert!(fetched_c <= 3, "C fetched {fetched_c} chunks");
    wait_for_file(&net.b.path("big.bin"), &edited, LONG).await;
    wait_for_file(&net.c.path("big.bin"), &edited, LONG).await;

    net.a.shutdown().await;
    net.b.shutdown().await;
    net.c.shutdown().await;
}

/// Success criterion 3: forged, expired, wrong-audience, wrong-document and
/// read-only-for-write tokens are all rejected, and no chunk bytes are served.
#[tokio::test]
async fn criterion_3_bad_tokens_are_rejected_and_serve_nothing() {
    let net = three_nodes().await;
    let bytes = seeded_bytes(3, 80_000);
    let v = match with_timeout(net.a.engine.publish_local_change("t.bin", bytes.clone()))
        .await
        .unwrap()
    {
        PublishOutcome::Published(id) => id,
        other => panic!("{other:?}"),
    };
    wait_for_file(&net.b.path("t.bin"), &bytes, LONG).await;
    let manifest_id = *net
        .a
        .node
        .store
        .version(&net.doc.id, &v)
        .unwrap()
        .unwrap()
        .manifest_id();
    let manifest = net
        .a
        .node
        .store
        .get_manifest(&net.doc.id, &manifest_id)
        .unwrap()
        .unwrap();
    let hash = manifest.chunks[0].hash;

    // A stranger with several bad tokens.
    let d = TestNode::spawn().await;
    d.know(&net.a.node);
    let conn = with_timeout(d.pool.connect(net.a.id())).await.unwrap();
    let before = served(&net.a);
    let attacker = Doc::new();
    let mut claims = attacker.token(d.id_bytes(), true, true).claims;
    claims.doc_id = net.doc.id;
    let forged = CapabilityToken::issue(claims, &attacker.owner);
    let expired = net
        .doc
        .token_with_window(d.id_bytes(), true, false, 1_000, 2_000);
    let wrong_audience = net.doc.token(net.c.node.id_bytes(), true, true);
    // Issued by the real owner, but for a different document.
    let mut other_claims = net.doc.token(d.id_bytes(), true, true).claims;
    other_claims.doc_id = random_bytes32();
    let wrong_doc = CapabilityToken::issue(other_claims, &net.doc.owner);
    let cases: [(&str, CapabilityToken, ErrorCode); 4] = [
        ("forged", forged, ErrorCode::Unauthorized),
        ("expired", expired, ErrorCode::Unauthorized),
        ("wrong audience", wrong_audience, ErrorCode::Forbidden),
        ("wrong document", wrong_doc, ErrorCode::Forbidden),
    ];
    for (name, token, code) in cases {
        let err = with_timeout(get_chunk(&conn, &token, net.doc.id, hash))
            .await
            .unwrap_err();
        match err {
            TransportError::Remote(c) => assert_eq!(c, code, "{name}"),
            other => panic!("{name}: {other:?}"),
        }
    }
    assert_eq!(served(&net.a), before, "no chunk bytes may be served");

    // A read-only member announces a version: nobody applies it.
    let ro_token = net.doc.token(d.id_bytes(), true, false);
    let mut sub = d
        .gossip
        .subscribe(
            p2p_sync_poc::crypto::derive_topic_id(&net.salt, &net.doc.id),
            vec![net.a.id()],
        )
        .await
        .unwrap();
    with_timeout(sub.joined()).await.unwrap();
    let evil = SyncMessage::new_version(
        d.secret(),
        net.doc.id,
        [9u8; 32],
        None,
        Hlc::new(physical_now_ms(), 0),
        ro_token.clone(),
    );
    with_timeout(sub.broadcast(&evil)).await.unwrap();
    // Read access itself is fine for the read-only member.
    let ok = with_timeout(get_chunk(&conn, &ro_token, net.doc.id, hash))
        .await
        .unwrap();
    assert_eq!(ok.len(), manifest.chunks[0].length as usize);
    tokio::time::sleep(Duration::from_millis(1_500)).await;
    for h in [&net.a, &net.b, &net.c] {
        let heads = h.engine.heads().unwrap();
        assert_eq!(heads.len(), 1, "{heads:?}");
        assert_eq!(heads[0].0, "t.bin");
        assert!(h
            .node
            .store
            .version(&net.doc.id, &vid(&evil))
            .unwrap()
            .is_none());
    }
    d.shutdown().await;
    net.a.shutdown().await;
    net.b.shutdown().await;
    net.c.shutdown().await;
}

/// Success criterion 4: A and B edit the same file from the same version
/// while partitioned. After they reconnect all three nodes hold the version
/// with the smaller (hlc, author), the loser's bytes sit under
/// `.p2p-sync/rejected/` on the loser only, and the loser's next save on top
/// of the winner reaches everyone.
#[tokio::test]
async fn criterion_4_partitioned_edits_converge_and_loser_republishes() {
    let net = three_nodes().await;
    let base = seeded_bytes(4, 40_000);
    net.a.write("shared.txt", &base);
    let v0 = wait_for_head(&net.a, "shared.txt", |_| true, LONG).await;
    wait_for_file(&net.b.path("shared.txt"), &base, LONG).await;
    wait_for_file(&net.c.path("shared.txt"), &base, LONG).await;

    // Partition A and B from everyone.
    net.a.set_online(false);
    net.b.set_online(false);
    let edit_a = seeded_bytes(5, 40_000);
    let edit_b = seeded_bytes(6, 40_000);
    net.a.write("shared.txt", &edit_a);
    net.b.write("shared.txt", &edit_b);
    let va = wait_for_head(&net.a, "shared.txt", |id| *id != v0, LONG).await;
    let vb = wait_for_head(&net.b, "shared.txt", |id| *id != v0, LONG).await;
    assert_ne!(va, vb);
    let ha = net
        .a
        .node
        .store
        .head(&net.doc.id, "shared.txt")
        .unwrap()
        .unwrap();
    let hb = net
        .b
        .node
        .store
        .head(&net.doc.id, "shared.txt")
        .unwrap()
        .unwrap();
    let a_wins = (ha.hlc, ha.author) < (hb.hlc, hb.author);
    let (winner, loser_id, winner_bytes, loser_bytes) = if a_wins {
        (va, vb, &edit_a, &edit_b)
    } else {
        (vb, va, &edit_b, &edit_a)
    };
    // While partitioned nobody else has moved.
    assert_eq!(net.c.read("shared.txt"), base);

    // Reconnect: held announcements go out, and each side reconciles what it
    // missed through catch-up.
    net.a.set_online(true);
    net.b.set_online(true);
    with_timeout(net.a.engine.catch_up(net.b.id()))
        .await
        .unwrap();
    with_timeout(net.b.engine.catch_up(net.a.id()))
        .await
        .unwrap();
    for h in [&net.a, &net.b, &net.c] {
        wait_for_head(h, "shared.txt", |id| *id == winner, LONG).await;
        wait_for_file(&h.path("shared.txt"), winner_bytes, LONG).await;
        assert!(h.node.store.is_rejected(&net.doc.id, &loser_id).unwrap());
    }
    // `loser` is the node whose version lost.
    let (loser, win_node) = if a_wins {
        (&net.b, &net.a)
    } else {
        (&net.a, &net.b)
    };
    let kept = loser.rejected_files();
    assert_eq!(kept.len(), 1, "{kept:?}");
    assert_eq!(std::fs::read(&kept[0]).unwrap(), *loser_bytes);
    assert!(win_node.rejected_files().is_empty());
    assert!(net.c.rejected_files().is_empty());
    assert_eq!(loser.engine.rejections().len(), 1);
    assert!(win_node.engine.rejections().is_empty());

    // The loser's next save builds on the winner and reaches everyone.
    let merged = seeded_bytes(7, 40_000);
    loser.write("shared.txt", &merged);
    let v_next = wait_for_head(loser, "shared.txt", |id| *id != winner, LONG).await;
    let msg = loser
        .node
        .store
        .version(&net.doc.id, &v_next)
        .unwrap()
        .unwrap();
    assert!(matches!(msg, SyncMessage::NewVersion { parent, .. } if parent == Some(winner)));
    for h in [&net.a, &net.b, &net.c] {
        wait_for_file(&h.path("shared.txt"), &merged, LONG).await;
        wait_for_head(h, "shared.txt", |id| *id == v_next, LONG).await;
    }
    net.a.shutdown().await;
    net.b.shutdown().await;
    net.c.shutdown().await;
}

/// C joins after A and B have synced and catches up through GetHeads,
/// fetching from both.
#[tokio::test]
async fn late_joiner_catches_up_from_both_providers() {
    let doc = Doc::new();
    let salt = random_bytes32();
    let mut a = Harness::new(&doc, true).await;
    let mut b = Harness::new(&doc, true).await;
    a.node.know(&b.node);
    b.node.know(&a.node);
    a.go_online(&salt, vec![]).await;
    b.go_online(&salt, vec![a.id()]).await;
    let file_a = seeded_bytes(8, 300_000);
    let file_b = seeded_bytes(9, 300_000);
    with_timeout(a.engine.publish_local_change("from_a.bin", file_a.clone()))
        .await
        .unwrap();
    with_timeout(b.engine.publish_local_change("from_b.bin", file_b.clone()))
        .await
        .unwrap();
    wait_for_file(&a.path("from_b.bin"), &file_b, LONG).await;
    wait_for_file(&b.path("from_a.bin"), &file_a, LONG).await;

    let c = Harness::new(&doc, false).await;
    c.node.know(&a.node);
    c.node.know(&b.node);
    let (sa, sb) = (served(&a), served(&b));
    let applied = with_timeout(c.engine.catch_up(a.id())).await.unwrap();
    assert_eq!(applied, 2);
    assert_eq!(c.read("from_a.bin"), file_a);
    assert_eq!(c.read("from_b.bin"), file_b);
    assert!(served(&a) > sa, "A served chunks");
    assert!(served(&b) > sb, "B served chunks");
    a.shutdown().await;
    b.shutdown().await;
    c.shutdown().await;
}

/// A provider is stopped mid-transfer and the fetch still completes from
/// another.
#[tokio::test]
async fn provider_stopped_mid_transfer_is_replaced() {
    let doc = Doc::new();
    let salt = random_bytes32();
    let mut a = Harness::new(&doc, true).await;
    let mut b = Harness::new(&doc, true).await;
    a.node.know(&b.node);
    b.node.know(&a.node);
    a.go_online(&salt, vec![]).await;
    b.go_online(&salt, vec![a.id()]).await;
    let data = seeded_bytes(10, 3 << 20);
    with_timeout(a.engine.publish_local_change("big.bin", data.clone()))
        .await
        .unwrap();
    wait_for_file(&b.path("big.bin"), &data, LONG).await;
    let version = a.node.store.heads(&doc.id).unwrap().remove(0);

    let d = Harness::new(&doc, false).await;
    d.node.know(&a.node);
    d.node.know(&b.node);
    let (b_id, a_id): (EndpointId, EndpointId) = (b.id(), a.id());
    let stopper = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(30)).await;
        b.shutdown().await;
    });
    let r = tokio::time::timeout(LONG, d.engine.apply_remote(&version, &[b_id, a_id]))
        .await
        .expect("hung")
        .unwrap();
    assert!(matches!(r, ApplyOutcome::Applied { .. }), "{r:?}");
    assert_eq!(d.read("big.bin"), data);
    stopper.await.unwrap();
    a.shutdown().await;
    d.shutdown().await;
}
