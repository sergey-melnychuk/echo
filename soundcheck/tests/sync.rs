//! Stage 7: sync engine, parallel fetcher, fork and rejection rules over
//! loopback nodes.

mod common;

use common::*;
use iroh::{EndpointId, SecretKey};
use p2p_sync_poc::clock::Hlc;
use p2p_sync_poc::crypto::chunk_hash;
use p2p_sync_poc::gossip::SyncMessage;
use p2p_sync_poc::manifest::{ChunkRef, FileManifest, ManifestError};
use p2p_sync_poc::storage::{HeadInfo, MemStore, Store, StoreError};
use p2p_sync_poc::sync::{ApplyOutcome, PublishOutcome, RejectReason, SyncError, SyncEvent};
use p2p_sync_poc::transport::ServerMetrics;
use p2p_sync_poc::{Hash, VersionId};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// A store that serves wrong data on purpose: corrupt chunk bytes, or a
/// substitute manifest for one manifest ID. Everything else delegates.
struct Misbehaving {
    inner: MemStore,
    corrupt_chunks: bool,
    substitute: Option<(Hash, FileManifest)>,
}

impl Misbehaving {
    fn corrupt() -> Arc<dyn Store> {
        Arc::new(Misbehaving {
            inner: MemStore::new(),
            corrupt_chunks: true,
            substitute: None,
        })
    }

    fn substitute(id: Hash, manifest: FileManifest) -> Arc<dyn Store> {
        Arc::new(Misbehaving {
            inner: MemStore::new(),
            corrupt_chunks: false,
            substitute: Some((id, manifest)),
        })
    }
}

impl Store for Misbehaving {
    fn has_chunk(&self, hash: &Hash) -> Result<bool, StoreError> {
        self.inner.has_chunk(hash)
    }
    fn put_chunk(&self, hash: Hash, data: Vec<u8>) -> Result<(), StoreError> {
        self.inner.put_chunk(hash, data)
    }
    fn get_chunk(&self, hash: &Hash) -> Result<Option<Vec<u8>>, StoreError> {
        let mut c = self.inner.get_chunk(hash)?;
        if self.corrupt_chunks {
            if let Some(bytes) = c.as_mut() {
                if let Some(b) = bytes.first_mut() {
                    *b ^= 0xFF;
                }
            }
        }
        Ok(c)
    }
    fn doc_has_chunk(&self, doc: &Hash, hash: &Hash) -> Result<bool, StoreError> {
        self.inner.doc_has_chunk(doc, hash)
    }
    fn get_manifest(&self, doc: &Hash, id: &Hash) -> Result<Option<FileManifest>, StoreError> {
        if let Some((sub_id, m)) = &self.substitute {
            if sub_id == id {
                return Ok(Some(m.clone()));
            }
        }
        self.inner.get_manifest(doc, id)
    }
    fn version(&self, doc: &Hash, id: &VersionId) -> Result<Option<SyncMessage>, StoreError> {
        self.inner.version(doc, id)
    }
    fn is_rejected(&self, doc: &Hash, id: &VersionId) -> Result<bool, StoreError> {
        self.inner.is_rejected(doc, id)
    }
    fn record_rejected(&self, doc: &Hash, version: &SyncMessage) -> Result<(), StoreError> {
        self.inner.record_rejected(doc, version)
    }
    fn record_version(&self, doc: &Hash, version: &SyncMessage) -> Result<(), StoreError> {
        self.inner.record_version(doc, version)
    }
    fn head(&self, doc: &Hash, file_name: &str) -> Result<Option<HeadInfo>, StoreError> {
        self.inner.head(doc, file_name)
    }
    fn heads(&self, doc: &Hash) -> Result<Vec<SyncMessage>, StoreError> {
        self.inner.heads(doc)
    }
    fn commit_version(
        &self,
        doc: &Hash,
        manifest: &FileManifest,
        version: &SyncMessage,
        expected_head: Option<VersionId>,
        written: bool,
    ) -> Result<(), StoreError> {
        self.inner
            .commit_version(doc, manifest, version, expected_head, written)
    }
    fn switch_branch(
        &self,
        doc: &Hash,
        manifest: &FileManifest,
        version: &SyncMessage,
        expected_head: VersionId,
        rejected: &[VersionId],
    ) -> Result<(), StoreError> {
        self.inner
            .switch_branch(doc, manifest, version, expected_head, rejected)
    }
    fn mark_written(&self, doc: &Hash, file_name: &str, id: &VersionId) -> Result<(), StoreError> {
        self.inner.mark_written(doc, file_name, id)
    }
    fn unwritten_heads(&self, doc: &Hash) -> Result<Vec<HeadInfo>, StoreError> {
        self.inner.unwritten_heads(doc)
    }
    fn load_clock(&self) -> Result<Hlc, StoreError> {
        self.inner.load_clock()
    }
    fn save_clock(&self, hlc: Hlc) -> Result<(), StoreError> {
        self.inner.save_clock(hlc)
    }
}

fn served(node: &TestNode) -> u64 {
    ServerMetrics::get(&node.sync.metrics().chunks_served)
}

fn all_chunks_present(store: &dyn Store, manifest: &FileManifest) -> bool {
    manifest.chunks.iter().all(|c| {
        store
            .get_chunk(&c.hash)
            .expect("get")
            .is_some_and(|b| chunk_hash(&b) == c.hash && b.len() == c.length as usize)
    })
}

/// A provider node serving `doc` that already holds `bytes` as version `msg`.
async fn provider_with(doc: &Doc, file: &str, bytes: &[u8]) -> (TestNode, SyncMessage) {
    let p = TestNode::spawn().await;
    p.sync.add_document(doc.id, doc.owner_pub);
    let pl = payload(file, bytes);
    let v = version_by(doc, p.secret(), &pl, None, past_hlc(0));
    seed(p.store.as_ref(), doc, &pl, &v);
    (p, v)
}

// ---------------------------------------------------------------------------
// Fetcher
// ---------------------------------------------------------------------------

#[tokio::test]
async fn fetcher_requests_only_missing_chunks_and_repeats_once() {
    let doc = Doc::new();
    let block = seeded_bytes(1, 200_000);
    let mut bytes = block.clone();
    bytes.extend_from_slice(&block); // interior chunks repeat
    let (p, _v) = provider_with(&doc, "rep.bin", &bytes).await;
    let pl = payload("rep.bin", &bytes);
    let unique: std::collections::HashSet<Hash> =
        pl.manifest.chunks.iter().map(|c| c.hash).collect();
    assert!(
        unique.len() < pl.manifest.chunks.len(),
        "no repeated chunk in fixture"
    );

    let h = Harness::new(&doc, false).await;
    h.node.know(&p);
    // Pre-seed half of the unique chunks locally.
    let mut present = 0;
    for (i, hash) in unique.iter().enumerate() {
        if i % 2 == 0 {
            let (_, b) = pl.iter().find(|(r, _)| r.hash == *hash).unwrap();
            h.node.store.put_chunk(*hash, b.clone()).unwrap();
            present += 1;
        }
    }
    let report = with_timeout(h.engine.fetcher().fetch_missing(
        h.engine.ctx(),
        &pl.manifest,
        &[p.id()],
    ))
    .await
    .unwrap();
    assert_eq!(report.unique_chunks, unique.len());
    assert_eq!(report.already_present, present);
    assert_eq!(report.fetched, unique.len() - present);
    assert_eq!(report.retries, 0);
    assert_eq!(served(&p), (unique.len() - present) as u64);
    assert!(all_chunks_present(h.node.store.as_ref(), &pl.manifest));

    // A second call fetches nothing.
    let report = with_timeout(h.engine.fetcher().fetch_missing(
        h.engine.ctx(),
        &pl.manifest,
        &[p.id()],
    ))
    .await
    .unwrap();
    assert_eq!(report.fetched, 0);
    assert_eq!(report.already_present, unique.len());
    h.shutdown().await;
    p.shutdown().await;
}

/// SEC-8: corrupt bytes are detected by the hash check and the chunk is
/// retried on another provider.
#[tokio::test]
async fn corrupt_provider_is_detected_and_chunks_retried_elsewhere() {
    let doc = Doc::new();
    let bytes = seeded_bytes(2, 150_000);
    let (good, _v) = provider_with(&doc, "f.bin", &bytes).await;
    let bad = TestNode::spawn_with(Misbehaving::corrupt()).await;
    bad.sync.add_document(doc.id, doc.owner_pub);
    let pl = payload("f.bin", &bytes);
    let v_bad = version_by(&doc, bad.secret(), &pl, None, past_hlc(0));
    seed(bad.store.as_ref(), &doc, &pl, &v_bad);

    let h = Harness::new(&doc, false).await;
    h.node.know(&good);
    h.node.know(&bad);
    let report = with_timeout(h.engine.fetcher().fetch_missing(
        h.engine.ctx(),
        &pl.manifest,
        &[bad.id(), good.id()],
    ))
    .await
    .unwrap();
    assert_eq!(report.fetched, pl.manifest.chunks.len());
    assert!(
        report.retries > 0,
        "corrupt provider must have caused retries"
    );
    assert!(served(&bad) > 0, "the corrupt provider was asked");
    assert!(all_chunks_present(h.node.store.as_ref(), &pl.manifest));
    h.shutdown().await;
    good.shutdown().await;
    bad.shutdown().await;
}

#[tokio::test]
async fn offline_provider_falls_back_and_only_dead_providers_is_fatal() {
    let doc = Doc::new();
    let bytes = seeded_bytes(3, 2 << 20);
    let (a, _) = provider_with(&doc, "big.bin", &bytes).await;
    let (b, _) = provider_with(&doc, "big.bin", &bytes).await;
    let pl = payload("big.bin", &bytes);

    let h = Harness::new(&doc, false).await;
    h.node.know(&a);
    h.node.know(&b);
    // B goes offline shortly after the transfer starts.
    let b_id = b.id();
    let shutdown = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(30)).await;
        b.shutdown().await;
    });
    let report = tokio::time::timeout(
        Duration::from_secs(30),
        h.engine
            .fetcher()
            .fetch_missing(h.engine.ctx(), &pl.manifest, &[b_id, a.id()]),
    )
    .await
    .expect("fetch hung")
    .unwrap();
    shutdown.await.unwrap();
    assert_eq!(report.fetched, report.unique_chunks);
    assert!(all_chunks_present(h.node.store.as_ref(), &pl.manifest));

    // Only an unreachable provider: a fatal error, returned promptly.
    let dead = SecretKey::generate().public();
    let small = payload("s.bin", &seeded_bytes(4, 50_000));
    let started = Instant::now();
    let err = tokio::time::timeout(
        Duration::from_secs(30),
        h.engine
            .fetcher()
            .fetch_missing(h.engine.ctx(), &small.manifest, &[dead]),
    )
    .await
    .expect("fetch hung")
    .unwrap_err();
    assert!(matches!(err, SyncError::ChunkFailed { .. }), "{err:?}");
    assert!(started.elapsed() < Duration::from_secs(25));
    h.shutdown().await;
    a.shutdown().await;
}

// ---------------------------------------------------------------------------
// Apply pipeline
// ---------------------------------------------------------------------------

#[tokio::test]
async fn remote_version_is_applied_and_written_and_twice_is_a_noop() {
    let doc = Doc::new();
    let bytes = seeded_bytes(5, 120_000);
    let (p, v) = provider_with(&doc, "dir/data.bin", &bytes).await;
    let mut h = Harness::new(&doc, false).await;
    h.node.know(&p);

    let outcome = with_timeout(h.engine.apply_remote(&v, &[p.id()]))
        .await
        .unwrap();
    match outcome {
        ApplyOutcome::Applied {
            version_id,
            file_name,
            fetched_chunks,
        } => {
            assert_eq!(version_id, vid(&v));
            assert_eq!(file_name, "dir/data.bin");
            assert!(fetched_chunks > 0);
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(h.read("dir/data.bin"), bytes);
    let head = h.node.store.head(&doc.id, "dir/data.bin").unwrap().unwrap();
    assert_eq!(head.version_id, vid(&v));
    assert!(head.written);
    // A Have was announced and the file-written event fired.
    let out = h.drain_outbox();
    assert!(
        matches!(out.as_slice(), [SyncMessage::Have { manifest_id, .. }] if *manifest_id == *v.manifest_id())
    );
    let mut saw_applied = false;
    while let Ok(ev) = h.events.try_recv() {
        if matches!(ev, SyncEvent::Applied { .. }) {
            saw_applied = true;
        }
    }
    assert!(saw_applied);

    let before = served(&p);
    let again = with_timeout(h.engine.apply_remote(&v, &[p.id()]))
        .await
        .unwrap();
    assert_eq!(again, ApplyOutcome::AlreadyKnown);
    assert_eq!(served(&p), before);
    assert!(h.drain_outbox().is_empty());
    h.shutdown().await;
    p.shutdown().await;
}

/// SEC-8: a provider that serves a manifest whose recomputed ID differs
/// from the announced one is rejected and nothing is written.
#[tokio::test]
async fn manifest_id_mismatch_is_rejected() {
    let doc = Doc::new();
    let bytes = seeded_bytes(6, 40_000);
    let pl = payload("m.bin", &bytes);
    let announced = pl.manifest.id();
    let mut tampered = pl.manifest.clone();
    tampered.chunks[0].hash[0] ^= 1;
    let p = TestNode::spawn_with(Misbehaving::substitute(announced, tampered)).await;
    p.sync.add_document(doc.id, doc.owner_pub);
    let v = version_by(&doc, p.secret(), &pl, None, past_hlc(0));
    seed(p.store.as_ref(), &doc, &pl, &v);

    let h = Harness::new(&doc, false).await;
    h.node.know(&p);
    let err = with_timeout(h.engine.apply_remote(&v, &[p.id()]))
        .await
        .unwrap_err();
    assert!(matches!(err, SyncError::ManifestMismatch), "{err:?}");
    assert!(!h.path("m.bin").exists());
    assert!(h.node.store.head(&doc.id, "m.bin").unwrap().is_none());
    h.shutdown().await;
    p.shutdown().await;
}

/// SEC-9: a manifest naming `../evil` writes nothing outside the document.
#[tokio::test]
async fn sec9_manifest_with_dotdot_writes_nothing_outside() {
    let doc = Doc::new();
    let evil = FileManifest {
        file_name: "../evil".into(),
        total_size: 3,
        chunks: vec![ChunkRef {
            hash: chunk_hash(b"abc"),
            length: 3,
        }],
    };
    let evil_id = evil.id();
    let p = TestNode::spawn_with(Misbehaving::substitute(evil_id, evil)).await;
    p.sync.add_document(doc.id, doc.owner_pub);
    p.store
        .put_chunk(chunk_hash(b"abc"), b"abc".to_vec())
        .unwrap();
    let v = SyncMessage::new_version(
        p.secret(),
        doc.id,
        evil_id,
        None,
        past_hlc(0),
        doc.token(p.id_bytes(), true, true),
    );

    let h = Harness::new(&doc, false).await;
    h.node.know(&p);
    let err = with_timeout(h.engine.apply_remote(&v, &[p.id()]))
        .await
        .unwrap_err();
    assert!(
        matches!(err, SyncError::Manifest(ManifestError::BadPath(_))),
        "{err:?}"
    );
    let outside = h.doc_dir().parent().unwrap().join("evil");
    assert!(!outside.exists());
    assert!(!h.doc_dir().join("evil").exists());
    h.shutdown().await;
    p.shutdown().await;
}

// ---------------------------------------------------------------------------
// Publishing and conflicts
// ---------------------------------------------------------------------------

/// CON-1, CON-2: publishing from a stale head fails with HeadMoved. Nothing
/// is broadcast, no chunk of the failed version is servable, and its bytes
/// are kept under `.p2p-sync/rejected/`.
#[tokio::test]
async fn publish_from_stale_head_is_rejected_without_side_effects() {
    let doc = Doc::new();
    let mut h = Harness::new(&doc, true).await;
    let b1 = seeded_bytes(7, 30_000);
    h.write("notes.txt", &b1);
    let v1 = match with_timeout(h.engine.publish_file("notes.txt"))
        .await
        .unwrap()
    {
        PublishOutcome::Published(id) => id,
        other => panic!("{other:?}"),
    };
    let out = h.drain_outbox();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].version_id(), Some(v1));

    // Same bytes again: no-op.
    assert_eq!(
        with_timeout(h.engine.publish_file("notes.txt"))
            .await
            .unwrap(),
        PublishOutcome::Unchanged
    );

    // A stale publish: built on "no head" while the head is v1.
    let b2 = seeded_bytes(8, 30_000);
    let outcome = with_timeout(h.engine.publish_from("notes.txt", b2.clone(), None))
        .await
        .unwrap();
    let PublishOutcome::Rejected {
        version_id,
        kept_at,
        head,
    } = outcome
    else {
        panic!("expected rejection, got {outcome:?}");
    };
    assert_eq!(head, Some(v1));
    assert_eq!(std::fs::read(&kept_at).unwrap(), b2);
    assert!(kept_at.starts_with(h.doc_dir().join(".p2p-sync").join("rejected")));
    assert!(h.drain_outbox().is_empty(), "nothing may be broadcast");
    let pl2 = payload("notes.txt", &b2);
    let pl1 = payload("notes.txt", &b1);
    for c in &pl2.manifest.chunks {
        if !pl1.manifest.chunks.iter().any(|x| x.hash == c.hash) {
            assert!(!h.node.store.doc_has_chunk(&doc.id, &c.hash).unwrap());
        }
    }
    assert!(h
        .node
        .store
        .version(&doc.id, &version_id)
        .unwrap()
        .is_none());
    assert_eq!(
        h.node
            .store
            .head(&doc.id, "notes.txt")
            .unwrap()
            .unwrap()
            .version_id,
        v1
    );
    let rej = h.engine.rejections();
    assert_eq!(rej.len(), 1);
    assert_eq!(rej[0].version_id, Some(version_id));
    assert_eq!(rej[0].winner, Some(v1));
    let mut saw = false;
    while let Ok(ev) = h.events.try_recv() {
        if let SyncEvent::VersionRejected { version_id: id, .. } = ev {
            saw = saw || id == version_id;
        }
    }
    assert!(saw);
    h.engine.clear_rejections();
    assert!(h.engine.rejections().is_empty());
    h.shutdown().await;
}

#[tokio::test]
async fn read_only_node_cannot_publish() {
    let doc = Doc::new();
    let h = Harness::new(&doc, false).await;
    let err = with_timeout(h.engine.publish_local_change("x", b"data".to_vec()))
        .await
        .unwrap_err();
    assert!(matches!(err, SyncError::NotWritable));
    h.shutdown().await;
}

/// Build the CON-3 fixture: v0 on provider P, then two concurrent children
/// by nodes B and C where C ranks lower (earlier hlc), all served by P.
struct ForkFixture {
    doc: Doc,
    p: TestNode,
    b: TestNode,
    c: TestNode,
    v0: SyncMessage,
    vb: SyncMessage,
    vc: SyncMessage,
    bytes_b: Vec<u8>,
    bytes_c: Vec<u8>,
}

async fn fork_fixture() -> ForkFixture {
    let doc = Doc::new();
    let b0 = seeded_bytes(10, 60_000);
    let (p, v0) = provider_with(&doc, "shared.bin", &b0).await;
    let b = TestNode::spawn().await;
    let c = TestNode::spawn().await;
    let bytes_b = seeded_bytes(11, 60_000);
    let bytes_c = seeded_bytes(12, 60_000);
    let pl_b = payload("shared.bin", &bytes_b);
    let pl_c = payload("shared.bin", &bytes_c);
    let vb = version_by(&doc, b.secret(), &pl_b, Some(vid(&v0)), past_hlc(2_000));
    let vc = version_by(&doc, c.secret(), &pl_c, Some(vid(&v0)), past_hlc(1_000));
    seed(p.store.as_ref(), &doc, &pl_b, &vb);
    seed(p.store.as_ref(), &doc, &pl_c, &vc);
    ForkFixture {
        doc,
        p,
        b,
        c,
        v0,
        vb,
        vc,
        bytes_b,
        bytes_c,
    }
}

/// CON-3 over the network: same parent, either delivery order, the version
/// with the smaller (hlc, author) ends as head and on disk.
#[tokio::test]
async fn con3_fork_converges_in_either_order() {
    let f = fork_fixture().await;
    for order in [[&f.vb, &f.vc], [&f.vc, &f.vb]] {
        let mut h = Harness::new(&f.doc, false).await;
        h.node.know(&f.p);
        h.node.know(&f.b);
        h.node.know(&f.c);
        with_timeout(h.engine.apply_remote(&f.v0, &[f.p.id()]))
            .await
            .unwrap();
        for v in order {
            with_timeout(h.engine.apply_remote(v, &[f.p.id()]))
                .await
                .unwrap();
        }
        let head = h.node.store.head(&f.doc.id, "shared.bin").unwrap().unwrap();
        assert_eq!(head.version_id, vid(&f.vc));
        assert!(head.written);
        assert_eq!(h.read("shared.bin"), f.bytes_c);
        assert!(h.node.store.is_rejected(&f.doc.id, &vid(&f.vb)).unwrap());
        assert!(!h.node.store.is_rejected(&f.doc.id, &vid(&f.vc)).unwrap());
        // Two or three Haves were announced (one per applied version).
        let haves = h
            .drain_outbox()
            .into_iter()
            .filter(|m| matches!(m, SyncMessage::Have { .. }))
            .count();
        assert!(haves >= 2);
        let _ = &f.bytes_b;
        h.shutdown().await;
    }
    f.p.shutdown().await;
    f.b.shutdown().await;
    f.c.shutdown().await;
}

/// CON-4 and CON-5 over the network: a child of a rejected version is
/// rejected, and a child whose clock is not after its parent's is rejected.
#[tokio::test]
async fn con4_con5_rejections_over_network() {
    let f = fork_fixture().await;
    let h = Harness::new(&f.doc, false).await;
    h.node.know(&f.p);
    h.node.know(&f.b);
    h.node.know(&f.c);
    with_timeout(h.engine.apply_remote(&f.v0, &[f.p.id()]))
        .await
        .unwrap();
    with_timeout(h.engine.apply_remote(&f.vc, &[f.p.id()]))
        .await
        .unwrap();
    let r = with_timeout(h.engine.apply_remote(&f.vb, &[f.p.id()]))
        .await
        .unwrap();
    assert!(matches!(
        r,
        ApplyOutcome::Rejected {
            reason: RejectReason::LostFork { .. },
            ..
        }
    ));
    // Child of the rejected vb.
    let pl = payload("shared.bin", &seeded_bytes(13, 10_000));
    let vb2 = version_by(&f.doc, f.b.secret(), &pl, Some(vid(&f.vb)), past_hlc(3_000));
    seed(f.p.store.as_ref(), &f.doc, &pl, &vb2);
    let r = with_timeout(h.engine.apply_remote(&vb2, &[f.p.id()]))
        .await
        .unwrap();
    assert_eq!(
        r,
        ApplyOutcome::Rejected {
            version_id: vid(&vb2),
            reason: RejectReason::ParentRejected
        }
    );
    // Clock not after parent: a child of vc stamped before vc.
    let pl = payload("shared.bin", &seeded_bytes(14, 10_000));
    let stale = version_by(&f.doc, f.c.secret(), &pl, Some(vid(&f.vc)), past_hlc(500));
    seed(f.p.store.as_ref(), &f.doc, &pl, &stale);
    let r = with_timeout(h.engine.apply_remote(&stale, &[f.p.id()]))
        .await
        .unwrap();
    assert_eq!(
        r,
        ApplyOutcome::Rejected {
            version_id: vid(&stale),
            reason: RejectReason::ClockNotAfterParent
        }
    );
    assert_eq!(
        h.node
            .store
            .head(&f.doc.id, "shared.bin")
            .unwrap()
            .unwrap()
            .version_id,
        vid(&f.vc)
    );
    assert_eq!(h.read("shared.bin"), f.bytes_c);
    h.shutdown().await;
    f.p.shutdown().await;
    f.b.shutdown().await;
    f.c.shutdown().await;
}

/// CON-6: a locally authored version loses a fork. The file on disk holds the
/// winner, the loser's bytes are kept, a VersionRejected event is emitted,
/// and the next save publishes with the winner as its parent.
#[tokio::test]
async fn con6_local_version_loses_and_next_save_builds_on_winner() {
    let doc = Doc::new();
    let b0 = seeded_bytes(20, 50_000);
    let (p, v0) = provider_with(&doc, "doc.txt", &b0).await;
    let mut h = Harness::new(&doc, true).await;
    h.node.know(&p);
    with_timeout(h.engine.apply_remote(&v0, &[p.id()]))
        .await
        .unwrap();
    assert_eq!(h.read("doc.txt"), b0);
    h.drain_outbox();

    // Local edit on top of v0, stamped with real time (well after past_hlc).
    let mine = seeded_bytes(21, 50_000);
    h.write("doc.txt", &mine);
    let v1 = match with_timeout(h.engine.publish_file("doc.txt"))
        .await
        .unwrap()
    {
        PublishOutcome::Published(id) => id,
        other => panic!("{other:?}"),
    };
    let v1_msg = h.node.store.version(&doc.id, &v1).unwrap().unwrap();
    assert!(matches!(v1_msg, SyncMessage::NewVersion { parent, .. } if parent == Some(vid(&v0))));
    h.drain_outbox();

    // A concurrent remote version with a smaller hlc built on v0 arrives.
    let theirs = seeded_bytes(22, 50_000);
    let pl_c = payload("doc.txt", &theirs);
    let vc = version_by(&doc, p.secret(), &pl_c, Some(vid(&v0)), past_hlc(1));
    seed(p.store.as_ref(), &doc, &pl_c, &vc);
    let r = with_timeout(h.engine.apply_remote(&vc, &[p.id()]))
        .await
        .unwrap();
    assert!(matches!(r, ApplyOutcome::Applied { .. }), "{r:?}");

    assert_eq!(h.read("doc.txt"), theirs, "disk holds the winner");
    let head = h.node.store.head(&doc.id, "doc.txt").unwrap().unwrap();
    assert_eq!(head.version_id, vid(&vc));
    assert!(h.node.store.is_rejected(&doc.id, &v1).unwrap());
    let kept = h.rejected_files();
    assert_eq!(kept.len(), 1, "{kept:?}");
    assert_eq!(std::fs::read(&kept[0]).unwrap(), mine);
    assert!(kept[0].to_string_lossy().contains(&hex::encode(&v1[..4])));
    let mut saw = false;
    while let Ok(ev) = h.events.try_recv() {
        if let SyncEvent::VersionRejected {
            version_id, winner, ..
        } = ev
        {
            assert_eq!(version_id, v1);
            assert_eq!(winner, Some(vid(&vc)));
            saw = true;
        }
    }
    assert!(saw, "VersionRejected event");
    let rej = h.engine.rejections();
    assert_eq!(rej.len(), 1);
    assert_eq!(rej[0].version_id, Some(v1));

    // The next save builds on the winner.
    let next = seeded_bytes(23, 50_000);
    h.write("doc.txt", &next);
    let v2 = match with_timeout(h.engine.publish_file("doc.txt"))
        .await
        .unwrap()
    {
        PublishOutcome::Published(id) => id,
        other => panic!("{other:?}"),
    };
    let v2_msg = h.node.store.version(&doc.id, &v2).unwrap().unwrap();
    assert!(matches!(v2_msg, SyncMessage::NewVersion { parent, .. } if parent == Some(vid(&vc))));
    h.shutdown().await;
    p.shutdown().await;
}

/// An unpublished local edit displaced by a remote version is kept, never
/// silently overwritten.
#[tokio::test]
async fn unpublished_edit_displaced_by_remote_version_is_kept() {
    let doc = Doc::new();
    let b0 = seeded_bytes(30, 20_000);
    let (p, v0) = provider_with(&doc, "note.md", &b0).await;
    let mut h = Harness::new(&doc, true).await;
    h.node.know(&p);
    // The user already has an unpublished file with this name.
    let local = b"my unpublished draft".to_vec();
    h.write("note.md", &local);
    with_timeout(h.engine.apply_remote(&v0, &[p.id()]))
        .await
        .unwrap();
    assert_eq!(h.read("note.md"), b0);
    let kept = h.rejected_files();
    assert_eq!(kept.len(), 1, "{kept:?}");
    assert_eq!(std::fs::read(&kept[0]).unwrap(), local);
    let mut saw = false;
    while let Ok(ev) = h.events.try_recv() {
        saw = saw || matches!(ev, SyncEvent::EditDisplaced { .. });
    }
    assert!(saw);
    h.shutdown().await;
    p.shutdown().await;
}

// ---------------------------------------------------------------------------
// Gaps, catch-up, repair
// ---------------------------------------------------------------------------

#[tokio::test]
async fn gap_is_filled_by_walking_back_with_get_version() {
    let doc = Doc::new();
    let p = TestNode::spawn().await;
    p.sync.add_document(doc.id, doc.owner_pub);
    let mut versions = Vec::new();
    let mut parent = None;
    let mut last_bytes = Vec::new();
    for i in 0..4u64 {
        let bytes = seeded_bytes(40 + i, 30_000);
        let pl = payload("chain.bin", &bytes);
        let v = version_by(&doc, p.secret(), &pl, parent, past_hlc(i * 100));
        seed(p.store.as_ref(), &doc, &pl, &v);
        parent = Some(vid(&v));
        versions.push(v);
        last_bytes = bytes;
    }
    let h = Harness::new(&doc, false).await;
    h.node.know(&p);
    with_timeout(h.engine.apply_remote(&versions[0], &[p.id()]))
        .await
        .unwrap();
    let before = ServerMetrics::get(&p.sync.metrics().versions_served);
    let r = with_timeout(h.engine.apply_remote(&versions[3], &[p.id()]))
        .await
        .unwrap();
    assert!(matches!(r, ApplyOutcome::Applied { .. }), "{r:?}");
    assert_eq!(
        ServerMetrics::get(&p.sync.metrics().versions_served) - before,
        2
    );
    assert_eq!(
        h.node
            .store
            .head(&doc.id, "chain.bin")
            .unwrap()
            .unwrap()
            .version_id,
        vid(&versions[3])
    );
    assert_eq!(h.read("chain.bin"), last_bytes);
    for v in &versions {
        assert!(h.node.store.version(&doc.id, &vid(v)).unwrap().is_some());
        assert!(!h.node.store.is_rejected(&doc.id, &vid(v)).unwrap());
    }
    h.shutdown().await;
    p.shutdown().await;
}

#[tokio::test]
async fn chain_that_does_not_connect_within_64_steps_is_dropped() {
    let doc = Doc::new();
    let p = TestNode::spawn().await;
    p.sync.add_document(doc.id, doc.owner_pub);
    // An independent 70-deep chain for "g" on P, rooted separately.
    let mut parent = None;
    let mut tip = None;
    for i in 0..70u64 {
        let pl = payload("g", &seeded_bytes(100 + i, 1_000));
        let v = version_by(&doc, p.secret(), &pl, parent, past_hlc(i * 10));
        seed(p.store.as_ref(), &doc, &pl, &v);
        parent = Some(vid(&v));
        tip = Some(v);
    }
    let tip = tip.unwrap();
    // Our own root for "g".
    let h = Harness::new(&doc, true).await;
    h.node.know(&p);
    let mine = b"my own g".to_vec();
    h.write("g", &mine);
    let my_root = match with_timeout(h.engine.publish_file("g")).await.unwrap() {
        PublishOutcome::Published(id) => id,
        other => panic!("{other:?}"),
    };
    let r = tokio::time::timeout(
        Duration::from_secs(30),
        h.engine.apply_remote(&tip, &[p.id()]),
    )
    .await
    .expect("hung")
    .unwrap();
    assert!(matches!(r, ApplyOutcome::Dropped(_)), "{r:?}");
    assert_eq!(
        h.node.store.head(&doc.id, "g").unwrap().unwrap().version_id,
        my_root
    );
    assert_eq!(h.read("g"), mine);
    h.shutdown().await;
    p.shutdown().await;
}

#[tokio::test]
async fn late_joiner_catches_up_through_get_heads() {
    let doc = Doc::new();
    let p = TestNode::spawn().await;
    p.sync.add_document(doc.id, doc.owner_pub);
    let a = seeded_bytes(50, 70_000);
    let b = seeded_bytes(51, 5_000);
    for (name, bytes) in [("x/a.bin", &a), ("b.txt", &b)] {
        let pl = payload(name, bytes);
        let v = version_by(&doc, p.secret(), &pl, None, past_hlc(0));
        seed(p.store.as_ref(), &doc, &pl, &v);
    }
    let h = Harness::new(&doc, false).await;
    h.node.know(&p);
    let applied = with_timeout(h.engine.catch_up(p.id())).await.unwrap();
    assert_eq!(applied, 2);
    assert_eq!(h.read("x/a.bin"), a);
    assert_eq!(h.read("b.txt"), b);
    let mut heads = h.engine.heads().unwrap();
    heads.sort_by(|x, y| x.0.cmp(&y.0));
    assert_eq!(heads.len(), 2);
    assert_eq!(heads[0].0, "b.txt");
    assert_eq!(heads[1].0, "x/a.bin");
    // A second catch-up applies nothing new; a random-peer catch-up works.
    assert_eq!(with_timeout(h.engine.catch_up(p.id())).await.unwrap(), 0);
    assert_eq!(
        with_timeout(h.engine.catch_up_any()).await.unwrap(),
        Some(0)
    );
    h.shutdown().await;
    p.shutdown().await;
}

#[tokio::test]
async fn have_announcement_registers_a_provider_used_for_fetching() {
    let doc = Doc::new();
    let bytes = seeded_bytes(60, 40_000);
    let (p, v) = provider_with(&doc, "h.bin", &bytes).await;
    // The version's author is P, but pretend we only know P as a Have sender:
    // author lookups also point at P, so use a second node as the announced
    // provider to prove the Have path.
    let q = TestNode::spawn().await;
    q.sync.add_document(doc.id, doc.owner_pub);
    let pl = payload("h.bin", &bytes);
    seed(q.store.as_ref(), &doc, &pl, &v);
    let h = Harness::new(&doc, false).await;
    h.node.know(&q);
    // P is unknown to our address book, so only Q can serve.
    let have = SyncMessage::have(
        q.secret(),
        doc.id,
        pl.manifest.id(),
        doc.token(q.id_bytes(), true, false),
    );
    assert_eq!(
        with_timeout(h.engine.handle_announcement(&have, None))
            .await
            .unwrap(),
        None
    );
    let known = h.engine.known_providers();
    assert_eq!(known, vec![(pl.manifest.id(), vec![q.id()])]);
    let r = tokio::time::timeout(
        Duration::from_secs(30),
        h.engine.handle_announcement(&v, None),
    )
    .await
    .expect("hung")
    .unwrap();
    assert!(matches!(r, Some(ApplyOutcome::Applied { .. })), "{r:?}");
    assert_eq!(h.read("h.bin"), bytes);
    h.shutdown().await;
    p.shutdown().await;
    q.shutdown().await;
}

#[tokio::test]
async fn crash_between_commit_and_write_is_repaired_at_startup() {
    let doc = Doc::new();
    let h = Harness::new(&doc, true).await;
    let bytes = seeded_bytes(70, 45_000);
    let pl = payload("r.bin", &bytes);
    let v = version_by(&doc, h.node.secret(), &pl, None, past_hlc(0));
    for (r, b) in pl.iter() {
        h.node.store.put_chunk(r.hash, b.clone()).unwrap();
    }
    // Committed but never written: the crash.
    h.node
        .store
        .commit_version(&doc.id, &pl.manifest, &v, None, false)
        .unwrap();
    assert!(!h.path("r.bin").exists());
    assert_eq!(
        with_timeout(h.engine.repair_unwritten_heads())
            .await
            .unwrap(),
        1
    );
    assert_eq!(h.read("r.bin"), bytes);
    assert!(
        h.node
            .store
            .head(&doc.id, "r.bin")
            .unwrap()
            .unwrap()
            .written
    );
    assert!(h.engine.take_recent_write("r.bin", Duration::from_secs(5)));
    // The repaired file is not a new edit.
    assert_eq!(
        with_timeout(h.engine.publish_file("r.bin")).await.unwrap(),
        PublishOutcome::Unchanged
    );
    assert_eq!(
        with_timeout(h.engine.repair_unwritten_heads())
            .await
            .unwrap(),
        0
    );
    h.shutdown().await;
}

#[tokio::test]
async fn connect_to_unknown_peer_fails_promptly() {
    let n = TestNode::spawn().await;
    let unknown: EndpointId = SecretKey::generate().public();
    let started = Instant::now();
    let r = tokio::time::timeout(Duration::from_secs(15), n.pool.connect(unknown)).await;
    assert!(
        matches!(r, Ok(Err(_))),
        "expected a connect error, got {r:?}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(12),
        "{:?}",
        started.elapsed()
    );
    n.shutdown().await;
}
