//! Shared helpers for the integration tests: loopback nodes, documents,
//! tokens and a default timeout.
//!
//! Every test binary that includes this module uses a different subset of
//! it, so unused-item warnings here would be noise rather than signal.
#![allow(dead_code)]

use ed25519_dalek::SigningKey;
use iroh::protocol::Router;
use iroh::{EndpointAddr, EndpointId, SecretKey};
use p2p_sync_poc::capabilities::{CapabilityClaims, CapabilityToken};
use p2p_sync_poc::chunker::ChunkedPayload;
use p2p_sync_poc::clock::unix_now_secs;
use p2p_sync_poc::clock::Hlc;
use p2p_sync_poc::crypto::derive_topic_id;
use p2p_sync_poc::crypto::{generate_signing_key, random_bytes32};
use p2p_sync_poc::gossip::{GossipNode, SyncMessage};
use p2p_sync_poc::storage::{MemStore, Store};
use p2p_sync_poc::sync::{spawn_gossip_driver_gated, DocContext, SyncEngine, SyncEvent};
use p2p_sync_poc::transport::{
    bind_endpoint, router_builder, BoundEndpoint, ConnectionPool, EndpointOptions, SyncProtocol,
};
use p2p_sync_poc::watcher::FileWatcher;
use p2p_sync_poc::{Hash, VersionId};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, mpsc, watch};
use tokio::task::JoinHandle;

/// Every network wait in a test is bounded by this.
pub const TEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Fail instead of hanging.
pub async fn with_timeout<F: Future>(f: F) -> F::Output {
    tokio::time::timeout(TEST_TIMEOUT, f)
        .await
        .expect("test timed out")
}

/// One loopback node: endpoint, router with the sync and gossip protocols,
/// in-memory store and a client connection pool.
pub struct TestNode {
    pub bound: BoundEndpoint,
    pub router: Router,
    pub sync: SyncProtocol,
    pub gossip: GossipNode,
    pub store: Arc<dyn Store>,
    pub pool: Arc<ConnectionPool>,
}

impl TestNode {
    /// Bind on 127.0.0.1 with relays disabled and spawn the router, over a
    /// fresh in-memory store.
    pub async fn spawn() -> TestNode {
        Self::spawn_with(Arc::new(MemStore::new())).await
    }

    /// Like `spawn`, serving from the given store (tests use wrappers that
    /// misbehave on purpose).
    pub async fn spawn_with(store: Arc<dyn Store>) -> TestNode {
        let sync = SyncProtocol::new(store.clone());
        let bound = bind_endpoint(EndpointOptions::loopback(SecretKey::generate()))
            .await
            .expect("bind loopback endpoint");
        let gossip = GossipNode::spawn(bound.endpoint.clone());
        let router = router_builder(bound.endpoint.clone(), sync.clone())
            .accept(GossipNode::alpn(), gossip.handler())
            .spawn();
        let pool = Arc::new(ConnectionPool::new(bound.endpoint.clone()));
        TestNode {
            bound,
            router,
            sync,
            gossip,
            store,
            pool,
        }
    }

    /// This node's endpoint secret key, for signing announcements.
    pub fn secret(&self) -> &SecretKey {
        self.bound.endpoint.secret_key()
    }

    pub fn id(&self) -> EndpointId {
        self.bound.endpoint.id()
    }

    pub fn id_bytes(&self) -> [u8; 32] {
        *self.id().as_bytes()
    }

    pub fn addr(&self) -> EndpointAddr {
        self.bound.endpoint.addr()
    }

    /// Enter `other` into this node's address book so it can be dialed by ID.
    pub fn know(&self, other: &TestNode) {
        self.bound.add_addr(other.addr());
    }

    pub async fn shutdown(self) {
        self.pool.close_all();
        self.gossip.shutdown().await;
        let _ = self.router.shutdown().await;
        self.bound.endpoint.close().await;
    }
}

/// A document with its owner key.
pub struct Doc {
    pub id: Hash,
    pub owner: SigningKey,
    pub owner_pub: [u8; 32],
}

impl Default for Doc {
    fn default() -> Self {
        Self::new()
    }
}

impl Doc {
    pub fn new() -> Doc {
        let owner = generate_signing_key();
        let owner_pub = owner.verifying_key().to_bytes();
        Doc {
            id: random_bytes32(),
            owner,
            owner_pub,
        }
    }

    /// A token valid from 100 s ago until an hour from now.
    pub fn token(&self, audience: [u8; 32], read: bool, write: bool) -> CapabilityToken {
        let now = unix_now_secs();
        self.token_with_window(audience, read, write, now - 100, now + 3600)
    }

    pub fn token_with_window(
        &self,
        audience: [u8; 32],
        read: bool,
        write: bool,
        not_before: u64,
        expires_at: u64,
    ) -> CapabilityToken {
        CapabilityToken::issue(
            CapabilityClaims {
                doc_id: self.id,
                audience,
                can_read: read,
                can_write: write,
                not_before,
                expires_at,
            },
            &self.owner,
        )
    }
}

/// Deterministic pseudo-random bytes for test files.
pub fn test_data(seed: u64, len: usize) -> Vec<u8> {
    let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(1);
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 24) as u8
        })
        .collect()
}

/// Deterministic pseudo-random bytes for test files.
pub fn seeded_bytes(seed: u64, len: usize) -> Vec<u8> {
    test_data(seed, len)
}

/// Chunk `bytes` under `file_name`.
pub fn payload(file_name: &str, bytes: &[u8]) -> ChunkedPayload {
    p2p_sync_poc::chunker::chunk_bytes(file_name, bytes).expect("chunk")
}

/// A signed `NewVersion` by `author` with a write token from the document
/// owner bound to that author.
pub fn version_by(
    doc: &Doc,
    author: &SecretKey,
    payload: &ChunkedPayload,
    parent: Option<VersionId>,
    hlc: Hlc,
) -> SyncMessage {
    SyncMessage::new_version(
        author,
        doc.id,
        payload.manifest.id(),
        parent,
        hlc,
        doc.token(*author.public().as_bytes(), true, true),
    )
}

/// Put the payload's chunks into `store` and commit `msg` on top of the
/// file's current head there, so the node serves it.
pub fn seed(store: &dyn Store, doc: &Doc, payload: &ChunkedPayload, msg: &SyncMessage) {
    for (r, b) in payload.iter() {
        store.put_chunk(r.hash, b.clone()).expect("put chunk");
    }
    let head = store
        .head(&doc.id, &payload.manifest.file_name)
        .expect("head")
        .map(|h| h.version_id);
    store
        .commit_version(&doc.id, &payload.manifest, msg, head, true)
        .expect("commit");
}

/// The version id of a `NewVersion`.
pub fn vid(msg: &SyncMessage) -> VersionId {
    msg.version_id().expect("NewVersion")
}

/// A clock value one minute in the past plus `offset_ms`, so versions built
/// in tests sort before anything the engine stamps with real time.
pub fn past_hlc(offset_ms: u64) -> Hlc {
    Hlc::new(
        p2p_sync_poc::clock::physical_now_ms() - 60_000 + offset_ms,
        0,
    )
}

/// A node running a sync engine over its own temporary document directory.
pub struct Harness {
    pub node: TestNode,
    pub engine: SyncEngine,
    /// The engine's outbox until `go_online` hands it to the gossip driver.
    pub outbox: Option<mpsc::UnboundedReceiver<SyncMessage>>,
    pub events: broadcast::Receiver<SyncEvent>,
    pub dir: tempfile::TempDir,
    online: Option<watch::Sender<bool>>,
    driver: Option<JoinHandle<()>>,
    watcher: Option<FileWatcher>,
}

impl Harness {
    /// Spawn a node and an engine for `doc`, with a read token and, if
    /// `write`, a write token. The node also serves `doc`.
    pub async fn new(doc: &Doc, write: bool) -> Harness {
        let node = TestNode::spawn().await;
        Self::with_node(node, doc, write).await
    }

    pub async fn with_node(node: TestNode, doc: &Doc, write: bool) -> Harness {
        node.sync.add_document(doc.id, doc.owner_pub);
        let dir = tempfile::tempdir().expect("tempdir");
        let ctx = DocContext {
            doc_id: doc.id,
            owner_key: doc.owner_pub,
            token: doc.token(node.id_bytes(), true, write),
            doc_dir: dir.path().to_path_buf(),
            secret: node.secret().clone(),
        };
        let (tx, outbox) = mpsc::unbounded_channel();
        let engine =
            SyncEngine::new(ctx, node.store.clone(), node.pool.clone(), tx).expect("engine");
        let events = engine.subscribe_events();
        Harness {
            node,
            engine,
            outbox: Some(outbox),
            events,
            dir,
            online: None,
            driver: None,
            watcher: None,
        }
    }

    pub fn id(&self) -> iroh::EndpointId {
        self.node.id()
    }

    /// Join the document's gossip topic and start the driver, waiting for a
    /// neighbor when `bootstrap` is not empty.
    pub async fn go_online(&mut self, salt: &[u8; 32], bootstrap: Vec<iroh::EndpointId>) {
        let topic = derive_topic_id(salt, &self.engine.ctx().doc_id);
        let mut sub = self
            .node
            .gossip
            .subscribe(topic, bootstrap.clone())
            .await
            .expect("subscribe");
        if !bootstrap.is_empty() {
            with_timeout(sub.joined()).await.expect("joined");
        }
        let outbox = self.outbox.take().expect("outbox already taken");
        let (tx, rx) = watch::channel(true);
        self.online = Some(tx);
        self.driver = Some(spawn_gossip_driver_gated(
            self.engine.clone(),
            sub,
            outbox,
            rx,
        ));
    }

    /// Simulate a partition (`false`) or reconnection (`true`).
    pub fn set_online(&self, on: bool) {
        self.online
            .as_ref()
            .expect("go_online first")
            .send_replace(on);
    }

    /// Start the file watcher on the document directory.
    pub fn start_watcher(&mut self) {
        self.watcher = Some(FileWatcher::spawn(self.engine.clone()).expect("watcher"));
    }

    pub fn doc_dir(&self) -> &Path {
        self.dir.path()
    }

    pub fn path(&self, file_name: &str) -> PathBuf {
        self.dir.path().join(file_name)
    }

    pub fn read(&self, file_name: &str) -> Vec<u8> {
        std::fs::read(self.path(file_name)).expect("read synced file")
    }

    pub fn write(&self, file_name: &str, bytes: &[u8]) {
        let p = self.path(file_name);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).expect("mkdir");
        }
        std::fs::write(p, bytes).expect("write");
    }

    /// Files under `.p2p-sync/rejected`, recursively.
    pub fn rejected_files(&self) -> Vec<PathBuf> {
        fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
            if let Ok(entries) = std::fs::read_dir(dir) {
                for e in entries.flatten() {
                    let p = e.path();
                    if p.is_dir() {
                        walk(&p, out);
                    } else {
                        out.push(p);
                    }
                }
            }
        }
        let mut out = Vec::new();
        walk(
            &self.dir.path().join(".p2p-sync").join("rejected"),
            &mut out,
        );
        out.sort();
        out
    }

    /// Drain the outbox without waiting (empty once a driver owns it).
    pub fn drain_outbox(&mut self) -> Vec<SyncMessage> {
        let mut out = Vec::new();
        if let Some(rx) = self.outbox.as_mut() {
            while let Ok(m) = rx.try_recv() {
                out.push(m);
            }
        }
        out
    }

    pub async fn shutdown(self) {
        if let Some(w) = self.watcher {
            w.stop();
        }
        if let Some(d) = self.driver {
            d.abort();
        }
        self.node.shutdown().await;
    }
}
