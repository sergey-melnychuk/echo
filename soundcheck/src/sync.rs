//! Publish and apply pipelines, [`ParallelFetcher`], and the fork and rejection
//! rules (CON-1 to CON-6).
//!
//! Divergence is normal here: conflicts are settled by rule, not by a
//! coordinator. An update must be built on the current head of its file, and
//! among updates built on the same parent the smallest (`hlc`, `author`) wins
//! on every node whatever the arrival order. The loser is kept locally under
//! `.p2p-sync/rejected/` and never announced.
//!
//! [`decide`] is the pure case table from section 8 over the [`Store`];
//! [`SyncEngine`] wraps it with fetching, file writes and announcements.

use crate::capabilities::CapabilityToken;
use crate::chunker::chunk_bytes;
use crate::clock::{physical_now_ms, unix_now_secs, ClockError, Hlc, HlcClock};
use crate::crypto::{chunk_hash, short_hex};
use crate::gossip::{
    validate_decoded, validate_message, DedupKey, GossipError, LruSet, SyncMessage,
    TopicSubscription,
};
use crate::manifest::{confined_path, FileManifest, ManifestError, INTERNAL_DIR};
use crate::protocol::MAX_HEADS;
use crate::storage::{HeadInfo, Store, StoreError};
use crate::transport::{self, ConnectionPool, TransportError};
use crate::{Hash, VersionId};
use iroh::{EndpointId, SecretKey};
use parking_lot::Mutex;
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::{broadcast, mpsc, watch, Semaphore};
use tokio::task::{JoinHandle, JoinSet};
use tracing::{debug, info, warn};

/// Concurrent chunk streams per provider.
pub const STREAMS_PER_PROVIDER: usize = 16;
/// Concurrent chunk streams overall.
pub const STREAMS_OVERALL: usize = 32;
/// Manifests being fetched at once per document.
pub const MANIFESTS_IN_FLIGHT: usize = 4;
/// Attempts per chunk, on a different provider when possible.
pub const CHUNK_ATTEMPTS: u32 = 3;
/// Consecutive failures after which a provider is skipped for [`PROVIDER_SKIP`].
pub const PROVIDER_FAILURE_THRESHOLD: u32 = 3;
/// How long a failing provider is skipped.
pub const PROVIDER_SKIP: Duration = Duration::from_secs(60);
/// First retry backoff; doubles per attempt, plus jitter.
pub const BACKOFF_BASE: Duration = Duration::from_millis(100);
/// Most ancestors fetched to connect a version to the local chain.
pub const MAX_GAP_STEPS: usize = 64;
/// Most versions walked back from the head when looking for a fork point.
pub const MAX_CHAIN_WALK: usize = 4_096;
/// Period of the catch-up task.
pub const CATCH_UP_INTERVAL: Duration = Duration::from_secs(300);
/// Subdirectory of `.p2p-sync` holding rejected and displaced bytes.
pub const REJECTED_DIR: &str = "rejected";
/// Subdirectory of `.p2p-sync` for files being assembled.
pub const TMP_DIR: &str = "tmp";

/// Failures of the sync engine, aggregating every module's errors.
#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    /// Storage failed.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// A manifest or path was invalid.
    #[error(transparent)]
    Manifest(#[from] ManifestError),
    /// A network request failed.
    #[error(transparent)]
    Transport(#[from] TransportError),
    /// An announcement or fetched version failed validation.
    #[error(transparent)]
    Gossip(#[from] GossipError),
    /// The clock refused a remote value.
    #[error(transparent)]
    Clock(#[from] ClockError),
    /// A filesystem operation failed.
    #[error("io error at {path}: {source}")]
    Io {
        /// The path involved.
        path: PathBuf,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },
    /// Data is missing and no provider is known.
    #[error("no provider can serve this data")]
    NoProviders,
    /// A chunk could not be fetched from any provider.
    #[error("chunk {hash} could not be fetched after {attempts} attempts")]
    ChunkFailed {
        /// First 8 hex characters of the chunk hash.
        hash: String,
        /// Attempts made.
        attempts: u32,
    },
    /// A provider returned a manifest whose recomputed ID differs (SEC-8).
    #[error("manifest from provider does not match the announced id")]
    ManifestMismatch,
    /// No provider could serve the manifest.
    #[error("manifest {0} unavailable from every provider")]
    ManifestUnavailable(String),
    /// This node's token lacks `can_write`.
    #[error("this node's token does not grant write")]
    NotWritable,
    /// The head changed between deciding and committing.
    #[error("head moved during commit")]
    HeadMoved,
    /// The message cannot be applied.
    #[error("version cannot be applied: {0}")]
    InvalidVersion(&'static str),
    /// The version was dropped; the reason says why.
    #[error("version dropped: {0}")]
    Dropped(&'static str),
    /// A spawned task failed.
    #[error("background task failed: {0}")]
    Task(String),
}

/// Everything the engine needs to know about the document it syncs.
#[derive(Debug, Clone)]
pub struct DocContext {
    /// The document.
    pub doc_id: Hash,
    /// The owner public key every token must be issued by (SEC-1).
    pub owner_key: [u8; 32],
    /// This node's own token (read, and write if it may publish).
    pub token: CapabilityToken,
    /// Root of the synced directory tree.
    pub doc_dir: PathBuf,
    /// This node's endpoint key, for signing announcements.
    pub secret: SecretKey,
}

impl DocContext {
    /// This node's `NodeId`.
    pub fn node_id(&self) -> EndpointId {
        self.secret.public()
    }

    /// This node's `NodeId` as bytes.
    pub fn node_id_bytes(&self) -> [u8; 32] {
        *self.secret.public().as_bytes()
    }

    /// Whether this node may publish versions.
    pub fn can_write(&self) -> bool {
        self.token.claims.can_write
    }

    /// `<doc_dir>/.p2p-sync`.
    pub fn internal_dir(&self) -> PathBuf {
        self.doc_dir.join(INTERNAL_DIR)
    }

    /// `<doc_dir>/.p2p-sync/rejected`.
    pub fn rejected_dir(&self) -> PathBuf {
        self.internal_dir().join(REJECTED_DIR)
    }

    /// `<doc_dir>/.p2p-sync/tmp`.
    pub fn tmp_dir(&self) -> PathBuf {
        self.internal_dir().join(TMP_DIR)
    }
}

/// The fields of a `NewVersion` the rules operate on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VersionInfo {
    /// Derived version ID.
    pub id: VersionId,
    /// The manifest.
    pub manifest_id: Hash,
    /// The version it was built on.
    pub parent: Option<VersionId>,
    /// Commit time.
    pub hlc: Hlc,
    /// Author `NodeId`.
    pub author: [u8; 32],
}

impl VersionInfo {
    /// Extract from a `NewVersion`; `None` for `Have`.
    pub fn from_message(msg: &SyncMessage) -> Option<Self> {
        match msg {
            SyncMessage::NewVersion {
                manifest_id,
                parent,
                hlc,
                author,
                ..
            } => Some(VersionInfo {
                id: msg.version_id()?,
                manifest_id: *manifest_id,
                parent: *parent,
                hlc: *hlc,
                author: *author,
            }),
            SyncMessage::Have { .. } => None,
        }
    }

    /// The total order among concurrent versions: smaller is earlier (CON-3).
    pub fn rank(&self) -> (Hlc, [u8; 32]) {
        (self.hlc, self.author)
    }
}

/// Why a version was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RejectReason {
    /// Its parent is a rejected version (CON-4).
    ParentRejected,
    /// Its `hlc` is not greater than its parent's (CON-5).
    ClockNotAfterParent,
    /// It lost a fork to `winner` (CON-3).
    LostFork {
        /// The version that stays on the chain.
        winner: VersionId,
    },
}

/// The row of the section 8 case table that applies to a version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Already stored, accepted or rejected: ignore.
    AlreadyKnown,
    /// Record as rejected.
    Reject(RejectReason),
    /// No head yet: apply as the first known head. `ancestry_missing` names
    /// the version's parent when it is not stored locally, so the caller can
    /// record the ancestors first (they make later fork detection possible).
    Bootstrap {
        /// The unknown parent, if any.
        ancestry_missing: Option<VersionId>,
    },
    /// Extends the current head.
    FastForward {
        /// The current head, the expected value for the compare-and-set.
        head: VersionId,
    },
    /// Wins a fork: becomes head, rejecting the losing branch.
    ForkWin {
        /// The current head, the expected value for the compare-and-set.
        head: VersionId,
        /// The losing branch, from the fork point's child up to `head`.
        rejected: Vec<VersionId>,
    },
    /// The parent is unknown: fetch ancestors, then decide again.
    Gap {
        /// The first missing ancestor.
        missing: VersionId,
    },
    /// Cannot connect to the local chain and has no ancestors to fetch.
    Drop(&'static str),
}

/// Apply the section 8 case table to `v` for `file_name`, reading the local
/// chain from `store`. Pure with respect to everything but the store.
pub fn decide(
    store: &dyn Store,
    doc: &Hash,
    file_name: &str,
    v: &VersionInfo,
) -> Result<Decision, SyncError> {
    if store.version(doc, &v.id)?.is_some() {
        return Ok(Decision::AlreadyKnown);
    }
    if let Some(p) = &v.parent {
        if store.is_rejected(doc, p)? {
            return Ok(Decision::Reject(RejectReason::ParentRejected));
        }
    }
    let Some(head) = store.head(doc, file_name)? else {
        let ancestry_missing = match &v.parent {
            Some(p) if store.version(doc, p)?.is_none() => Some(*p),
            _ => None,
        };
        return Ok(Decision::Bootstrap { ancestry_missing });
    };
    if v.parent == Some(head.version_id) {
        return Ok(if v.hlc > head.hlc {
            Decision::FastForward {
                head: head.version_id,
            }
        } else {
            Decision::Reject(RejectReason::ClockNotAfterParent)
        });
    }
    // Walk the local chain from the head backwards looking for a version
    // that shares v's parent: that is the fork point.
    let mut chain: Vec<VersionId> = Vec::new();
    let mut cursor = Some(head.version_id);
    while let Some(id) = cursor {
        if chain.len() >= MAX_CHAIN_WALK {
            break;
        }
        let Some(msg) = store.version(doc, &id)? else {
            break;
        };
        let Some(r) = VersionInfo::from_message(&msg) else {
            break;
        };
        if r.parent == v.parent {
            // CON-5 against the shared parent, when it is known.
            if let Some(p) = &v.parent {
                if let Some(pm) = store.version(doc, p)? {
                    if let Some(pi) = VersionInfo::from_message(&pm) {
                        if v.hlc <= pi.hlc {
                            return Ok(Decision::Reject(RejectReason::ClockNotAfterParent));
                        }
                    }
                }
            }
            if v.rank() < r.rank() {
                chain.push(r.id);
                return Ok(Decision::ForkWin {
                    head: head.version_id,
                    rejected: chain,
                });
            }
            return Ok(Decision::Reject(RejectReason::LostFork { winner: r.id }));
        }
        chain.push(r.id);
        cursor = r.parent;
    }
    match v.parent {
        Some(missing) => Ok(Decision::Gap { missing }),
        None => Ok(Decision::Drop(
            "root version does not connect to the local chain",
        )),
    }
}

/// Perform the storage side of a decision in one transaction: commit,
/// switch branch, or record a rejection. `written` says whether the file on
/// disk already holds the content (local publishes only).
pub fn commit_decision(
    store: &dyn Store,
    doc: &Hash,
    manifest: &FileManifest,
    msg: &SyncMessage,
    decision: &Decision,
    written: bool,
) -> Result<(), StoreError> {
    match decision {
        Decision::Bootstrap { .. } => store.commit_version(doc, manifest, msg, None, written),
        Decision::FastForward { head } => {
            store.commit_version(doc, manifest, msg, Some(*head), written)
        }
        Decision::ForkWin { head, rejected } => {
            store.switch_branch(doc, manifest, msg, *head, rejected)
        }
        Decision::Reject(_) => store.record_rejected(doc, msg),
        Decision::AlreadyKnown | Decision::Gap { .. } | Decision::Drop(_) => Ok(()),
    }
}

// ---------------------------------------------------------------------------
// Parallel fetcher
// ---------------------------------------------------------------------------

/// What one `fetch_missing` call did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FetchReport {
    /// Distinct chunks the manifest references.
    pub unique_chunks: usize,
    /// Chunks already in the store before the call.
    pub already_present: usize,
    /// Chunks fetched and stored by this call.
    pub fetched: usize,
    /// Failed attempts that were retried.
    pub retries: usize,
    /// Bytes fetched.
    pub bytes: u64,
}

#[derive(Debug, Default, Clone, Copy)]
struct Health {
    consecutive_failures: u32,
    skip_until: Option<Instant>,
}

struct FetcherInner {
    pool: Arc<ConnectionPool>,
    store: Arc<dyn Store>,
    self_id: EndpointId,
    overall: Arc<Semaphore>,
    manifests: Arc<Semaphore>,
    health: Mutex<HashMap<EndpointId, Health>>,
}

impl FetcherInner {
    fn select_provider(&self, providers: &[EndpointId], start: usize) -> EndpointId {
        let now = Instant::now();
        let health = self.health.lock();
        let n = providers.len();
        for i in 0..n {
            let p = providers[(start + i) % n];
            let skipped = health
                .get(&p)
                .and_then(|h| h.skip_until)
                .is_some_and(|until| until > now);
            if !skipped {
                return p;
            }
        }
        // Every provider is skipped: try the round-robin choice anyway.
        providers[start % n]
    }

    fn mark_failure(&self, p: EndpointId) {
        let mut health = self.health.lock();
        let h = health.entry(p).or_default();
        h.consecutive_failures += 1;
        if h.consecutive_failures >= PROVIDER_FAILURE_THRESHOLD {
            h.skip_until = Some(Instant::now() + PROVIDER_SKIP);
        }
    }

    fn mark_ok(&self, p: EndpointId) {
        let mut health = self.health.lock();
        health.insert(p, Health::default());
    }
}

/// Pulls the chunks a manifest needs from every provider that holds them,
/// in parallel, verifying each chunk before it is stored (SEC-8).
#[derive(Clone)]
pub struct ParallelFetcher {
    inner: Arc<FetcherInner>,
}

impl ParallelFetcher {
    /// A fetcher dialing through `pool` and storing into `store`. `self_id`
    /// is never used as a provider.
    pub fn new(pool: Arc<ConnectionPool>, store: Arc<dyn Store>, self_id: EndpointId) -> Self {
        ParallelFetcher {
            inner: Arc::new(FetcherInner {
                pool,
                store,
                self_id,
                overall: Arc::new(Semaphore::new(STREAMS_OVERALL)),
                manifests: Arc::new(Semaphore::new(MANIFESTS_IN_FLIGHT)),
                health: Mutex::new(HashMap::new()),
            }),
        }
    }

    /// Fetch every chunk of `manifest` that the store lacks, from
    /// `providers`. Chunks are verified against their hash and length before
    /// `put_chunk`. On a fatal error every outstanding task is aborted.
    pub async fn fetch_missing(
        &self,
        ctx: &DocContext,
        manifest: &FileManifest,
        providers: &[EndpointId],
    ) -> Result<FetchReport, SyncError> {
        let _manifest_permit = Arc::clone(&self.inner.manifests)
            .acquire_owned()
            .await
            .map_err(|e| SyncError::Task(e.to_string()))?;

        // Distinct chunks, in file order.
        let mut seen = HashSet::new();
        let mut unique: Vec<(Hash, u32)> = Vec::new();
        for c in &manifest.chunks {
            if seen.insert(c.hash) {
                unique.push((c.hash, c.length));
            }
        }
        let mut report = FetchReport {
            unique_chunks: unique.len(),
            ..FetchReport::default()
        };
        let missing: Vec<(Hash, u32)> = with_store(&self.inner.store, move |s| {
            let mut out = Vec::new();
            for (h, len) in unique {
                if !s.has_chunk(&h)? {
                    out.push((h, len));
                }
            }
            Ok(out)
        })
        .await?;
        report.already_present = report.unique_chunks - missing.len();
        if missing.is_empty() {
            return Ok(report);
        }

        let providers: Vec<EndpointId> = {
            let mut v = Vec::new();
            for p in providers {
                if *p != self.inner.self_id && !v.contains(p) {
                    v.push(*p);
                }
            }
            v
        };
        if providers.is_empty() {
            return Err(SyncError::NoProviders);
        }
        let per_provider: Arc<HashMap<EndpointId, Arc<Semaphore>>> = Arc::new(
            providers
                .iter()
                .map(|p| (*p, Arc::new(Semaphore::new(STREAMS_PER_PROVIDER))))
                .collect(),
        );
        let queue: Arc<Mutex<VecDeque<(usize, Hash, u32)>>> = Arc::new(Mutex::new(
            missing
                .into_iter()
                .enumerate()
                .map(|(i, (h, l))| (i, h, l))
                .collect(),
        ));
        let stats = Arc::new(Mutex::new(FetchReport::default()));
        let workers = queue.lock().len().min(STREAMS_OVERALL);
        let mut set = JoinSet::new();
        for _ in 0..workers {
            let inner = Arc::clone(&self.inner);
            let providers = providers.clone();
            let per_provider = Arc::clone(&per_provider);
            let queue = Arc::clone(&queue);
            let stats = Arc::clone(&stats);
            let token = ctx.token.clone();
            let doc_id = ctx.doc_id;
            set.spawn(async move {
                loop {
                    let next = queue.lock().pop_front();
                    let Some((idx, hash, len)) = next else {
                        return Ok::<(), SyncError>(());
                    };
                    fetch_one(
                        &inner,
                        &providers,
                        &per_provider,
                        &token,
                        doc_id,
                        idx,
                        hash,
                        len,
                        &stats,
                    )
                    .await?;
                }
            });
        }
        while let Some(res) = set.join_next().await {
            match res {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    set.abort_all();
                    return Err(e);
                }
                Err(e) => {
                    set.abort_all();
                    return Err(SyncError::Task(e.to_string()));
                }
            }
        }
        let s = *stats.lock();
        report.fetched = s.fetched;
        report.retries = s.retries;
        report.bytes = s.bytes;
        Ok(report)
    }
}

#[allow(clippy::too_many_arguments)] // one call site; a struct would only rename the arguments
async fn fetch_one(
    inner: &Arc<FetcherInner>,
    providers: &[EndpointId],
    per_provider: &HashMap<EndpointId, Arc<Semaphore>>,
    token: &CapabilityToken,
    doc_id: Hash,
    idx: usize,
    hash: Hash,
    len: u32,
    stats: &Mutex<FetchReport>,
) -> Result<(), SyncError> {
    for attempt in 0..CHUNK_ATTEMPTS {
        let provider = inner.select_provider(providers, idx + attempt as usize);
        let result = {
            let _overall = inner
                .overall
                .acquire()
                .await
                .map_err(|e| SyncError::Task(e.to_string()))?;
            let _slot = match per_provider.get(&provider) {
                Some(s) => Some(
                    s.acquire()
                        .await
                        .map_err(|e| SyncError::Task(e.to_string()))?,
                ),
                None => None,
            };
            async {
                let conn = inner.pool.connect(provider).await?;
                transport::get_chunk(&conn, token, doc_id, hash).await
            }
            .await
        };
        match result {
            Ok(bytes) if bytes.len() == len as usize && chunk_hash(&bytes) == hash => {
                inner.mark_ok(provider);
                let store = Arc::clone(&inner.store);
                let n = bytes.len() as u64;
                with_store(&store, move |s| s.put_chunk(hash, bytes)).await?;
                let mut st = stats.lock();
                st.fetched += 1;
                st.bytes += n;
                return Ok(());
            }
            Ok(bytes) => {
                debug!(
                    chunk = %short_hex(&hash),
                    provider = %provider.fmt_short(),
                    got = bytes.len(),
                    want = len,
                    "corrupt chunk from provider"
                );
                inner.mark_failure(provider);
            }
            Err(e) => {
                debug!(chunk = %short_hex(&hash), provider = %provider.fmt_short(), "chunk fetch failed: {e}");
                inner.mark_failure(provider);
                if matches!(e, TransportError::Connect(_)) {
                    inner.pool.evict(&provider);
                }
            }
        }
        stats.lock().retries += 1;
        if attempt + 1 < CHUNK_ATTEMPTS {
            let backoff = BACKOFF_BASE * 2u32.pow(attempt);
            let jitter = Duration::from_millis(rand::random_range(0..50u64));
            tokio::time::sleep(backoff + jitter).await;
        }
    }
    Err(SyncError::ChunkFailed {
        hash: short_hex(&hash),
        attempts: CHUNK_ATTEMPTS,
    })
}

// ---------------------------------------------------------------------------
// Sync engine
// ---------------------------------------------------------------------------

/// What happened to a local change.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PublishOutcome {
    /// Committed and announced.
    Published(VersionId),
    /// The content equals the current head: nothing to do.
    Unchanged,
    /// The head moved: nothing was announced, the bytes were kept.
    Rejected {
        /// The version that would have been published.
        version_id: VersionId,
        /// Where the bytes were kept.
        kept_at: PathBuf,
        /// The head that won.
        head: Option<VersionId>,
    },
}

/// What happened to a remote version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ApplyOutcome {
    /// Already stored: nothing done.
    AlreadyKnown,
    /// Applied as the new head and written to disk.
    Applied {
        /// The version.
        version_id: VersionId,
        /// The file it changed.
        file_name: String,
        /// Chunks fetched over the network for it.
        fetched_chunks: usize,
    },
    /// Recorded as rejected.
    Rejected {
        /// The version.
        version_id: VersionId,
        /// Why.
        reason: RejectReason,
    },
    /// Dropped without a record; the reason says why.
    Dropped(&'static str),
}

/// A rejection this node should tell its user about.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RejectedRecord {
    /// The file.
    pub file_name: String,
    /// The version or edit that lost.
    pub version_id: Option<VersionId>,
    /// Where its bytes were kept.
    pub kept_at: PathBuf,
    /// The version that won, if known.
    pub winner: Option<VersionId>,
    /// When it happened.
    pub at: SystemTime,
}

/// Notifications from the engine.
#[derive(Clone, Debug)]
pub enum SyncEvent {
    /// A local change was committed and announced.
    Published {
        /// The file.
        file_name: String,
        /// The new version.
        version_id: VersionId,
    },
    /// A remote version became head and was written to disk.
    Applied {
        /// The file.
        file_name: String,
        /// The version.
        version_id: VersionId,
        /// Chunks fetched over the network.
        fetched_chunks: usize,
    },
    /// A version this node authored, or a stale publish, lost (CON-6).
    VersionRejected {
        /// The file.
        file_name: String,
        /// The losing version.
        version_id: VersionId,
        /// Where its bytes were kept.
        kept_at: PathBuf,
        /// The winning version, if known.
        winner: Option<VersionId>,
    },
    /// An unpublished edit on disk was displaced by a remote version and kept.
    EditDisplaced {
        /// The file.
        file_name: String,
        /// Where the edit was kept.
        kept_at: PathBuf,
    },
    /// The engine wrote a file (for watcher echo suppression).
    FileWritten {
        /// The file.
        file_name: String,
    },
}

struct EngineInner {
    ctx: DocContext,
    store: Arc<dyn Store>,
    pool: Arc<ConnectionPool>,
    fetcher: ParallelFetcher,
    clock: Mutex<HlcClock>,
    file_locks: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    providers: Mutex<HashMap<Hash, Vec<EndpointId>>>,
    peers: Mutex<BTreeSet<EndpointId>>,
    rejections: Mutex<Vec<RejectedRecord>>,
    recent_writes: Mutex<HashMap<String, Instant>>,
    dedup: Mutex<LruSet<DedupKey>>,
    events: broadcast::Sender<SyncEvent>,
    outbox: mpsc::UnboundedSender<SyncMessage>,
}

/// One document's sync engine. Cloning shares state.
#[derive(Clone)]
pub struct SyncEngine {
    inner: Arc<EngineInner>,
}

/// Run a blocking store operation off the async runtime.
async fn with_store<T: Send + 'static>(
    store: &Arc<dyn Store>,
    f: impl FnOnce(&dyn Store) -> Result<T, StoreError> + Send + 'static,
) -> Result<T, SyncError> {
    let store = Arc::clone(store);
    tokio::task::spawn_blocking(move || f(store.as_ref()))
        .await
        .map_err(|e| SyncError::Task(e.to_string()))?
        .map_err(SyncError::from)
}

fn io_err(path: &Path) -> impl FnOnce(std::io::Error) -> SyncError + '_ {
    move |source| SyncError::Io {
        path: path.to_path_buf(),
        source,
    }
}

impl SyncEngine {
    /// Create the engine: makes `.p2p-sync/{tmp,rejected}`, empties `tmp`,
    /// and loads the persisted clock. Announcements the engine makes are sent
    /// to `outbox`; drive it with [`spawn_gossip_driver`].
    pub fn new(
        ctx: DocContext,
        store: Arc<dyn Store>,
        pool: Arc<ConnectionPool>,
        outbox: mpsc::UnboundedSender<SyncMessage>,
    ) -> Result<Self, SyncError> {
        let tmp = ctx.tmp_dir();
        let rejected = ctx.rejected_dir();
        std::fs::create_dir_all(&tmp).map_err(io_err(&tmp))?;
        std::fs::create_dir_all(&rejected).map_err(io_err(&rejected))?;
        for entry in std::fs::read_dir(&tmp).map_err(io_err(&tmp))? {
            let entry = entry.map_err(io_err(&tmp))?;
            let path = entry.path();
            if path.is_dir() {
                std::fs::remove_dir_all(&path).map_err(io_err(&path))?;
            } else {
                std::fs::remove_file(&path).map_err(io_err(&path))?;
            }
        }
        let clock = HlcClock::new(store.load_clock()?);
        let fetcher = ParallelFetcher::new(Arc::clone(&pool), Arc::clone(&store), ctx.node_id());
        let (events, _) = broadcast::channel(256);
        Ok(SyncEngine {
            inner: Arc::new(EngineInner {
                ctx,
                store,
                pool,
                fetcher,
                clock: Mutex::new(clock),
                file_locks: Mutex::new(HashMap::new()),
                providers: Mutex::new(HashMap::new()),
                peers: Mutex::new(BTreeSet::new()),
                rejections: Mutex::new(Vec::new()),
                recent_writes: Mutex::new(HashMap::new()),
                dedup: Mutex::new(LruSet::default()),
                events,
                outbox,
            }),
        })
    }

    /// The document context.
    pub fn ctx(&self) -> &DocContext {
        &self.inner.ctx
    }

    /// The store.
    pub fn store(&self) -> &Arc<dyn Store> {
        &self.inner.store
    }

    /// The fetcher, for direct use in tests.
    pub fn fetcher(&self) -> &ParallelFetcher {
        &self.inner.fetcher
    }

    /// Subscribe to engine events.
    pub fn subscribe_events(&self) -> broadcast::Receiver<SyncEvent> {
        self.inner.events.subscribe()
    }

    /// Remember that `peer` can serve `manifest_id`.
    pub fn add_provider(&self, manifest_id: Hash, peer: EndpointId) {
        if peer == self.inner.ctx.node_id() {
            return;
        }
        let mut p = self.inner.providers.lock();
        let list = p.entry(manifest_id).or_default();
        if !list.contains(&peer) {
            list.push(peer);
        }
        self.inner.peers.lock().insert(peer);
    }

    /// Remember a peer for catch-up.
    pub fn add_peer(&self, peer: EndpointId) {
        if peer != self.inner.ctx.node_id() {
            self.inner.peers.lock().insert(peer);
        }
    }

    /// Known providers per manifest.
    pub fn known_providers(&self) -> Vec<(Hash, Vec<EndpointId>)> {
        let p = self.inner.providers.lock();
        let mut out: Vec<(Hash, Vec<EndpointId>)> =
            p.iter().map(|(k, v)| (*k, v.clone())).collect();
        out.sort_by_key(|(k, _)| *k);
        out
    }

    /// Known peers.
    pub fn peers(&self) -> Vec<EndpointId> {
        self.inner.peers.lock().iter().copied().collect()
    }

    /// Rejections not yet cleared by the user.
    pub fn rejections(&self) -> Vec<RejectedRecord> {
        self.inner.rejections.lock().clone()
    }

    /// Forget the listed rejections.
    pub fn clear_rejections(&self) {
        self.inner.rejections.lock().clear();
    }

    /// Whether the engine wrote `file_name` within `within`. Consumes the
    /// record. For the watcher's echo suppression.
    pub fn take_recent_write(&self, file_name: &str, within: Duration) -> bool {
        let mut w = self.inner.recent_writes.lock();
        match w.remove(file_name) {
            Some(at) => at.elapsed() <= within,
            None => false,
        }
    }

    /// Current heads with their file names, for `status`.
    pub fn heads(&self) -> Result<Vec<(String, HeadInfo)>, SyncError> {
        let store = &self.inner.store;
        let doc = self.inner.ctx.doc_id;
        let mut out = Vec::new();
        for msg in store.heads(&doc)? {
            let Some(manifest) = store.get_manifest(&doc, msg.manifest_id())? else {
                continue;
            };
            if let Some(h) = store.head(&doc, &manifest.file_name)? {
                out.push((manifest.file_name, h));
            }
        }
        Ok(out)
    }

    fn file_lock(&self, file_name: &str) -> Arc<tokio::sync::Mutex<()>> {
        let mut locks = self.inner.file_locks.lock();
        Arc::clone(
            locks
                .entry(file_name.to_string())
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(()))),
        )
    }

    async fn persist_clock(&self, hlc: Hlc) -> Result<(), SyncError> {
        with_store(&self.inner.store, move |s| s.save_clock(hlc)).await
    }

    async fn clock_now(&self) -> Result<Hlc, SyncError> {
        let hlc = self.inner.clock.lock().now(physical_now_ms());
        self.persist_clock(hlc).await?;
        Ok(hlc)
    }

    async fn clock_observe(&self, remote: Hlc) -> Result<(), SyncError> {
        let observed = self.inner.clock.lock().observe(remote, physical_now_ms())?;
        self.persist_clock(observed).await
    }

    fn emit(&self, event: SyncEvent) {
        let _ = self.inner.events.send(event);
    }

    fn providers_for(&self, v: &VersionInfo, hints: &[EndpointId]) -> Vec<EndpointId> {
        let me = self.inner.ctx.node_id();
        let mut out: Vec<EndpointId> = Vec::new();
        let mut push = |p: EndpointId| {
            if p != me && !out.contains(&p) {
                out.push(p);
            }
        };
        if let Ok(author) = EndpointId::from_bytes(&v.author) {
            push(author);
        }
        for h in hints {
            push(*h);
        }
        if let Some(list) = self.inner.providers.lock().get(&v.manifest_id) {
            for p in list {
                push(*p);
            }
        }
        out
    }

    // -- publishing ---------------------------------------------------------

    /// Publish the bytes of `file_name` on top of the current head (steps 2
    /// to 6 of "Publishing a local change").
    pub async fn publish_local_change(
        &self,
        file_name: &str,
        bytes: Vec<u8>,
    ) -> Result<PublishOutcome, SyncError> {
        self.publish_inner(file_name, bytes, None).await
    }

    /// Publish on top of an explicit base head. If the store's head is not
    /// `base` at commit time the publish is rejected (CON-1, CON-2): nothing
    /// is announced, no chunk becomes servable, the bytes are kept.
    pub async fn publish_from(
        &self,
        file_name: &str,
        bytes: Vec<u8>,
        base: Option<VersionId>,
    ) -> Result<PublishOutcome, SyncError> {
        self.publish_inner(file_name, bytes, Some(base)).await
    }

    /// Read `file_name` from the document directory and publish it.
    pub async fn publish_file(&self, file_name: &str) -> Result<PublishOutcome, SyncError> {
        let path = confined_path(&self.inner.ctx.doc_dir, file_name)?;
        let p = path.clone();
        let bytes = tokio::task::spawn_blocking(move || std::fs::read(&p))
            .await
            .map_err(|e| SyncError::Task(e.to_string()))?
            .map_err(io_err(&path))?;
        self.publish_local_change(file_name, bytes).await
    }

    async fn publish_inner(
        &self,
        file_name: &str,
        bytes: Vec<u8>,
        base: Option<Option<VersionId>>,
    ) -> Result<PublishOutcome, SyncError> {
        let ctx = &self.inner.ctx;
        if !ctx.can_write() {
            return Err(SyncError::NotWritable);
        }
        let lock = self.file_lock(file_name);
        let _guard = lock.lock().await;

        let doc = ctx.doc_id;
        let name = file_name.to_string();
        let head = with_store(&self.inner.store, move |s| s.head(&doc, &name)).await?;
        let expected = base.unwrap_or(head.map(|h| h.version_id));

        let name = file_name.to_string();
        let data = bytes;
        let (payload, data) =
            tokio::task::spawn_blocking(move || chunk_bytes(&name, &data).map(|p| (p, data)))
                .await
                .map_err(|e| SyncError::Task(e.to_string()))??;
        let manifest = payload.manifest.clone();
        let manifest_id = manifest.id();

        // Store the chunks; they are not servable until the commit registers them.
        let chunks: Vec<(Hash, Vec<u8>)> =
            payload.iter().map(|(r, b)| (r.hash, b.clone())).collect();
        with_store(&self.inner.store, move |s| {
            for (h, b) in chunks {
                s.put_chunk(h, b)?;
            }
            Ok(())
        })
        .await?;

        if let Some(h) = &head {
            if h.manifest_id == manifest_id && expected == Some(h.version_id) {
                return Ok(PublishOutcome::Unchanged);
            }
            self.clock_observe(h.hlc).await?;
        }
        let hlc = self.clock_now().await?;
        let msg = SyncMessage::new_version(
            &ctx.secret,
            doc,
            manifest_id,
            expected,
            hlc,
            ctx.token.clone(),
        );
        let version_id = msg
            .version_id()
            .ok_or(SyncError::InvalidVersion("not a NewVersion"))?;

        let m = manifest.clone();
        let msg_for_store = msg.clone();
        let result = with_store(&self.inner.store, move |s| {
            s.commit_version(&doc, &m, &msg_for_store, expected, true)
        })
        .await;
        match result {
            Ok(()) => {
                self.add_own_provider(manifest_id);
                let _ = self.inner.outbox.send(msg);
                self.emit(SyncEvent::Published {
                    file_name: file_name.to_string(),
                    version_id,
                });
                info!(file = file_name, version = %short_hex(&version_id), "published");
                Ok(PublishOutcome::Published(version_id))
            }
            Err(SyncError::Store(StoreError::HeadMoved { actual, .. })) => {
                let kept_at = self
                    .keep_bytes(file_name, &short_hex(&version_id), &data)
                    .await?;
                self.record_rejection(file_name, Some(version_id), kept_at.clone(), actual);
                info!(file = file_name, version = %short_hex(&version_id), "publish rejected: head moved");
                Ok(PublishOutcome::Rejected {
                    version_id,
                    kept_at,
                    head: actual,
                })
            }
            Err(e) => Err(e),
        }
    }

    fn add_own_provider(&self, manifest_id: Hash) {
        // Recorded for `status`; `providers_for` never dials ourselves.
        let _ = manifest_id;
    }

    fn record_rejection(
        &self,
        file_name: &str,
        version_id: Option<VersionId>,
        kept_at: PathBuf,
        winner: Option<VersionId>,
    ) {
        self.inner.rejections.lock().push(RejectedRecord {
            file_name: file_name.to_string(),
            version_id,
            kept_at: kept_at.clone(),
            winner,
            at: SystemTime::now(),
        });
        match version_id {
            Some(version_id) => self.emit(SyncEvent::VersionRejected {
                file_name: file_name.to_string(),
                version_id,
                kept_at,
                winner,
            }),
            None => self.emit(SyncEvent::EditDisplaced {
                file_name: file_name.to_string(),
                kept_at,
            }),
        }
    }

    /// Write `bytes` under `.p2p-sync/rejected/<file_name>.<tag>`.
    async fn keep_bytes(
        &self,
        file_name: &str,
        tag: &str,
        bytes: &[u8],
    ) -> Result<PathBuf, SyncError> {
        let path = self
            .inner
            .ctx
            .rejected_dir()
            .join(format!("{file_name}.{tag}"));
        let p = path.clone();
        let data = bytes.to_vec();
        tokio::task::spawn_blocking(move || -> Result<(), std::io::Error> {
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&p, data)
        })
        .await
        .map_err(|e| SyncError::Task(e.to_string()))?
        .map_err(io_err(&path))?;
        Ok(path)
    }

    // -- applying -----------------------------------------------------------

    /// Handle a validated announcement: `Have` records a provider,
    /// `NewVersion` is applied. Returns `None` for `Have`.
    pub async fn handle_announcement(
        &self,
        msg: &SyncMessage,
        delivered_from: Option<EndpointId>,
    ) -> Result<Option<ApplyOutcome>, SyncError> {
        if let Some(from) = delivered_from {
            self.add_peer(from);
        }
        match msg {
            SyncMessage::Have {
                manifest_id,
                provider,
                ..
            } => {
                if let Ok(p) = EndpointId::from_bytes(provider) {
                    self.add_provider(*manifest_id, p);
                }
                Ok(None)
            }
            SyncMessage::NewVersion { author, .. } => {
                if let Ok(a) = EndpointId::from_bytes(author) {
                    self.add_peer(a);
                }
                self.apply_remote(msg, &[]).await.map(Some)
            }
        }
    }

    /// Apply a validated remote `NewVersion` by the section 8 rules. `hints`
    /// are extra peers that may serve its data (the author and known `Have`
    /// senders are always tried).
    pub async fn apply_remote(
        &self,
        msg: &SyncMessage,
        hints: &[EndpointId],
    ) -> Result<ApplyOutcome, SyncError> {
        self.apply_inner(msg, hints, true).await
    }

    async fn apply_inner(
        &self,
        msg: &SyncMessage,
        hints: &[EndpointId],
        allow_gap: bool,
    ) -> Result<ApplyOutcome, SyncError> {
        let doc = self.inner.ctx.doc_id;
        if msg.doc_id() != &doc {
            return Err(SyncError::InvalidVersion("version names another document"));
        }
        let v =
            VersionInfo::from_message(msg).ok_or(SyncError::InvalidVersion("not a NewVersion"))?;
        let id = v.id;
        if with_store(&self.inner.store, move |s| s.version(&doc, &id))
            .await?
            .is_some()
        {
            return Ok(ApplyOutcome::AlreadyKnown);
        }
        let providers = self.providers_for(&v, hints);
        let manifest = self.obtain_manifest(&v.manifest_id, &providers).await?;
        let file_name = manifest.file_name.clone();

        let lock = self.file_lock(&file_name);
        let guard = lock.lock().await;
        let name = file_name.clone();
        let decision =
            with_store(&self.inner.store, move |s| decide_store(s, &doc, &name, &v)).await?;
        debug!(file = %file_name, version = %short_hex(&v.id), ?decision, "decided");
        match decision {
            Decision::AlreadyKnown => Ok(ApplyOutcome::AlreadyKnown),
            Decision::Drop(reason) => Ok(ApplyOutcome::Dropped(reason)),
            Decision::Reject(reason) => {
                let m = msg.clone();
                with_store(&self.inner.store, move |s| s.record_rejected(&doc, &m)).await?;
                Ok(ApplyOutcome::Rejected {
                    version_id: v.id,
                    reason,
                })
            }
            Decision::Gap { missing } => {
                drop(guard);
                if !allow_gap {
                    return Ok(ApplyOutcome::Dropped("ancestors did not connect"));
                }
                let ancestors = match self.fetch_ancestors(missing, &providers).await {
                    Ok(a) => a,
                    Err(SyncError::Dropped(reason)) => {
                        debug!(version = %short_hex(&v.id), "dropped: {reason}");
                        return Ok(ApplyOutcome::Dropped(reason));
                    }
                    Err(e) => return Err(e),
                };
                for ancestor in ancestors.iter().rev() {
                    Box::pin(self.apply_inner(ancestor, &providers, false)).await?;
                }
                Box::pin(self.apply_inner(msg, hints, false)).await
            }
            Decision::Bootstrap {
                ancestry_missing: Some(missing),
            } if allow_gap => {
                // Record the ancestry first so later forks can be resolved;
                // if it cannot be fetched, bootstrap without it as section 8
                // allows.
                drop(guard);
                match self.fetch_ancestors(missing, &providers).await {
                    Ok(ancestors) => {
                        for a in ancestors {
                            with_store(&self.inner.store, move |s| s.record_version(&doc, &a))
                                .await?;
                        }
                    }
                    Err(SyncError::Dropped(reason)) => {
                        debug!(version = %short_hex(&v.id), "bootstrapping without ancestry: {reason}");
                    }
                    Err(e) => return Err(e),
                }
                Box::pin(self.apply_inner(msg, hints, false)).await
            }
            Decision::Bootstrap { .. }
            | Decision::FastForward { .. }
            | Decision::ForkWin { .. } => {
                self.apply_winner(msg, &v, &manifest, &providers, decision)
                    .await
            }
        }
    }

    /// Steps 1 to 6 of "To apply a winning version". Called with the file lock held.
    async fn apply_winner(
        &self,
        msg: &SyncMessage,
        v: &VersionInfo,
        manifest: &FileManifest,
        providers: &[EndpointId],
        decision: Decision,
    ) -> Result<ApplyOutcome, SyncError> {
        let doc = self.inner.ctx.doc_id;
        let file_name = manifest.file_name.clone();
        let me = self.inner.ctx.node_id_bytes();

        // 2. Missing chunks.
        let report = if manifest.chunks.is_empty() {
            FetchReport::default()
        } else {
            self.inner
                .fetcher
                .fetch_missing(&self.inner.ctx, manifest, providers)
                .await?
        };

        // 3. Preserve what is about to be lost (CON-6).
        let name = file_name.clone();
        let head = with_store(&self.inner.store, move |s| s.head(&doc, &name)).await?;
        let mut own_losses: Vec<(VersionId, PathBuf)> = Vec::new();
        if let Decision::ForkWin { rejected, .. } = &decision {
            for id in rejected {
                let rid = *id;
                let lost = with_store(&self.inner.store, move |s| s.version(&doc, &rid)).await?;
                let Some(lost) = lost else { continue };
                if lost.signer() != &me {
                    continue;
                }
                let mid = *lost.manifest_id();
                let lost_manifest =
                    with_store(&self.inner.store, move |s| s.get_manifest(&doc, &mid)).await?;
                let Some(lost_manifest) = lost_manifest else {
                    continue;
                };
                let bytes = self.assemble(&lost_manifest).await?;
                let kept = self.keep_bytes(&file_name, &short_hex(id), &bytes).await?;
                own_losses.push((*id, kept));
            }
        }
        if let Some(kept) = self
            .preserve_unpublished_edit(&file_name, head.as_ref())
            .await?
        {
            self.record_rejection(&file_name, None, kept, Some(v.id));
        }

        // 4. Commit before writing, so a crash cannot leave the winner's
        //    content on disk under an old head.
        let m = manifest.clone();
        let msg_for_store = msg.clone();
        let d = decision.clone();
        match with_store(&self.inner.store, move |s| {
            commit_decision(s, &doc, &m, &msg_for_store, &d, false)
        })
        .await
        {
            Ok(()) => {}
            Err(SyncError::Store(StoreError::HeadMoved { .. })) => {
                return Err(SyncError::HeadMoved)
            }
            Err(e) => return Err(e),
        }
        for (id, kept) in own_losses {
            self.record_rejection(&file_name, Some(id), kept, Some(v.id));
        }

        // 5. Write atomically, then mark written.
        self.write_file(manifest).await?;
        let name = file_name.clone();
        let vid = v.id;
        with_store(&self.inner.store, move |s| {
            s.mark_written(&doc, &name, &vid)
        })
        .await?;

        // 6. Clock, echo suppression, announce.
        self.clock_observe(v.hlc).await?;
        self.inner
            .recent_writes
            .lock()
            .insert(file_name.clone(), Instant::now());
        let have = SyncMessage::have(
            &self.inner.ctx.secret,
            doc,
            v.manifest_id,
            self.inner.ctx.token.clone(),
        );
        let _ = self.inner.outbox.send(have);
        self.emit(SyncEvent::FileWritten {
            file_name: file_name.clone(),
        });
        self.emit(SyncEvent::Applied {
            file_name: file_name.clone(),
            version_id: v.id,
            fetched_chunks: report.fetched,
        });
        info!(file = %file_name, version = %short_hex(&v.id), fetched = report.fetched, "applied");
        Ok(ApplyOutcome::Applied {
            version_id: v.id,
            file_name,
            fetched_chunks: report.fetched,
        })
    }

    /// If the file on disk differs from `head`'s content (or exists while
    /// there is no head), keep it under `.p2p-sync/rejected/`.
    async fn preserve_unpublished_edit(
        &self,
        file_name: &str,
        head: Option<&HeadInfo>,
    ) -> Result<Option<PathBuf>, SyncError> {
        let path = confined_path(&self.inner.ctx.doc_dir, file_name)?;
        let p = path.clone();
        let name = file_name.to_string();
        let on_disk =
            tokio::task::spawn_blocking(move || -> Result<Option<(Hash, Vec<u8>)>, SyncError> {
                let bytes = match std::fs::read(&p) {
                    Ok(b) => b,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                    Err(e) => return Err(io_err(&p)(e)),
                };
                let id = chunk_bytes(&name, &bytes)?.manifest.id();
                Ok(Some((id, bytes)))
            })
            .await
            .map_err(|e| SyncError::Task(e.to_string()))??;
        let Some((disk_id, bytes)) = on_disk else {
            return Ok(None);
        };
        let matches_head = head.is_some_and(|h| h.manifest_id == disk_id);
        if matches_head {
            return Ok(None);
        }
        let tag = format!("unpublished.{}", short_hex(&disk_id));
        let kept = self.keep_bytes(file_name, &tag, &bytes).await?;
        info!(file = file_name, kept = %kept.display(), "unpublished edit displaced; kept");
        Ok(Some(kept))
    }

    /// The manifest, from the store if committed locally, else from the
    /// first provider that serves it. Its ID is recomputed and it is
    /// validated before use (SEC-8, SEC-9).
    async fn obtain_manifest(
        &self,
        manifest_id: &Hash,
        providers: &[EndpointId],
    ) -> Result<FileManifest, SyncError> {
        let doc = self.inner.ctx.doc_id;
        let mid = *manifest_id;
        if let Some(m) = with_store(&self.inner.store, move |s| s.get_manifest(&doc, &mid)).await? {
            return Ok(m);
        }
        if providers.is_empty() {
            return Err(SyncError::NoProviders);
        }
        let mut last: Option<SyncError> = None;
        for p in providers {
            let fetched = async {
                let conn = self.inner.pool.connect(*p).await?;
                transport::get_manifest(&conn, &self.inner.ctx.token, doc, mid).await
            }
            .await;
            match fetched {
                Ok(m) => {
                    if m.id() != mid {
                        warn!(provider = %p.fmt_short(), manifest = %short_hex(&mid), "manifest id mismatch");
                        last = Some(SyncError::ManifestMismatch);
                        continue;
                    }
                    m.validate()?;
                    return Ok(m);
                }
                Err(e) => {
                    debug!(provider = %p.fmt_short(), "manifest fetch failed: {e}");
                    last = Some(SyncError::Transport(e));
                }
            }
        }
        Err(last.unwrap_or(SyncError::ManifestUnavailable(short_hex(&mid))))
    }

    /// Walk back from `missing` with `GetVersion` until a locally known
    /// version or a root is reached, at most [`MAX_GAP_STEPS`] steps. Returns
    /// the fetched versions newest first, each validated like an announcement.
    async fn fetch_ancestors(
        &self,
        missing: VersionId,
        providers: &[EndpointId],
    ) -> Result<Vec<SyncMessage>, SyncError> {
        let doc = self.inner.ctx.doc_id;
        let owner = self.inner.ctx.owner_key;
        let mut out = Vec::new();
        let mut next = Some(missing);
        while let Some(id) = next {
            if out.len() >= MAX_GAP_STEPS {
                return Err(SyncError::Dropped("ancestor chain longer than 64 steps"));
            }
            if with_store(&self.inner.store, move |s| s.version(&doc, &id))
                .await?
                .is_some()
            {
                break;
            }
            let mut fetched: Option<SyncMessage> = None;
            for p in providers {
                let r = async {
                    let conn = self.inner.pool.connect(*p).await?;
                    transport::get_version(&conn, &self.inner.ctx.token, doc, id).await
                }
                .await;
                match r {
                    Ok(m) => {
                        fetched = Some(m);
                        break;
                    }
                    Err(e) => debug!(provider = %p.fmt_short(), "ancestor fetch failed: {e}"),
                }
            }
            let Some(msg) = fetched else {
                return Err(SyncError::Dropped("an ancestor is unavailable"));
            };
            validate_decoded(&msg, &doc, &owner, unix_now_secs(), physical_now_ms())?;
            let info = VersionInfo::from_message(&msg)
                .ok_or(SyncError::InvalidVersion("ancestor is not a NewVersion"))?;
            if info.id != id {
                return Err(SyncError::Dropped("provider returned the wrong version"));
            }
            next = info.parent;
            out.push(msg);
        }
        Ok(out)
    }

    /// Reassemble a manifest's bytes from the store.
    async fn assemble(&self, manifest: &FileManifest) -> Result<Vec<u8>, SyncError> {
        let m = manifest.clone();
        with_store(&self.inner.store, move |s| {
            let mut out = Vec::with_capacity(m.total_size as usize);
            for c in &m.chunks {
                match s.get_chunk(&c.hash)? {
                    Some(b) => out.extend_from_slice(&b),
                    None => return Err(StoreError::InvalidVersion("chunk missing from store")),
                }
            }
            Ok(out)
        })
        .await
    }

    /// Assemble into `.p2p-sync/tmp/`, fsync, then rename over the target,
    /// which is confined to the document directory (SEC-9).
    async fn write_file(&self, manifest: &FileManifest) -> Result<(), SyncError> {
        let bytes = self.assemble(manifest).await?;
        let target = confined_path(&self.inner.ctx.doc_dir, &manifest.file_name)?;
        let tmp = self.inner.ctx.tmp_dir().join(format!(
            "{}-{}",
            short_hex(&manifest.id()),
            hex::encode(rand::random::<[u8; 4]>())
        ));
        let (t, tg) = (tmp.clone(), target.clone());
        tokio::task::spawn_blocking(move || -> Result<(), SyncError> {
            {
                let mut f = std::fs::File::create(&t).map_err(io_err(&t))?;
                std::io::Write::write_all(&mut f, &bytes).map_err(io_err(&t))?;
                f.sync_all().map_err(io_err(&t))?;
            }
            if let Some(parent) = tg.parent() {
                std::fs::create_dir_all(parent).map_err(io_err(parent))?;
            }
            std::fs::rename(&t, &tg).map_err(io_err(&tg))?;
            Ok(())
        })
        .await
        .map_err(|e| SyncError::Task(e.to_string()))?
    }

    // -- catch-up and repair -------------------------------------------------

    /// Fetch `provider`'s heads and apply each one that validates. Returns
    /// how many versions became head here.
    pub async fn catch_up(&self, provider: EndpointId) -> Result<usize, SyncError> {
        let doc = self.inner.ctx.doc_id;
        let conn = self.inner.pool.connect(provider).await?;
        let heads = transport::get_heads(&conn, &self.inner.ctx.token, doc).await?;
        self.add_peer(provider);
        let mut applied = 0;
        for msg in heads.into_iter().take(MAX_HEADS) {
            if let Err(e) = validate_decoded(
                &msg,
                &doc,
                &self.inner.ctx.owner_key,
                unix_now_secs(),
                physical_now_ms(),
            ) {
                debug!(provider = %provider.fmt_short(), "head entry rejected: {e}");
                continue;
            }
            match self.apply_remote(&msg, &[provider]).await {
                Ok(ApplyOutcome::Applied { .. }) => applied += 1,
                Ok(_) => {}
                Err(e) => warn!(provider = %provider.fmt_short(), "catch-up apply failed: {e}"),
            }
        }
        Ok(applied)
    }

    /// Catch up from one random known peer, if any.
    pub async fn catch_up_any(&self) -> Result<Option<usize>, SyncError> {
        let peers = self.peers();
        if peers.is_empty() {
            return Ok(None);
        }
        let p = peers[rand::random_range(0..peers.len())];
        self.catch_up(p).await.map(Some)
    }

    /// Write every head whose content is not yet on disk (a crash between
    /// commit and write). Call before the watcher starts.
    pub async fn repair_unwritten_heads(&self) -> Result<usize, SyncError> {
        let doc = self.inner.ctx.doc_id;
        let heads = with_store(&self.inner.store, move |s| s.unwritten_heads(&doc)).await?;
        let mut repaired = 0;
        for h in heads {
            let mid = h.manifest_id;
            let Some(manifest) =
                with_store(&self.inner.store, move |s| s.get_manifest(&doc, &mid)).await?
            else {
                warn!(manifest = %short_hex(&mid), "unwritten head has no manifest");
                continue;
            };
            let lock = self.file_lock(&manifest.file_name);
            let _guard = lock.lock().await;
            self.write_file(&manifest).await?;
            let name = manifest.file_name.clone();
            let vid = h.version_id;
            with_store(&self.inner.store, move |s| {
                s.mark_written(&doc, &name, &vid)
            })
            .await?;
            self.inner
                .recent_writes
                .lock()
                .insert(manifest.file_name.clone(), Instant::now());
            self.emit(SyncEvent::FileWritten {
                file_name: manifest.file_name.clone(),
            });
            repaired += 1;
        }
        Ok(repaired)
    }

    /// Validate a raw gossip frame against this document with the engine's
    /// de-duplication set.
    pub fn validate_frame(&self, bytes: &[u8]) -> Result<SyncMessage, GossipError> {
        let mut dedup = self.inner.dedup.lock();
        validate_message(
            bytes,
            &self.inner.ctx.doc_id,
            &self.inner.ctx.owner_key,
            unix_now_secs(),
            physical_now_ms(),
            &mut dedup,
        )
    }
}

fn decide_store(
    store: &dyn Store,
    doc: &Hash,
    file_name: &str,
    v: &VersionInfo,
) -> Result<Decision, StoreError> {
    match decide(store, doc, file_name, v) {
        Ok(d) => Ok(d),
        Err(SyncError::Store(e)) => Err(e),
        Err(e) => Err(StoreError::InvalidVersion(match e {
            SyncError::InvalidVersion(s) | SyncError::Dropped(s) => s,
            _ => "decision failed",
        })),
    }
}

/// Drive a topic subscription: validated announcements are handled by the
/// engine, and messages the engine sends to its outbox are broadcast.
pub fn spawn_gossip_driver(
    engine: SyncEngine,
    sub: TopicSubscription,
    outbox: mpsc::UnboundedReceiver<SyncMessage>,
) -> JoinHandle<()> {
    let (_always_online, online) = watch::channel(true);
    spawn_gossip_driver_gated(engine, sub, outbox, online)
}

/// Like [`spawn_gossip_driver`] with an on/off switch. While `online` is
/// `false` the driver holds outgoing messages and drops incoming ones, which
/// simulates a network partition; flipping it back broadcasts what was held.
/// Peers reconcile anything missed through `catch_up`.
pub fn spawn_gossip_driver_gated(
    engine: SyncEngine,
    mut sub: TopicSubscription,
    mut outbox: mpsc::UnboundedReceiver<SyncMessage>,
    mut online: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut held: Vec<SyncMessage> = Vec::new();
        // Once the switch's sender is gone the state is fixed; stop polling it.
        let mut switch_alive = true;
        loop {
            let is_online = *online.borrow();
            if is_online {
                for msg in held.drain(..) {
                    if let Err(e) = sub.broadcast(&msg).await {
                        warn!("broadcast of held message failed: {e}");
                    }
                }
            }
            tokio::select! {
                out = outbox.recv() => {
                    match out {
                        Some(msg) if is_online => {
                            if let Err(e) = sub.broadcast(&msg).await {
                                warn!("broadcast failed: {e}");
                            }
                        }
                        Some(msg) => held.push(msg),
                        None => break,
                    }
                }
                ann = sub.next_announcement() => {
                    match ann {
                        None => break,
                        Some(Err(e)) => warn!("gossip stream error: {e}"),
                        Some(Ok(_)) if !is_online => {
                            debug!("offline: announcement dropped");
                        }
                        Some(Ok(raw)) => match engine.validate_frame(&raw.bytes) {
                            Ok(msg) => {
                                let engine = engine.clone();
                                tokio::spawn(async move {
                                    if let Err(e) = engine
                                        .handle_announcement(&msg, Some(raw.delivered_from))
                                        .await
                                    {
                                        warn!("announcement not applied: {e}");
                                    }
                                });
                            }
                            Err(e) => debug!("announcement dropped: {e}"),
                        },
                    }
                }
                changed = online.changed(), if switch_alive => {
                    if changed.is_err() {
                        switch_alive = false;
                    }
                }
            }
        }
    })
}

/// Catch up from a random known peer now and then every `interval`.
pub fn spawn_catch_up_task(engine: SyncEngine, interval: Duration) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            match engine.catch_up_any().await {
                Ok(Some(n)) => debug!(applied = n, "catch-up done"),
                Ok(None) => debug!("catch-up skipped: no known peers"),
                Err(e) => warn!("catch-up failed: {e}"),
            }
            tokio::time::sleep(interval).await;
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capabilities::{CapabilityClaims, CapabilityToken};
    use crate::crypto::generate_signing_key;
    use crate::storage::MemStore;
    use ed25519_dalek::Signature;
    use proptest::prelude::*;

    const DOC: Hash = [1u8; 32];
    const FILE: &str = "f";

    fn token(audience: [u8; 32]) -> CapabilityToken {
        CapabilityToken::issue(
            CapabilityClaims {
                doc_id: DOC,
                audience,
                can_read: true,
                can_write: true,
                not_before: 0,
                expires_at: u64::MAX,
            },
            &generate_signing_key(),
        )
    }

    fn manifest() -> FileManifest {
        FileManifest {
            file_name: FILE.into(),
            total_size: 0,
            chunks: vec![],
        }
    }

    /// An unsigned version: `decide` never checks signatures.
    fn version(parent: Option<VersionId>, hlc: Hlc, author: [u8; 32]) -> SyncMessage {
        SyncMessage::NewVersion {
            doc_id: DOC,
            manifest_id: manifest().id(),
            parent,
            hlc,
            author,
            token: token(author),
            signature: Signature::from_bytes(&[0u8; 64]),
        }
    }

    fn info(m: &SyncMessage) -> VersionInfo {
        VersionInfo::from_message(m).unwrap()
    }

    fn apply(store: &MemStore, m: &SyncMessage) -> Decision {
        let d = decide(store, &DOC, FILE, &info(m)).unwrap();
        commit_decision(store, &DOC, &manifest(), m, &d, true).unwrap();
        d
    }

    fn head(store: &MemStore) -> Option<VersionId> {
        store.head(&DOC, FILE).unwrap().map(|h| h.version_id)
    }

    #[test]
    fn bootstrap_fast_forward_and_already_known() {
        let s = MemStore::new();
        let v0 = version(None, Hlc::new(10, 0), [1; 32]);
        assert_eq!(
            apply(&s, &v0),
            Decision::Bootstrap {
                ancestry_missing: None
            }
        );
        assert_eq!(head(&s), v0.version_id());
        let v1 = version(v0.version_id(), Hlc::new(11, 0), [1; 32]);
        assert!(matches!(apply(&s, &v1), Decision::FastForward { .. }));
        assert_eq!(head(&s), v1.version_id());
        assert_eq!(apply(&s, &v1), Decision::AlreadyKnown);
        assert_eq!(apply(&s, &v0), Decision::AlreadyKnown);
    }

    /// CON-5: a child whose clock is not after its parent's is rejected.
    #[test]
    fn con5_clock_not_after_parent_is_rejected() {
        let s = MemStore::new();
        let v0 = version(None, Hlc::new(10, 0), [1; 32]);
        apply(&s, &v0);
        let bad = version(v0.version_id(), Hlc::new(10, 0), [2; 32]);
        assert_eq!(
            apply(&s, &bad),
            Decision::Reject(RejectReason::ClockNotAfterParent)
        );
        assert!(s.is_rejected(&DOC, &bad.version_id().unwrap()).unwrap());
        assert_eq!(head(&s), v0.version_id());
        // Same for a fork sibling that is not after the shared parent.
        let v1 = version(v0.version_id(), Hlc::new(12, 0), [1; 32]);
        apply(&s, &v1);
        let bad2 = version(v0.version_id(), Hlc::new(9, 0), [0; 32]);
        assert_eq!(
            apply(&s, &bad2),
            Decision::Reject(RejectReason::ClockNotAfterParent)
        );
        assert_eq!(head(&s), v1.version_id());
    }

    /// CON-3: same parent, either order, smaller (hlc, author) wins.
    #[test]
    fn con3_fork_resolves_the_same_in_either_order() {
        let v0 = version(None, Hlc::new(10, 0), [1; 32]);
        let a = version(v0.version_id(), Hlc::new(20, 0), [5; 32]);
        let b = version(v0.version_id(), Hlc::new(20, 0), [3; 32]); // smaller author wins
        let c = version(v0.version_id(), Hlc::new(19, 9), [9; 32]); // smaller hlc wins over both

        for order in [[&a, &b, &c], [&c, &b, &a], [&b, &a, &c], [&a, &c, &b]] {
            let s = MemStore::new();
            apply(&s, &v0);
            for m in order {
                apply(&s, m);
            }
            assert_eq!(
                head(&s),
                c.version_id(),
                "order {:?}",
                order.map(|m| m.version_id())
            );
            assert!(s.is_rejected(&DOC, &a.version_id().unwrap()).unwrap());
            assert!(s.is_rejected(&DOC, &b.version_id().unwrap()).unwrap());
            assert!(!s.is_rejected(&DOC, &c.version_id().unwrap()).unwrap());
        }
    }

    /// CON-4: a child of a rejected version is rejected; a fork winner that
    /// arrives after a losing branch of three rejects all three.
    #[test]
    fn con4_rejected_parent_and_late_winner() {
        let s = MemStore::new();
        let v0 = version(None, Hlc::new(10, 0), [1; 32]);
        apply(&s, &v0);
        let b1 = version(v0.version_id(), Hlc::new(20, 0), [7; 32]);
        let b2 = version(b1.version_id(), Hlc::new(21, 0), [7; 32]);
        let b3 = version(b2.version_id(), Hlc::new(22, 0), [7; 32]);
        apply(&s, &b1);
        apply(&s, &b2);
        apply(&s, &b3);
        assert_eq!(head(&s), b3.version_id());

        let winner = version(v0.version_id(), Hlc::new(15, 0), [8; 32]);
        let d = apply(&s, &winner);
        match &d {
            Decision::ForkWin { head: h, rejected } => {
                assert_eq!(Some(*h), b3.version_id());
                assert_eq!(
                    rejected,
                    &vec![
                        b3.version_id().unwrap(),
                        b2.version_id().unwrap(),
                        b1.version_id().unwrap()
                    ]
                );
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(head(&s), winner.version_id());
        for b in [&b1, &b2, &b3] {
            assert!(s.is_rejected(&DOC, &b.version_id().unwrap()).unwrap());
        }
        // A child of the rejected branch is rejected.
        let b4 = version(b3.version_id(), Hlc::new(23, 0), [7; 32]);
        assert_eq!(
            apply(&s, &b4),
            Decision::Reject(RejectReason::ParentRejected)
        );
        assert_eq!(head(&s), winner.version_id());
        // A late loser at the same fork is rejected too.
        let late = version(v0.version_id(), Hlc::new(16, 0), [8; 32]);
        assert!(matches!(
            apply(&s, &late),
            Decision::Reject(RejectReason::LostFork { .. })
        ));
    }

    #[test]
    fn unknown_parent_is_a_gap_and_unconnected_root_is_dropped() {
        let s = MemStore::new();
        let v0 = version(None, Hlc::new(10, 0), [1; 32]);
        apply(&s, &v0);
        let orphan = version(Some([9u8; 32]), Hlc::new(30, 0), [2; 32]);
        assert_eq!(
            decide(&s, &DOC, FILE, &info(&orphan)).unwrap(),
            Decision::Gap { missing: [9u8; 32] }
        );
        let other_root = version(None, Hlc::new(30, 0), [2; 32]);
        // Two roots for the same file fork at "no parent": the earlier wins.
        assert!(matches!(
            decide(&s, &DOC, FILE, &info(&other_root)).unwrap(),
            Decision::Reject(RejectReason::LostFork { .. })
        ));
        let earlier_root = version(None, Hlc::new(5, 0), [2; 32]);
        assert!(matches!(
            decide(&s, &DOC, FILE, &info(&earlier_root)).unwrap(),
            Decision::ForkWin { .. }
        ));
    }

    /// A late joiner that bootstraps on a non-root head must still resolve a
    /// fork that arrives afterwards, once the ancestry has been recorded.
    #[test]
    fn bootstrap_on_non_root_then_fork_resolves_after_recording_ancestry() {
        let s = MemStore::new();
        let v0 = version(None, Hlc::new(10, 0), [1; 32]);
        let a = version(v0.version_id(), Hlc::new(20, 0), [5; 32]);
        let a2 = version(a.version_id(), Hlc::new(21, 0), [5; 32]);
        let b = version(v0.version_id(), Hlc::new(15, 0), [3; 32]);
        let all: HashMap<VersionId, SyncMessage> = [&v0, &a, &a2, &b]
            .into_iter()
            .map(|m| (m.version_id().unwrap(), m.clone()))
            .collect();
        assert_eq!(
            decide(&s, &DOC, FILE, &info(&a2)).unwrap(),
            Decision::Bootstrap {
                ancestry_missing: a.version_id()
            }
        );
        apply_with_gaps(&s, &a2, &all);
        assert_eq!(head(&s), a2.version_id());
        assert!(s
            .version(&DOC, &v0.version_id().unwrap())
            .unwrap()
            .is_some());
        apply_with_gaps(&s, &b, &all);
        assert_eq!(head(&s), b.version_id());
        assert!(s.is_rejected(&DOC, &a2.version_id().unwrap()).unwrap());
        assert!(s.is_rejected(&DOC, &a.version_id().unwrap()).unwrap());
    }

    // -- convergence property -------------------------------------------------

    #[derive(Clone, Debug)]
    struct Gen {
        versions: Vec<SyncMessage>,
    }

    /// A DAG of versions: a root, then versions whose parent is any earlier
    /// version at depth below 3, with a clock strictly after the parent's.
    fn dag() -> impl Strategy<Value = Gen> {
        (2usize..=12).prop_flat_map(|n| {
            (proptest::collection::vec(
                (0u8..3, 1u64..5, 0u32..3, 0usize..1000),
                n - 1,
            ),)
                .prop_map(move |(choices,)| {
                    let authors: [[u8; 32]; 3] = [[10; 32], [20; 32], [30; 32]];
                    let root = version(None, Hlc::new(1_000, 0), authors[0]);
                    let mut versions = vec![root];
                    let mut depth = vec![0usize];
                    for (author, dwall, counter, pick) in choices {
                        let candidates: Vec<usize> =
                            (0..versions.len()).filter(|i| depth[*i] < 3).collect();
                        let pi = candidates[pick % candidates.len()];
                        let parent = &versions[pi];
                        let p_info = info(parent);
                        let hlc = Hlc::new(p_info.hlc.wall_ms + dwall, counter);
                        let v = version(Some(p_info.id), hlc, authors[author as usize]);
                        versions.push(v);
                        depth.push(depth[pi] + 1);
                    }
                    Gen { versions }
                })
        })
    }

    fn apply_with_gaps(s: &MemStore, m: &SyncMessage, all: &HashMap<VersionId, SyncMessage>) {
        let mut d = decide(s, &DOC, FILE, &info(m)).unwrap();
        if let Decision::Bootstrap {
            ancestry_missing: Some(missing),
        } = d
        {
            // Record the ancestry (as the engine does through GetVersion).
            let mut next = Some(missing);
            while let Some(id) = next {
                if s.version(&DOC, &id).unwrap().is_some() {
                    break;
                }
                let a = all.get(&id).expect("ancestor exists");
                s.record_version(&DOC, a).unwrap();
                next = info(a).parent;
            }
            d = decide(s, &DOC, FILE, &info(m)).unwrap();
        }
        if let Decision::Gap { missing } = d {
            // Fetch ancestors from `all` until connected, apply oldest first.
            let mut chain = Vec::new();
            let mut next = Some(missing);
            while let Some(id) = next {
                if s.version(&DOC, &id).unwrap().is_some() {
                    break;
                }
                let a = all.get(&id).expect("ancestor exists");
                next = info(a).parent;
                chain.push(a.clone());
            }
            for a in chain.iter().rev() {
                let da = decide(s, &DOC, FILE, &info(a)).unwrap();
                assert!(!matches!(da, Decision::Gap { .. }));
                commit_decision(s, &DOC, &manifest(), a, &da, true).unwrap();
            }
            d = decide(s, &DOC, FILE, &info(m)).unwrap();
            assert!(!matches!(d, Decision::Gap { .. }));
        }
        commit_decision(s, &DOC, &manifest(), m, &d, true).unwrap();
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        /// Every delivery order of the same version set ends with the same head.
        #[test]
        fn heads_converge_under_random_delivery_order(g in dag(), seed in any::<u64>()) {
            let all: HashMap<VersionId, SyncMessage> = g
                .versions
                .iter()
                .map(|m| (m.version_id().unwrap(), m.clone()))
                .collect();
            // Reference: in generation order.
            let reference = MemStore::new();
            for m in &g.versions {
                apply_with_gaps(&reference, m, &all);
            }
            let expected = head(&reference).unwrap();

            // Three shuffles from the seed.
            let mut order: Vec<usize> = (0..g.versions.len()).collect();
            let mut state = seed | 1;
            for round in 0..3 {
                for i in (1..order.len()).rev() {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    let j = (state as usize) % (i + 1);
                    order.swap(i, j);
                }
                let s = MemStore::new();
                for i in &order {
                    apply_with_gaps(&s, &g.versions[*i], &all);
                }
                prop_assert_eq!(head(&s).unwrap(), expected, "round {}", round);
                // The head is never a rejected version, and every version is
                // either accepted on the chain or rejected.
                prop_assert!(!s.is_rejected(&DOC, &expected).unwrap());
            }
        }
    }
}
