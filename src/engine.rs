//! The sync engine (SPEC.md section 5.3): publishes local changes as file
//! documents and materializes the merged documents into the folder.
//!
//! All publish and apply work for one vault runs under one async mutex, so a
//! local change and a remote change to the same path never interleave.
//!
//! `state.json` remembers, per path, the hash of the bytes last written to or
//! read from disk, the document heads those bytes correspond to and, for
//! blobs, the manifest. A local edit is applied to the document forked at
//! those heads and merged back, so it combines with remote changes that
//! arrived in between (CRD-1) instead of replacing them (NOTES.md, stage 2).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use automerge::{ActorId, ChangeHash};
use iroh_blobs::Hash;
use iroh_docs::engine::LiveEvent;
use iroh_docs::store::Query;
use iroh_docs::ContentStatus;
use n0_future::StreamExt;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tracing::Instrument;

use crate::chunker;
use crate::config::{self, Config, ConflictIndex, Layout, LoserInfo};
use crate::filedoc::{self, Content, FileDoc, Version, VersionKind, Visible, MAX_TEXT_BYTES};
use crate::paths;
use crate::vault::Vault;
use crate::watcher::Watcher;

/// What one publish or apply did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// A new document version was published.
    Published,
    /// Nothing changed: the document already showed the content on disk.
    Unchanged,
    /// Nothing to do (no document, or nothing to delete).
    Nothing,
    /// The file on disk was written or removed to match the merged document.
    Materialized,
    /// Skipped: read-only device, or an invalid key.
    Skipped(String),
    /// The file on disk is not what this device last saw there: an
    /// unpublished local change that must be published first (CRD-1).
    LocalChange,
}

/// How long to wait for a document snapshot fetched from peers.
const SNAPSHOT_FETCH_TIMEOUT: Duration = Duration::from_secs(5);

/// Resource limits (SPEC.md stage 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Files larger than this are never published.
    pub max_file_bytes: u64,
    /// New paths are not published once the vault holds this many.
    pub max_entries: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_file_bytes: 1 << 30,
            max_entries: 100_000,
        }
    }
}

impl Limits {
    pub fn from_config(config: &Config) -> Limits {
        let defaults = Limits::default();
        Limits {
            max_file_bytes: config.max_file_bytes.unwrap_or(defaults.max_file_bytes),
            max_entries: config.max_entries.unwrap_or(defaults.max_entries),
        }
    }
}

/// One entry of `state.json`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct FileState {
    /// blake3 of the bytes last written to or read from disk.
    hash: String,
    /// Heads of the document those bytes were materialized from or published as.
    #[serde(default)]
    heads: Vec<String>,
    /// The manifest hash when the bytes are a blob version, hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    manifest: Option<String>,
}

impl FileState {
    fn new(hash: String, heads: &[ChangeHash], manifest: Option<String>) -> FileState {
        FileState {
            hash,
            heads: heads
                .iter()
                .map(|h| data_encoding::HEXLOWER.encode(&h.0))
                .collect(),
            manifest,
        }
    }

    fn base_heads(&self) -> Option<Vec<ChangeHash>> {
        if self.heads.is_empty() {
            return None;
        }
        let mut heads = Vec::with_capacity(self.heads.len());
        for text in &self.heads {
            let bytes = data_encoding::HEXLOWER_PERMISSIVE
                .decode(text.as_bytes())
                .ok()?;
            heads.push(ChangeHash(bytes.try_into().ok()?));
        }
        heads.sort();
        Some(heads)
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct State {
    files: BTreeMap<String, FileState>,
}

impl State {
    /// Load the state file. An unreadable file is set aside as
    /// `state.json.corrupt` and the engine starts from an empty state: every
    /// file then looks new and is re-published if it differs from the vault,
    /// which is safe, only slower.
    fn load(path: &Path) -> Result<State> {
        if !path.is_file() {
            return Ok(State::default());
        }
        let text = std::fs::read_to_string(path)?;
        match serde_json::from_str(&text) {
            Ok(state) => Ok(state),
            Err(err) => {
                let aside = path.with_extension("json.corrupt");
                tracing::warn!(
                    "{} is unreadable ({err}); moving it to {} and starting from an empty state",
                    path.display(),
                    aside.display()
                );
                std::fs::rename(path, &aside)?;
                Ok(State::default())
            }
        }
    }

    fn save(&self, path: &Path) -> Result<()> {
        config::write_private(path, serde_json::to_string_pretty(self)?.as_bytes())
    }
}

fn hex(bytes: &[u8]) -> String {
    data_encoding::HEXLOWER.encode(bytes)
}

fn hash_hex(bytes: &[u8]) -> String {
    hex(blake3::hash(bytes).as_bytes())
}

/// Text if valid UTF-8, no NUL and at most 1 MiB (SPEC.md section 4).
pub fn classify_text(bytes: Vec<u8>) -> Option<String> {
    if bytes.len() > MAX_TEXT_BYTES || bytes.contains(&0) {
        return None;
    }
    String::from_utf8(bytes).ok()
}

/// What is on disk for a key: the content hash and size, and the text if
/// the file is text. Large files are hashed in a streaming pass and never
/// held in memory.
#[derive(Debug, Clone)]
struct DiskFile {
    hash: String,
    size: u64,
    text: Option<String>,
}

#[derive(Debug)]
pub struct Engine {
    vault: Arc<Vault>,
    layout: Layout,
    /// The canonical vault root, for matching watcher paths.
    root: PathBuf,
    actor: ActorId,
    state: Mutex<State>,
    conflicts: Mutex<ConflictIndex>,
    /// Keys whose remote content is still downloading, by content hash.
    pending: Mutex<HashMap<Hash, HashSet<String>>>,
    /// Keys whose blob download failed; retried when a peer shows up.
    retry: Mutex<HashSet<String>>,
    limits: Limits,
    /// Number of distinct paths in the vault, refreshed by the scan.
    key_count: AtomicUsize,
    /// Serializes every publish and apply.
    work: tokio::sync::Mutex<()>,
}

impl Engine {
    /// An engine with the limits from the vault's config.
    pub fn new(vault: Arc<Vault>) -> Result<Engine> {
        let limits = Limits::from_config(vault.config());
        Self::with_limits(vault, limits)
    }

    pub fn with_limits(vault: Arc<Vault>, limits: Limits) -> Result<Engine> {
        let layout = vault.layout().clone();
        let root = layout
            .root()
            .canonicalize()
            .with_context(|| format!("canonicalizing {}", layout.root().display()))?;
        let state = State::load(&layout.state())?;
        let conflicts = config::load_conflicts(&layout.conflicts_index())?;
        clean_tmp(&layout.tmp());
        Ok(Engine {
            actor: filedoc::actor_for(&vault.author()),
            vault,
            layout,
            root,
            state: Mutex::new(state),
            conflicts: Mutex::new(conflicts),
            pending: Mutex::new(HashMap::new()),
            retry: Mutex::new(HashSet::new()),
            limits,
            key_count: AtomicUsize::new(0),
            work: tokio::sync::Mutex::new(()),
        })
    }

    pub fn limits(&self) -> Limits {
        self.limits
    }

    pub fn vault(&self) -> &Vault {
        &self.vault
    }

    /// Paths currently flagged as conflicted.
    pub fn conflicts(&self) -> ConflictIndex {
        self.conflicts.lock().expect("conflicts").clone()
    }

    /// The folder name, for log lines.
    fn name(&self) -> String {
        self.root
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| self.root.display().to_string())
    }

    /// Start the watcher and the live-event loop, run the startup scan, and
    /// keep syncing until [`Running::stop`].
    pub async fn start(self: Arc<Self>, debounce: Duration) -> Result<Running> {
        let (paths_tx, paths_rx) = mpsc::unbounded_channel();
        let watcher = Watcher::spawn(self.layout.root(), debounce, paths_tx)?;
        let events = self.vault.subscribe().await?;
        // Scan after the watcher is up so nothing slips between the two.
        self.scan().await?;
        let (stop_tx, stop_rx) = oneshot::channel();
        let engine = self.clone();
        let span = tracing::info_span!("vault", dir = %self.name());
        let task = tokio::spawn(
            async move {
                engine.event_loop(paths_rx, events, stop_rx).await;
            }
            .instrument(span),
        );
        Ok(Running {
            task,
            watcher: Some(watcher),
            stop: Some(stop_tx),
        })
    }

    async fn event_loop(
        &self,
        mut batches: mpsc::UnboundedReceiver<Vec<PathBuf>>,
        mut events: impl n0_future::Stream<Item = Result<LiveEvent>> + Unpin,
        mut stop: oneshot::Receiver<()>,
    ) {
        loop {
            tokio::select! {
                _ = &mut stop => break,
                batch = batches.recv() => match batch {
                    Some(batch) => {
                        if let Err(err) = self.on_local_batch(&batch).await {
                            tracing::warn!("local changes: {err:#}");
                        }
                    }
                    None => break,
                },
                event = events.next() => match event {
                    Some(Ok(event)) => {
                        if let Err(err) = self.on_live_event(event).await {
                            tracing::warn!("live event: {err:#}");
                        }
                    }
                    Some(Err(err)) => tracing::warn!("event stream error: {err:#}"),
                    None => {
                        tracing::warn!("event stream ended");
                        let _ = (&mut stop).await;
                        break;
                    }
                },
            }
        }
    }

    /// Startup scan: publish files that changed while the engine was not
    /// running (including deletions), then apply every key in the vault.
    pub async fn scan(&self) -> Result<()> {
        let _guard = self.work.lock().await;
        let mut on_disk = HashSet::new();
        let walker = walkdir::WalkDir::new(&self.root)
            .into_iter()
            .filter_entry(|e| {
                e.depth() == 0 || paths::key_from_path(&self.root, e.path()).is_some()
            });
        for entry in walker {
            let entry = match entry {
                Ok(entry) => entry,
                Err(err) => {
                    tracing::warn!("scan: {err}");
                    continue;
                }
            };
            if !entry.file_type().is_file() {
                continue;
            }
            let Some(key) = paths::key_from_path(&self.root, entry.path()) else {
                continue;
            };
            on_disk.insert(key.clone());
            let known_hash = self.known(&key).map(|k| k.hash);
            let disk_hash = self.read_disk(&key)?.map(|d| d.hash);
            if known_hash.is_some() && known_hash == disk_hash {
                continue;
            }
            if let Err(err) = self.publish_locked(&key).await {
                tracing::warn!("scan publish {key}: {err:#}");
            }
        }
        let gone: Vec<String> = {
            let state = self.state.lock().expect("state");
            state
                .files
                .keys()
                .filter(|k| !on_disk.contains(*k))
                .cloned()
                .collect()
        };
        for key in gone {
            if let Err(err) = self.publish_locked(&key).await {
                tracing::warn!("scan publish deletion {key}: {err:#}");
            }
        }
        let keys = self.all_keys().await?;
        self.key_count.store(keys.len(), Ordering::Relaxed);
        for key in keys {
            if let Err(err) = self.apply_locked(&key).await {
                tracing::warn!("scan apply {key}: {err:#}");
            }
        }
        Ok(())
    }

    async fn all_keys(&self) -> Result<Vec<String>> {
        let mut keys = HashSet::new();
        for entry in self.vault.entries(Query::all()).await? {
            match paths::key_from_bytes(entry.key()) {
                Ok(key) => {
                    keys.insert(key);
                }
                Err(err) => tracing::warn!(
                    "ignoring entry with invalid key {:?}: {err}",
                    String::from_utf8_lossy(entry.key())
                ),
            }
        }
        let mut keys: Vec<String> = keys.into_iter().collect();
        keys.sort();
        Ok(keys)
    }

    /// One debounce window of watcher paths: handle each, then publish a
    /// deletion for every known file that is no longer on disk (renames
    /// report only their destination, removed directories only themselves).
    pub async fn on_local_batch(&self, batch: &[PathBuf]) -> Result<()> {
        for path in batch {
            if let Err(err) = self.on_local_path(path).await {
                tracing::warn!("local change {}: {err:#}", path.display());
            }
        }
        self.reconcile_missing().await
    }

    /// Publish deletions for known files that are gone from disk.
    pub async fn reconcile_missing(&self) -> Result<()> {
        let known: Vec<String> = {
            let state = self.state.lock().expect("state");
            state.files.keys().cloned().collect()
        };
        for key in known {
            if !self.file_path(&key)?.exists() {
                tracing::debug!("{key}: gone from disk");
                self.publish_path(&key).await?;
            }
        }
        Ok(())
    }

    /// A path reported by the watcher.
    pub async fn on_local_path(&self, path: &Path) -> Result<()> {
        let path = if path.is_absolute() {
            path.to_path_buf()
        } else {
            self.root.join(path)
        };
        let Some(key) = paths::key_from_path(&self.root, &path) else {
            tracing::trace!(
                "ignoring path outside the vault or under .vault: {}",
                path.display()
            );
            return Ok(());
        };
        tracing::debug!("local change {key} (exists: {})", path.exists());
        if path.is_dir() {
            // A directory appeared or moved in: publish every file inside.
            for entry in walkdir::WalkDir::new(&path).into_iter().flatten() {
                if entry.file_type().is_file() {
                    if let Some(key) = paths::key_from_path(&self.root, entry.path()) {
                        self.publish_path(&key).await?;
                    }
                }
            }
            return Ok(());
        }
        self.publish_path(&key).await?;
        Ok(())
    }

    /// A docs live event.
    pub async fn on_live_event(&self, event: LiveEvent) -> Result<()> {
        match event {
            LiveEvent::InsertRemote {
                entry,
                content_status,
                from,
            } => {
                let key = match paths::key_from_bytes(entry.key()) {
                    Ok(key) => key,
                    Err(err) => {
                        tracing::warn!(
                            "ignoring remote entry with invalid key {:?} from {}: {err}",
                            String::from_utf8_lossy(entry.key()),
                            from.fmt_short()
                        );
                        return Ok(());
                    }
                };
                if content_status != ContentStatus::Complete {
                    self.pending
                        .lock()
                        .expect("pending")
                        .entry(entry.content_hash())
                        .or_default()
                        .insert(key.clone());
                }
                // Apply right away even when docs is still downloading the
                // content: `load_merged` fetches missing snapshots itself.
                self.apply_path(&key).await?;
            }
            LiveEvent::ContentReady { hash } => {
                let keys = self.pending.lock().expect("pending").remove(&hash);
                for key in keys.into_iter().flatten() {
                    self.apply_path(&key).await?;
                }
            }
            LiveEvent::PendingContentReady => {
                // Everything queued has arrived: apply whatever is still
                // waiting, in case a `ContentReady` was missed.
                let keys: HashSet<String> = {
                    let mut pending = self.pending.lock().expect("pending");
                    pending.drain().flat_map(|(_, keys)| keys).collect()
                };
                for key in keys {
                    self.apply_path(&key).await?;
                }
                self.retry_failed().await;
            }
            LiveEvent::NeighborUp(id) => {
                tracing::info!("peer up {}", id.fmt_short());
                self.vault.remember_peer(id).await?;
                self.retry_failed().await;
            }
            LiveEvent::NeighborDown(id) => tracing::info!("peer down {}", id.fmt_short()),
            LiveEvent::SyncFinished(event) => tracing::debug!(
                "sync with {} finished: {:?}",
                event.peer.fmt_short(),
                event.result
            ),
            LiveEvent::InsertLocal { .. } => {}
        }
        Ok(())
    }

    /// Retry keys whose blob download failed earlier.
    async fn retry_failed(&self) {
        let keys: Vec<String> = self.retry.lock().expect("retry").drain().collect();
        for key in keys {
            if let Err(err) = self.apply_path(&key).await {
                tracing::warn!("{key}: retry failed: {err:#}");
            }
        }
    }

    /// Publish the current on-disk content of `key` (SPEC.md 5.3, publishing),
    /// then bring the file in line with the merged document.
    pub async fn publish_path(&self, key: &str) -> Result<Outcome> {
        let _guard = self.work.lock().await;
        self.publish_locked(key).await
    }

    /// Materialize the merged document for `key` (SPEC.md 5.3, applying).
    pub async fn apply_path(&self, key: &str) -> Result<Outcome> {
        let _guard = self.work.lock().await;
        self.apply_locked(key).await
    }

    /// Export every losing version of `key` to `.vault/conflicts/`, fetching
    /// chunks from peers when needed. Returns the copies' paths.
    pub async fn export_conflicts(&self, key: &str) -> Result<Vec<PathBuf>> {
        let _guard = self.work.lock().await;
        paths::validate_key(key)?;
        let Some(doc) = self.load_merged(key).await? else {
            return Ok(Vec::new());
        };
        let visible = doc.visible()?;
        let mut copies = Vec::new();
        for loser in &visible.losers {
            copies.push(self.export_loser(key, &doc, loser).await?);
        }
        Ok(copies)
    }

    fn file_path(&self, key: &str) -> Result<PathBuf> {
        paths::path_for_key(&self.root, key)
    }

    fn tmp_path(&self, key: &str) -> PathBuf {
        self.layout
            .tmp()
            .join(format!("{}.tmp", hash_hex(key.as_bytes())))
    }

    /// Read what is on disk for `key`. Files up to 1 MiB are read in full and
    /// classified; larger files are hashed in a streaming pass.
    fn read_disk(&self, key: &str) -> Result<Option<DiskFile>> {
        let path = self.file_path(key)?;
        let mut file = match std::fs::File::open(&path) {
            Ok(file) => file,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(err).with_context(|| format!("opening {}", path.display())),
        };
        let metadata = file.metadata()?;
        if metadata.is_dir() {
            return Ok(None);
        }
        if metadata.len() <= MAX_TEXT_BYTES as u64 {
            let mut bytes = Vec::with_capacity(metadata.len() as usize);
            file.read_to_end(&mut bytes)
                .with_context(|| format!("reading {}", path.display()))?;
            let hash = hash_hex(&bytes);
            let size = bytes.len() as u64;
            let text = classify_text(bytes);
            return Ok(Some(DiskFile { hash, size, text }));
        }
        let mut hasher = blake3::Hasher::new();
        let mut buffer = vec![0u8; 1 << 20];
        let mut size = 0u64;
        loop {
            let n = file
                .read(&mut buffer)
                .with_context(|| format!("reading {}", path.display()))?;
            if n == 0 {
                break;
            }
            hasher.update(&buffer[..n]);
            size += n as u64;
        }
        Ok(Some(DiskFile {
            hash: hex(hasher.finalize().as_bytes()),
            size,
            text: None,
        }))
    }

    fn known(&self, key: &str) -> Option<FileState> {
        self.state.lock().expect("state").files.get(key).cloned()
    }

    fn set_known(&self, key: &str, state: Option<FileState>) -> Result<()> {
        let mut all = self.state.lock().expect("state");
        match state {
            Some(state) => all.files.insert(key.to_string(), state),
            None => all.files.remove(key),
        };
        all.save(&self.layout.state())
    }

    /// Load and merge every locally available snapshot for `key`.
    async fn load_merged(&self, key: &str) -> Result<Option<FileDoc>> {
        let mut snapshots = Vec::new();
        for entry in self.vault.entries(Query::all().key_exact(key)).await? {
            if entry.content_len() == 0 {
                continue;
            }
            let hash = entry.content_hash();
            if !self.vault.has_content(hash).await? {
                // Docs downloads an entry's content only from the peer that
                // sent the entry, and gives up when that connection drops.
                // Fetch the snapshot ourselves from every known peer.
                self.fetch_snapshot(key, hash).await;
            }
            if !self.vault.has_content(hash).await? {
                // Remember the key so the `ContentReady` for this hash, or the
                // next peer event, triggers another apply.
                self.pending
                    .lock()
                    .expect("pending")
                    .entry(hash)
                    .or_default()
                    .insert(key.to_string());
                self.retry.lock().expect("retry").insert(key.to_string());
                if !self.vault.has_content(hash).await? {
                    tracing::debug!("{key}: snapshot {} not downloaded yet", hash.fmt_short());
                    continue;
                }
                self.pending.lock().expect("pending").remove(&hash);
            }
            snapshots.push(self.vault.content(hash).await?);
        }
        let mut merged: Option<FileDoc> = None;
        for bytes in &snapshots {
            let result = match &mut merged {
                None => FileDoc::load(bytes, self.actor.clone()).map(|doc| merged = Some(doc)),
                Some(doc) => doc.merge_bytes(bytes),
            };
            if let Err(err) = result {
                tracing::warn!("{key}: skipping unreadable snapshot: {err:#}");
            }
        }
        Ok(merged)
    }

    /// Download one document snapshot from any known peer; failures are
    /// logged and left to the retry paths.
    async fn fetch_snapshot(&self, key: &str, hash: Hash) {
        let peers = match self.vault.peer_ids() {
            Ok(peers) if !peers.is_empty() => peers,
            _ => return,
        };
        let download = self.vault.node().downloader().download(hash, peers);
        match tokio::time::timeout(SNAPSHOT_FETCH_TIMEOUT, download).await {
            Ok(Ok(())) => tracing::debug!("{key}: fetched snapshot {}", hash.fmt_short()),
            Ok(Err(err)) => tracing::debug!(
                "{key}: fetching snapshot {} failed: {err}",
                hash.fmt_short()
            ),
            Err(_) => tracing::debug!("{key}: fetching snapshot {} timed out", hash.fmt_short()),
        }
    }

    async fn own_heads(&self, key: &str) -> Result<Option<Vec<ChangeHash>>> {
        let Some(entry) = self.vault.own_entry(key).await? else {
            return Ok(None);
        };
        if entry.content_len() == 0 || !self.vault.has_content(entry.content_hash()).await? {
            return Ok(None);
        }
        let bytes = self.vault.content(entry.content_hash()).await?;
        Ok(FileDoc::load(&bytes, self.actor.clone())
            .ok()
            .map(|mut doc| doc.heads()))
    }

    /// The content for a file on disk: text, or a blob imported into the
    /// store. A blob whose bytes match what the state file recorded reuses
    /// the recorded manifest instead of chunking again (echo suppression).
    async fn content_for(&self, key: &str, disk: &DiskFile) -> Result<Content> {
        if let Some(text) = &disk.text {
            return Ok(Content::Text(text.clone()));
        }
        if let Some(known) = self.known(key) {
            if known.hash == disk.hash {
                if let Some(manifest) = known.manifest.as_deref().and_then(parse_hex32) {
                    return Ok(Content::Blob {
                        manifest,
                        size: disk.size,
                    });
                }
            }
        }
        let path = self.file_path(key)?;
        let (manifest, size) = chunker::import_blob_file(self.vault.node().blobs(), &path)
            .await
            .with_context(|| format!("importing {key} as chunks"))?;
        tracing::info!(
            "{key}: imported {size} bytes as manifest {}",
            manifest.fmt_short()
        );
        Ok(Content::Blob {
            manifest: *manifest.as_bytes(),
            size,
        })
    }

    async fn publish_locked(&self, key: &str) -> Result<Outcome> {
        paths::validate_key(key)?;
        if !self.vault.can_write() {
            // SEC-6: a read-only device never publishes.
            return Ok(Outcome::Skipped("read-only".into()));
        }
        let disk = self.read_disk(key)?;
        if let Some(size) = disk.as_ref().map(|d| d.size) {
            if size > self.limits.max_file_bytes {
                tracing::warn!(
                    "{key}: {size} bytes exceeds the file size limit of {}; not published",
                    self.limits.max_file_bytes
                );
                return Ok(Outcome::Skipped("too large".into()));
            }
        }
        let disk_hash = disk.as_ref().map(|d| d.hash.clone());
        // An echo of this engine's own write (the bytes on disk are exactly
        // what the state file recorded) is not a user write: it must not
        // create a version, and in particular must not resolve a conflict.
        let echo = disk_hash == self.known(key).map(|k| k.hash);
        let content = match (&disk, echo) {
            (_, true) => None,
            (None, false) => Some(Content::Deleted),
            (Some(disk), false) => Some(self.content_for(key, disk).await?),
        };
        let mut doc = match self.load_merged(key).await? {
            Some(doc) => doc,
            None if matches!(content, None | Some(Content::Deleted)) => {
                return Ok(Outcome::Nothing)
            }
            None => {
                let count = self.key_count.load(Ordering::Relaxed);
                if count >= self.limits.max_entries {
                    tracing::warn!(
                        "{key}: the vault already holds {count} paths (limit {}); not published",
                        self.limits.max_entries
                    );
                    return Ok(Outcome::Skipped("entry limit".into()));
                }
                self.key_count.fetch_add(1, Ordering::Relaxed);
                FileDoc::new(self.actor.clone())
            }
        };
        let changed = match &content {
            Some(content) => self.ingest(key, &mut doc, content)?,
            None => false,
        };
        if changed {
            let snapshot = doc.save();
            self.vault.set(key.as_bytes().to_vec(), snapshot).await?;
            tracing::info!(
                "{key}: published {}",
                describe(content.as_ref().expect("changed implies content"))
            );
        }
        // The merged document may differ from the file when remote changes
        // were folded in; bring the disk in line, unless the file changed
        // again meanwhile (the watcher reports that separately).
        let outcome = self
            .materialize(key, &mut doc, disk_hash.as_deref())
            .await?;
        Ok(match (changed, outcome) {
            (_, Outcome::LocalChange) => {
                tracing::debug!("{key}: changed again while publishing");
                if changed {
                    Outcome::Published
                } else {
                    Outcome::Unchanged
                }
            }
            (true, _) => Outcome::Published,
            (false, outcome) => outcome,
        })
    }

    /// Apply `content` to `doc` as a local edit. When the state file knows the
    /// heads the on-disk content came from, and the document has moved on
    /// since, the edit is applied at those heads and merged (CRD-1).
    fn ingest(&self, key: &str, doc: &mut FileDoc, content: &Content) -> Result<bool> {
        let base = self.known(key).and_then(|k| k.base_heads());
        if let Some(base) = base {
            if doc.heads() != base {
                match doc.fork_at(&base) {
                    Ok(mut at_base) => {
                        let changed = at_base.apply_local(content)?;
                        if changed {
                            doc.merge(&mut at_base)?;
                        }
                        return Ok(changed);
                    }
                    Err(err) => tracing::warn!(
                        "{key}: cannot fork at the base heads ({err:#}); applying on the merge"
                    ),
                }
            }
        }
        doc.apply_local(content)
    }

    async fn apply_locked(&self, key: &str) -> Result<Outcome> {
        paths::validate_key(key)?;
        for _attempt in 0..3 {
            let Some(mut doc) = self.load_merged(key).await? else {
                return Ok(Outcome::Nothing);
            };
            // Publish the merge as this device's entry so that peers converge.
            if self.vault.can_write() {
                let merged_heads = doc.heads();
                if self.own_heads(key).await?.as_ref() != Some(&merged_heads) {
                    let snapshot = doc.save();
                    self.vault.set(key.as_bytes().to_vec(), snapshot).await?;
                    tracing::debug!("{key}: republished the merged document");
                }
            }
            let expected = self.known(key).map(|k| k.hash);
            match self.materialize(key, &mut doc, expected.as_deref()).await? {
                // CRD-1, step 3: an unpublished local edit goes first, then
                // the merge that includes it is materialized.
                Outcome::LocalChange if self.vault.can_write() => {
                    tracing::info!("{key}: publishing the local edit before applying");
                    self.publish_locked(key).await?;
                }
                Outcome::LocalChange => {
                    tracing::warn!("{key}: local edit on a read-only device is overwritten");
                    let now = self.read_disk(key)?.map(|d| d.hash);
                    return self.materialize(key, &mut doc, now.as_deref()).await;
                }
                outcome => return Ok(outcome),
            }
        }
        bail!("{key}: the file keeps changing while it is being applied");
    }

    /// Bring the file for `key` in line with the document's visible content
    /// and record what is now on disk. `expected` is the hash of the bytes
    /// the caller believes are on disk (the state file's, or what it just
    /// read); when the disk holds something else, nothing is written and
    /// [`Outcome::LocalChange`] is returned. Check and write use the same
    /// read of the disk, so a change in between cannot be overwritten unseen.
    async fn materialize(
        &self,
        key: &str,
        doc: &mut FileDoc,
        expected: Option<&str>,
    ) -> Result<Outcome> {
        let disk = self.read_disk(key)?;
        let disk_hash = disk.as_ref().map(|d| d.hash.clone());
        if disk_hash.as_deref() != expected {
            return Ok(Outcome::LocalChange);
        }
        let visible = doc.visible()?;
        self.record_conflict(key, &visible)?;
        let heads = doc.heads();
        let outcome = match &visible.content {
            Content::Deleted => {
                let existed = disk.is_some();
                if existed {
                    let path = self.file_path(key)?;
                    std::fs::remove_file(&path)
                        .with_context(|| format!("removing {}", path.display()))?;
                    tracing::info!("{key}: removed");
                }
                self.set_known(key, None)?;
                if existed {
                    Outcome::Materialized
                } else {
                    Outcome::Unchanged
                }
            }
            Content::Text(text) => {
                let bytes = text.as_bytes();
                let same = disk.as_ref().and_then(|d| d.text.as_deref()) == Some(text.as_str());
                if !same {
                    self.write_atomic(key, bytes)?;
                    tracing::info!("{key}: wrote {} bytes of text", bytes.len());
                }
                self.set_known(key, Some(FileState::new(hash_hex(bytes), &heads, None)))?;
                if same {
                    Outcome::Unchanged
                } else {
                    Outcome::Materialized
                }
            }
            Content::Blob { manifest, size } => {
                let manifest_hex = hex(manifest);
                let same = disk.is_some()
                    && self.known(key).and_then(|k| k.manifest).as_deref()
                        == Some(manifest_hex.as_str());
                if same {
                    let hash = disk_hash.expect("disk present");
                    self.set_known(key, Some(FileState::new(hash, &heads, Some(manifest_hex))))?;
                    Outcome::Unchanged
                } else {
                    let manifest = Hash::from_bytes(*manifest);
                    let (hash, written) = match self.export_blob(key, manifest).await {
                        Ok(result) => result,
                        Err(err) => {
                            self.retry.lock().expect("retry").insert(key.to_string());
                            return Err(err);
                        }
                    };
                    if written != *size {
                        tracing::warn!(
                            "{key}: manifest says {size} bytes but {written} were assembled"
                        );
                    }
                    tracing::info!("{key}: wrote {written} bytes from {}", manifest.fmt_short());
                    self.set_known(key, Some(FileState::new(hash, &heads, Some(manifest_hex))))?;
                    Outcome::Materialized
                }
            }
        };
        // CRD-4: a local copy of every losing version this device wrote.
        for loser in &visible.losers {
            if loser.actor == self.actor.to_bytes() {
                if let Err(err) = self.export_loser(key, doc, loser).await {
                    tracing::warn!("{key}: exporting the losing version: {err:#}");
                }
            }
        }
        Ok(outcome)
    }

    /// Download (if needed) and assemble the blob `manifest` into the file
    /// for `key`. Returns the hash and size of what was written.
    async fn export_blob(&self, key: &str, manifest: Hash) -> Result<(String, u64)> {
        let dest = self.file_path(key)?;
        let peers = self.vault.peer_ids()?;
        chunker::export_blob_file(
            self.vault.node().blobs(),
            self.vault.node().downloader(),
            manifest,
            &peers,
            &self.tmp_path(key),
            &dest,
        )
        .await
        .with_context(|| format!("materializing blob {} for {key}", manifest.fmt_short()))
    }

    /// The copy of a losing version: `.vault/conflicts/<key>.<8 hex>`.
    fn loser_copy_path(&self, key: &str, loser: &Version) -> PathBuf {
        let mut path = self.layout.conflicts();
        for component in key.split('/') {
            path.push(component);
        }
        let name = format!(
            "{}.{}",
            path.file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default(),
            loser_id(loser)
        );
        path.set_file_name(name);
        path
    }

    /// Write one losing version to its copy path, fetching chunks if needed.
    async fn export_loser(&self, key: &str, doc: &FileDoc, loser: &Version) -> Result<PathBuf> {
        let dest = self.loser_copy_path(key, loser);
        if dest.exists() {
            return Ok(dest);
        }
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = self.layout.tmp().join(format!(
            "conflict-{}.tmp",
            hash_hex(dest.to_string_lossy().as_bytes())
        ));
        match &loser.kind {
            VersionKind::Blob { manifest, .. } => {
                let peers = self.vault.peer_ids()?;
                chunker::export_blob_file(
                    self.vault.node().blobs(),
                    self.vault.node().downloader(),
                    Hash::from_bytes(*manifest),
                    &peers,
                    &tmp,
                    &dest,
                )
                .await?;
            }
            VersionKind::Text { .. } => {
                // The losing text edits live in the merged text object.
                std::fs::write(&tmp, doc.text()?)?;
                std::fs::rename(&tmp, &dest)?;
            }
            VersionKind::Deleted => bail!("a deletion is never a losing version"),
        }
        tracing::info!("{key}: losing version copied to {}", dest.display());
        Ok(dest)
    }

    /// Keep `conflicts.json` in step with the merged document.
    fn record_conflict(&self, key: &str, visible: &Visible) -> Result<()> {
        let mut index = self.conflicts.lock().expect("conflicts");
        let changed = if visible.is_conflict() {
            let losers: Vec<LoserInfo> = visible
                .losers
                .iter()
                .map(|loser| LoserInfo {
                    kind: match loser.kind {
                        VersionKind::Blob { .. } => "blob",
                        VersionKind::Text { .. } => "text",
                        VersionKind::Deleted => "deleted",
                    }
                    .to_string(),
                    id: loser_id(loser),
                    actor: hex(&loser.actor[..4]),
                })
                .collect();
            index.insert(key.to_string(), losers.clone()) != Some(losers)
        } else {
            index.remove(key).is_some()
        };
        if changed {
            config::save_conflicts(&self.layout.conflicts_index(), &index)?;
        }
        Ok(())
    }

    /// Write `bytes` to the file for `key` through `.vault/tmp/` and a rename.
    fn write_atomic(&self, key: &str, bytes: &[u8]) -> Result<()> {
        let path = self.file_path(key)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        let tmp = self.tmp_path(key);
        std::fs::write(&tmp, bytes).with_context(|| format!("writing {}", tmp.display()))?;
        std::fs::rename(&tmp, &path)
            .with_context(|| format!("renaming into {}", path.display()))?;
        Ok(())
    }
}

/// Remove leftovers of interrupted writes. Everything in `.vault/tmp/` is
/// ours and is only ever renamed into place when complete.
fn clean_tmp(tmp: &Path) {
    let Ok(entries) = std::fs::read_dir(tmp) else {
        return;
    };
    for entry in entries.flatten() {
        if entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
            if let Err(err) = std::fs::remove_file(entry.path()) {
                tracing::warn!("removing {}: {err}", entry.path().display());
            } else {
                tracing::info!("removed leftover {}", entry.path().display());
            }
        }
    }
}

/// The first 8 hex digits identifying a losing version.
fn loser_id(loser: &Version) -> String {
    match &loser.kind {
        VersionKind::Blob { manifest, .. } => hex(&manifest[..4]),
        VersionKind::Text { hash } => hex(&hash[..4]),
        VersionKind::Deleted => "deleted".to_string(),
    }
}

fn parse_hex32(text: &str) -> Option<[u8; 32]> {
    let bytes = data_encoding::HEXLOWER_PERMISSIVE
        .decode(text.as_bytes())
        .ok()?;
    bytes.try_into().ok()
}

fn describe(content: &Content) -> String {
    match content {
        Content::Text(text) => format!("{} bytes of text", text.len()),
        Content::Blob { size, .. } => format!("a {size}-byte blob"),
        Content::Deleted => "a deletion".to_string(),
    }
}

/// A running engine: the watcher and the event loop.
#[derive(Debug)]
pub struct Running {
    task: JoinHandle<()>,
    watcher: Option<Watcher>,
    stop: Option<oneshot::Sender<()>>,
}

impl Running {
    /// Stop the watcher and the loop; in-flight work finishes first.
    pub async fn stop(mut self) -> Result<()> {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(watcher) = self.watcher.take() {
            tokio::task::spawn_blocking(move || watcher.stop()).await?;
        }
        match (&mut self.task).await {
            Ok(()) => Ok(()),
            Err(err) if err.is_cancelled() => Ok(()),
            Err(err) => bail!("engine task failed: {err}"),
        }
    }
}
