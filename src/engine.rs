//! The sync engine (SPEC.md section 5.3): publishes local changes as file
//! documents and materializes the merged documents into the folder.
//!
//! All publish and apply work for one vault runs under one async mutex, so a
//! local change and a remote change to the same path never interleave.
//!
//! `state.json` remembers, per path, the hash of the bytes last written to or
//! read from disk and the document heads those bytes correspond to. A local
//! edit is applied to the document forked at those heads and merged back, so
//! it combines with remote changes that arrived in between (CRD-1) instead of
//! replacing them (NOTES.md, stage 2).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
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

use crate::config::{self, Layout};
use crate::filedoc::{self, Content, FileDoc, MAX_TEXT_BYTES};
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
    /// Skipped: read-only device, binary file before stage 3, or an invalid key.
    Skipped(String),
    /// The file on disk is not what this device last saw there: an
    /// unpublished local change that must be published first (CRD-1).
    LocalChange,
}

/// One entry of `state.json`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct FileState {
    /// blake3 of the bytes last written to or read from disk.
    hash: String,
    /// Heads of the document those bytes were materialized from or published as.
    #[serde(default)]
    heads: Vec<String>,
}

impl FileState {
    fn new(hash: String, heads: &[ChangeHash]) -> FileState {
        FileState {
            hash,
            heads: heads
                .iter()
                .map(|h| data_encoding::HEXLOWER.encode(&h.0))
                .collect(),
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
    fn load(path: &Path) -> Result<State> {
        if !path.is_file() {
            return Ok(State::default());
        }
        let text = std::fs::read_to_string(path)?;
        serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))
    }

    fn save(&self, path: &Path) -> Result<()> {
        config::write_private(path, serde_json::to_string_pretty(self)?.as_bytes())
    }
}

fn hash_hex(bytes: &[u8]) -> String {
    data_encoding::HEXLOWER.encode(blake3::hash(bytes).as_bytes())
}

/// Classify file bytes: text if valid UTF-8, no NUL and at most 1 MiB.
pub fn classify(bytes: Vec<u8>) -> Result<Content, Vec<u8>> {
    if bytes.len() > MAX_TEXT_BYTES || bytes.contains(&0) {
        return Err(bytes);
    }
    String::from_utf8(bytes)
        .map(Content::Text)
        .map_err(|err| err.into_bytes())
}

#[derive(Debug)]
pub struct Engine {
    vault: Arc<Vault>,
    layout: Layout,
    /// The canonical vault root, for matching watcher paths.
    root: PathBuf,
    actor: ActorId,
    state: Mutex<State>,
    /// Keys whose remote content is still downloading, by content hash.
    pending: Mutex<HashMap<Hash, HashSet<String>>>,
    /// Serializes every publish and apply.
    work: tokio::sync::Mutex<()>,
}

impl Engine {
    pub fn new(vault: Arc<Vault>) -> Result<Engine> {
        let layout = vault.layout().clone();
        let root = layout
            .root()
            .canonicalize()
            .with_context(|| format!("canonicalizing {}", layout.root().display()))?;
        let state = State::load(&layout.state())?;
        Ok(Engine {
            actor: filedoc::actor_for(&vault.author()),
            vault,
            layout,
            root,
            state: Mutex::new(state),
            pending: Mutex::new(HashMap::new()),
            work: tokio::sync::Mutex::new(()),
        })
    }

    pub fn vault(&self) -> &Vault {
        &self.vault
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
            let bytes = std::fs::read(entry.path())?;
            if self.known(&key).map(|k| k.hash) == Some(hash_hex(&bytes)) {
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
        for key in self.all_keys().await? {
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
        if !path.exists() {
            // Possibly a directory that was removed or renamed away: every
            // known file under it is gone.
            let prefix = format!("{key}/");
            let inside: Vec<String> = {
                let state = self.state.lock().expect("state");
                state
                    .files
                    .keys()
                    .filter(|k| k.starts_with(&prefix))
                    .cloned()
                    .collect()
            };
            for key in inside {
                self.publish_path(&key).await?;
            }
        }
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
                if content_status == ContentStatus::Complete {
                    self.apply_path(&key).await?;
                } else {
                    self.pending
                        .lock()
                        .expect("pending")
                        .entry(entry.content_hash())
                        .or_default()
                        .insert(key);
                }
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
            }
            LiveEvent::NeighborUp(id) => {
                tracing::info!("peer up {}", id.fmt_short());
                self.vault.remember_peer(id).await?;
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

    fn file_path(&self, key: &str) -> Result<PathBuf> {
        paths::path_for_key(&self.root, key)
    }

    fn read_disk(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let path = self.file_path(key)?;
        match std::fs::read(&path) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(err).with_context(|| format!("reading {}", path.display())),
        }
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
                // Remember the key so the `ContentReady` for this hash
                // triggers an apply even if the insert event was missed.
                self.pending
                    .lock()
                    .expect("pending")
                    .entry(hash)
                    .or_default()
                    .insert(key.to_string());
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

    async fn publish_locked(&self, key: &str) -> Result<Outcome> {
        paths::validate_key(key)?;
        let disk = self.read_disk(key)?;
        let disk_hash = disk.as_deref().map(hash_hex);
        let content = match disk {
            None => Content::Deleted,
            Some(bytes) => match classify(bytes) {
                Ok(content) => content,
                Err(_) => {
                    tracing::info!("{key}: binary files are synced from stage 3; skipping");
                    return Ok(Outcome::Skipped("binary".into()));
                }
            },
        };
        if !self.vault.can_write() {
            // SEC-6: a read-only device never publishes.
            return Ok(Outcome::Skipped("read-only".into()));
        }
        let mut doc = match self.load_merged(key).await? {
            Some(doc) => doc,
            None if content == Content::Deleted => return Ok(Outcome::Nothing),
            None => FileDoc::new(self.actor.clone()),
        };
        let changed = self.ingest(key, &mut doc, &content)?;
        if changed {
            let snapshot = doc.save();
            self.vault.set(key.as_bytes().to_vec(), snapshot).await?;
            tracing::info!("{key}: published {}", describe(&content));
        }
        // The merged document may differ from the file when remote changes
        // were folded in; bring the disk in line, unless the file changed
        // again meanwhile (the watcher reports that separately).
        let outcome = self.materialize(key, &mut doc, disk_hash.as_deref())?;
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
            match self.materialize(key, &mut doc, expected.as_deref())? {
                // CRD-1, step 3: an unpublished local edit goes first, then
                // the merge that includes it is materialized.
                Outcome::LocalChange if self.vault.can_write() => {
                    tracing::info!("{key}: publishing the local edit before applying");
                    self.publish_locked(key).await?;
                }
                Outcome::LocalChange => {
                    tracing::warn!("{key}: local edit on a read-only device is overwritten");
                    let now = self.read_disk(key)?.as_deref().map(hash_hex);
                    return self.materialize(key, &mut doc, now.as_deref());
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
    fn materialize(&self, key: &str, doc: &mut FileDoc, expected: Option<&str>) -> Result<Outcome> {
        let disk = self.read_disk(key)?;
        let disk_hash = disk.as_deref().map(hash_hex);
        if disk_hash.as_deref() != expected {
            return Ok(Outcome::LocalChange);
        }
        let visible = doc.visible()?;
        if visible.is_conflict() {
            tracing::warn!(
                "{key}: {} concurrent version(s) lost; the earliest write is visible",
                visible.losers.len()
            );
        }
        let heads = doc.heads();
        match &visible.content {
            Content::Deleted => {
                let existed = disk.is_some();
                if existed {
                    let path = self.file_path(key)?;
                    std::fs::remove_file(&path)
                        .with_context(|| format!("removing {}", path.display()))?;
                    tracing::info!("{key}: removed");
                }
                self.set_known(key, None)?;
                Ok(if existed {
                    Outcome::Materialized
                } else {
                    Outcome::Unchanged
                })
            }
            Content::Text(text) => {
                let bytes = text.as_bytes();
                let same = disk.as_deref() == Some(bytes);
                if !same {
                    self.write_atomic(key, bytes)?;
                    tracing::info!("{key}: wrote {} bytes of text", bytes.len());
                }
                self.set_known(key, Some(FileState::new(hash_hex(bytes), &heads)))?;
                Ok(if same {
                    Outcome::Unchanged
                } else {
                    Outcome::Materialized
                })
            }
            Content::Blob { .. } => {
                tracing::info!("{key}: blob content is materialized from stage 3; skipping");
                Ok(Outcome::Skipped("blob".into()))
            }
        }
    }

    /// Write `bytes` to the file for `key` through `.vault/tmp/` and a rename.
    fn write_atomic(&self, key: &str, bytes: &[u8]) -> Result<()> {
        let path = self.file_path(key)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        let tmp = self
            .layout
            .tmp()
            .join(format!("{}.tmp", hash_hex(key.as_bytes())));
        std::fs::write(&tmp, bytes).with_context(|| format!("writing {}", tmp.display()))?;
        std::fs::rename(&tmp, &path)
            .with_context(|| format!("renaming into {}", path.display()))?;
        Ok(())
    }
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
