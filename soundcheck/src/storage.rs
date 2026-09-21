//! [`Store`] trait with compare-and-set commits and rejection records, plus the
//! [`MemStore`] (tests) and [`RedbStore`] (disk) backends.
//!
//! Chunks are global and content-addressed. Manifests, chunk membership,
//! versions, rejections and heads are scoped per document. The trait is
//! synchronous; async callers wrap `redb` calls in `spawn_blocking`, and no
//! lock is ever held across an `.await`.

use crate::clock::Hlc;
use crate::crypto::chunk_hash;
use crate::gossip::SyncMessage;
use crate::manifest::{FileManifest, ManifestError, MAX_CHUNK};
use crate::protocol::{self, ProtocolError, RESPONSE_FRAME_LIMIT};
use crate::{Hash, VersionId};
use parking_lot::RwLock;
use redb::{
    Database, ReadOnlyDatabase, ReadTransaction, ReadableDatabase, ReadableTable, TableDefinition,
    WriteTransaction,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::Path;

/// The current head of one file in one document.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeadInfo {
    /// The head version.
    pub version_id: VersionId,
    /// Its manifest.
    pub manifest_id: Hash,
    /// Its clock value.
    pub hlc: Hlc,
    /// Its author's `NodeId`.
    pub author: [u8; 32],
    /// Whether the file on disk already holds this version's content.
    pub written: bool,
}

/// Storage failures.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// The file's head was not `expected_head` at commit time (CON-1, CON-2).
    #[error("head moved: expected {expected:?}, found {actual:?}")]
    HeadMoved {
        /// What the caller expected.
        expected: Option<VersionId>,
        /// What the store holds.
        actual: Option<VersionId>,
    },
    /// `put_chunk` data does not hash to the given hash (SEC-8).
    #[error("chunk data does not match its hash")]
    HashMismatch,
    /// `put_chunk` data exceeds the maximum chunk size.
    #[error("chunk of {0} bytes exceeds the {MAX_CHUNK} byte limit")]
    ChunkTooLarge(usize),
    /// A version message was not a `NewVersion`, or disagreed with its manifest.
    #[error("invalid version: {0}")]
    InvalidVersion(&'static str),
    /// The manifest failed validation.
    #[error(transparent)]
    Manifest(#[from] ManifestError),
    /// Encoding or decoding a stored value failed.
    #[error("codec error: {0}")]
    Codec(String),
    /// The `redb` backend failed.
    #[error("storage backend error: {0}")]
    Backend(String),
    /// The store is open read-only (`status` while `run` is not active) and a
    /// write was attempted.
    #[error("store is open read-only")]
    ReadOnly,
    /// Another process (a running node) holds the store's lock.
    #[error("store is locked by another process")]
    Locked,
}

impl From<ProtocolError> for StoreError {
    fn from(e: ProtocolError) -> Self {
        StoreError::Codec(e.to_string())
    }
}

fn backend<E: Into<redb::Error>>(e: E) -> StoreError {
    let text = e.into().to_string();
    if text.contains("already open") || text.contains("acquire lock") {
        StoreError::Locked
    } else {
        StoreError::Backend(text)
    }
}

/// Durable state of one node. See section 9 for the invariants each method
/// must uphold; `commit_version` and `switch_branch` are single transactions.
pub trait Store: Send + Sync + 'static {
    /// Whether the chunk bytes are held (for any document).
    fn has_chunk(&self, hash: &Hash) -> Result<bool, StoreError>;
    /// Store chunk bytes. Rejects data whose BLAKE3 hash is not `hash`
    /// (defense in depth for SEC-8). Idempotent.
    fn put_chunk(&self, hash: Hash, data: Vec<u8>) -> Result<(), StoreError>;
    /// The chunk bytes, if held.
    fn get_chunk(&self, hash: &Hash) -> Result<Option<Vec<u8>>, StoreError>;

    /// True if some committed manifest of `doc` references this chunk (SEC-3).
    fn doc_has_chunk(&self, doc: &Hash, hash: &Hash) -> Result<bool, StoreError>;
    /// A committed manifest of `doc`.
    fn get_manifest(&self, doc: &Hash, id: &Hash) -> Result<Option<FileManifest>, StoreError>;

    /// A stored signed `NewVersion`, whether accepted or rejected.
    fn version(&self, doc: &Hash, id: &VersionId) -> Result<Option<SyncMessage>, StoreError>;
    /// Whether the version is recorded as rejected.
    fn is_rejected(&self, doc: &Hash, id: &VersionId) -> Result<bool, StoreError>;
    /// Stores the version (if new) and marks it rejected. No chunks are registered.
    fn record_rejected(&self, doc: &Hash, version: &SyncMessage) -> Result<(), StoreError>;
    /// Stores a signed `NewVersion` learned through `GetVersion` (if new)
    /// without touching any head, chunk registration or rejection mark, so
    /// the local chain can be walked through it.
    fn record_version(&self, doc: &Hash, version: &SyncMessage) -> Result<(), StoreError>;

    /// The head of one file.
    fn head(&self, doc: &Hash, file_name: &str) -> Result<Option<HeadInfo>, StoreError>;
    /// The latest committed signed `NewVersion` for every file of `doc`.
    fn heads(&self, doc: &Hash) -> Result<Vec<SyncMessage>, StoreError>;

    /// Compare-and-set (CON-1, CON-2). In one transaction: fails with
    /// [`StoreError::HeadMoved`] unless the file's head equals `expected_head`;
    /// otherwise stores the manifest and version, registers the manifest's
    /// chunks for `doc`, and moves the head. `written` says whether the file
    /// on disk already matches (true for local publishes, false for remote applies).
    fn commit_version(
        &self,
        doc: &Hash,
        manifest: &FileManifest,
        version: &SyncMessage,
        expected_head: Option<VersionId>,
        written: bool,
    ) -> Result<(), StoreError>;

    /// Like `commit_version` for a fork winner, and in the same transaction
    /// marks every id in `rejected` as rejected. The head is left unwritten.
    fn switch_branch(
        &self,
        doc: &Hash,
        manifest: &FileManifest,
        version: &SyncMessage,
        expected_head: VersionId,
        rejected: &[VersionId],
    ) -> Result<(), StoreError>;

    /// Record that the file on disk now holds head `id`. Fails with
    /// `HeadMoved` if the head is no longer `id`, and changes nothing then.
    fn mark_written(&self, doc: &Hash, file_name: &str, id: &VersionId) -> Result<(), StoreError>;
    /// Heads whose content is not yet on disk.
    fn unwritten_heads(&self, doc: &Hash) -> Result<Vec<HeadInfo>, StoreError>;

    /// The persisted clock, or `Hlc::default()` on a fresh store.
    fn load_clock(&self) -> Result<Hlc, StoreError>;
    /// Persist the clock.
    fn save_clock(&self, hlc: Hlc) -> Result<(), StoreError>;
}

/// The fields a commit needs from a `NewVersion`, checked for consistency
/// with the manifest and document.
struct VersionFields {
    version_id: VersionId,
    manifest_id: Hash,
    hlc: Hlc,
    author: [u8; 32],
}

fn version_fields(
    doc: &Hash,
    manifest: &FileManifest,
    version: &SyncMessage,
) -> Result<VersionFields, StoreError> {
    let SyncMessage::NewVersion {
        doc_id,
        manifest_id,
        hlc,
        author,
        ..
    } = version
    else {
        return Err(StoreError::InvalidVersion("not a NewVersion"));
    };
    if doc_id != doc {
        return Err(StoreError::InvalidVersion("version names another document"));
    }
    manifest.validate()?;
    if manifest.id() != *manifest_id {
        return Err(StoreError::InvalidVersion(
            "manifest does not match the version's manifest_id",
        ));
    }
    let version_id = version
        .version_id()
        .ok_or(StoreError::InvalidVersion("not a NewVersion"))?;
    Ok(VersionFields {
        version_id,
        manifest_id: *manifest_id,
        hlc: *hlc,
        author: *author,
    })
}

fn check_chunk(hash: &Hash, data: &[u8]) -> Result<(), StoreError> {
    if data.len() > MAX_CHUNK as usize {
        return Err(StoreError::ChunkTooLarge(data.len()));
    }
    if chunk_hash(data) != *hash {
        return Err(StoreError::HashMismatch);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// In-memory backend
// ---------------------------------------------------------------------------

#[derive(Default)]
struct MemInner {
    chunks: HashMap<Hash, Vec<u8>>,
    manifests: HashMap<(Hash, Hash), FileManifest>,
    doc_chunks: HashSet<(Hash, Hash)>,
    versions: HashMap<(Hash, VersionId), SyncMessage>,
    rejected: HashSet<(Hash, VersionId)>,
    heads: HashMap<(Hash, String), HeadInfo>,
    clock: Hlc,
}

impl MemInner {
    fn commit(
        &mut self,
        doc: &Hash,
        manifest: &FileManifest,
        version: &SyncMessage,
        expected_head: Option<VersionId>,
        written: bool,
        rejected: &[VersionId],
    ) -> Result<(), StoreError> {
        let f = version_fields(doc, manifest, version)?;
        let key = (*doc, manifest.file_name.clone());
        let actual = self.heads.get(&key).map(|h| h.version_id);
        if actual != expected_head {
            return Err(StoreError::HeadMoved {
                expected: expected_head,
                actual,
            });
        }
        self.manifests
            .insert((*doc, f.manifest_id), manifest.clone());
        self.versions.insert((*doc, f.version_id), version.clone());
        for c in &manifest.chunks {
            self.doc_chunks.insert((*doc, c.hash));
        }
        for r in rejected {
            self.rejected.insert((*doc, *r));
        }
        self.heads.insert(
            key,
            HeadInfo {
                version_id: f.version_id,
                manifest_id: f.manifest_id,
                hlc: f.hlc,
                author: f.author,
                written,
            },
        );
        Ok(())
    }
}

/// In-memory [`Store`] for tests. A `parking_lot::RwLock` makes each method
/// atomic; nothing is persisted.
#[derive(Default)]
pub struct MemStore {
    inner: RwLock<MemInner>,
}

impl MemStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }
}

impl Store for MemStore {
    fn has_chunk(&self, hash: &Hash) -> Result<bool, StoreError> {
        Ok(self.inner.read().chunks.contains_key(hash))
    }

    fn put_chunk(&self, hash: Hash, data: Vec<u8>) -> Result<(), StoreError> {
        check_chunk(&hash, &data)?;
        self.inner.write().chunks.entry(hash).or_insert(data);
        Ok(())
    }

    fn get_chunk(&self, hash: &Hash) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(self.inner.read().chunks.get(hash).cloned())
    }

    fn doc_has_chunk(&self, doc: &Hash, hash: &Hash) -> Result<bool, StoreError> {
        Ok(self.inner.read().doc_chunks.contains(&(*doc, *hash)))
    }

    fn get_manifest(&self, doc: &Hash, id: &Hash) -> Result<Option<FileManifest>, StoreError> {
        Ok(self.inner.read().manifests.get(&(*doc, *id)).cloned())
    }

    fn version(&self, doc: &Hash, id: &VersionId) -> Result<Option<SyncMessage>, StoreError> {
        Ok(self.inner.read().versions.get(&(*doc, *id)).cloned())
    }

    fn is_rejected(&self, doc: &Hash, id: &VersionId) -> Result<bool, StoreError> {
        Ok(self.inner.read().rejected.contains(&(*doc, *id)))
    }

    fn record_rejected(&self, doc: &Hash, version: &SyncMessage) -> Result<(), StoreError> {
        let id = version
            .version_id()
            .ok_or(StoreError::InvalidVersion("not a NewVersion"))?;
        if version.doc_id() != doc {
            return Err(StoreError::InvalidVersion("version names another document"));
        }
        let mut g = self.inner.write();
        g.versions
            .entry((*doc, id))
            .or_insert_with(|| version.clone());
        g.rejected.insert((*doc, id));
        Ok(())
    }

    fn record_version(&self, doc: &Hash, version: &SyncMessage) -> Result<(), StoreError> {
        let id = version
            .version_id()
            .ok_or(StoreError::InvalidVersion("not a NewVersion"))?;
        if version.doc_id() != doc {
            return Err(StoreError::InvalidVersion("version names another document"));
        }
        self.inner
            .write()
            .versions
            .entry((*doc, id))
            .or_insert_with(|| version.clone());
        Ok(())
    }

    fn head(&self, doc: &Hash, file_name: &str) -> Result<Option<HeadInfo>, StoreError> {
        Ok(self
            .inner
            .read()
            .heads
            .get(&(*doc, file_name.to_string()))
            .copied())
    }

    fn heads(&self, doc: &Hash) -> Result<Vec<SyncMessage>, StoreError> {
        let g = self.inner.read();
        let mut names: Vec<&String> = g
            .heads
            .keys()
            .filter(|(d, _)| d == doc)
            .map(|(_, n)| n)
            .collect();
        names.sort();
        let mut out = Vec::with_capacity(names.len());
        for name in names {
            if let Some(h) = g.heads.get(&(*doc, name.clone())) {
                if let Some(v) = g.versions.get(&(*doc, h.version_id)) {
                    out.push(v.clone());
                }
            }
        }
        Ok(out)
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
            .write()
            .commit(doc, manifest, version, expected_head, written, &[])
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
            .write()
            .commit(doc, manifest, version, Some(expected_head), false, rejected)
    }

    fn mark_written(&self, doc: &Hash, file_name: &str, id: &VersionId) -> Result<(), StoreError> {
        let mut g = self.inner.write();
        let key = (*doc, file_name.to_string());
        match g.heads.get_mut(&key) {
            Some(h) if h.version_id == *id => {
                h.written = true;
                Ok(())
            }
            other => Err(StoreError::HeadMoved {
                expected: Some(*id),
                actual: other.map(|h| h.version_id),
            }),
        }
    }

    fn unwritten_heads(&self, doc: &Hash) -> Result<Vec<HeadInfo>, StoreError> {
        let g = self.inner.read();
        let mut entries: Vec<(&String, &HeadInfo)> = g
            .heads
            .iter()
            .filter(|((d, _), h)| d == doc && !h.written)
            .map(|((_, n), h)| (n, h))
            .collect();
        entries.sort_by(|a, b| a.0.cmp(b.0));
        Ok(entries.into_iter().map(|(_, h)| *h).collect())
    }

    fn load_clock(&self) -> Result<Hlc, StoreError> {
        Ok(self.inner.read().clock)
    }

    fn save_clock(&self, hlc: Hlc) -> Result<(), StoreError> {
        self.inner.write().clock = hlc;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// redb backend
// ---------------------------------------------------------------------------

type PairKey<'a> = (&'a [u8; 32], &'a [u8; 32]);

const CHUNKS: TableDefinition<&[u8; 32], &[u8]> = TableDefinition::new("chunks");
const MANIFESTS: TableDefinition<PairKey, &[u8]> = TableDefinition::new("manifests");
const DOC_CHUNKS: TableDefinition<PairKey, ()> = TableDefinition::new("doc_chunks");
const VERSIONS: TableDefinition<PairKey, &[u8]> = TableDefinition::new("versions");
const REJECTED: TableDefinition<PairKey, ()> = TableDefinition::new("rejected");
const HEADS: TableDefinition<(&[u8; 32], &str), &[u8]> = TableDefinition::new("heads");
const META: TableDefinition<&str, &[u8]> = TableDefinition::new("meta");
const META_CLOCK: &str = "clock";

enum Handle {
    ReadWrite(Database),
    ReadOnly(ReadOnlyDatabase),
}

/// Disk [`Store`] backed by `redb`. Lives at `<doc_dir>/.p2p-sync/store.redb`.
pub struct RedbStore {
    db: Handle,
}

impl RedbStore {
    /// Open or create the database at `path` and make sure every table exists.
    /// Holds redb's exclusive writer lock until dropped.
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        let db = Database::create(path).map_err(backend)?;
        let txn = db.begin_write().map_err(backend)?;
        {
            txn.open_table(CHUNKS).map_err(backend)?;
            txn.open_table(MANIFESTS).map_err(backend)?;
            txn.open_table(DOC_CHUNKS).map_err(backend)?;
            txn.open_table(VERSIONS).map_err(backend)?;
            txn.open_table(REJECTED).map_err(backend)?;
            txn.open_table(HEADS).map_err(backend)?;
            txn.open_table(META).map_err(backend)?;
        }
        txn.commit().map_err(backend)?;
        Ok(RedbStore {
            db: Handle::ReadWrite(db),
        })
    }

    /// Open an existing database read-only (for `status`). Fails with
    /// [`StoreError::Locked`] while a running node holds the writer lock, and
    /// every write method returns [`StoreError::ReadOnly`].
    pub fn open_read_only(path: &Path) -> Result<Self, StoreError> {
        let db = ReadOnlyDatabase::open(path).map_err(backend)?;
        Ok(RedbStore {
            db: Handle::ReadOnly(db),
        })
    }

    fn begin_read(&self) -> Result<ReadTransaction, StoreError> {
        match &self.db {
            Handle::ReadWrite(db) => db.begin_read().map_err(backend),
            Handle::ReadOnly(db) => db.begin_read().map_err(backend),
        }
    }

    fn begin_write(&self) -> Result<WriteTransaction, StoreError> {
        match &self.db {
            Handle::ReadWrite(db) => db.begin_write().map_err(backend),
            Handle::ReadOnly(_) => Err(StoreError::ReadOnly),
        }
    }

    fn get_bytes<K: redb::Key + 'static>(
        &self,
        table: TableDefinition<K, &[u8]>,
        key: &K::SelfType<'_>,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        let txn = self.begin_read()?;
        let t = txn.open_table(table).map_err(backend)?;
        Ok(t.get(key).map_err(backend)?.map(|g| g.value().to_vec()))
    }

    fn has_key<K: redb::Key + 'static>(
        &self,
        table: TableDefinition<K, ()>,
        key: &K::SelfType<'_>,
    ) -> Result<bool, StoreError> {
        let txn = self.begin_read()?;
        let t = txn.open_table(table).map_err(backend)?;
        Ok(t.get(key).map_err(backend)?.is_some())
    }

    fn commit(
        &self,
        doc: &Hash,
        manifest: &FileManifest,
        version: &SyncMessage,
        expected_head: Option<VersionId>,
        written: bool,
        rejected: &[VersionId],
    ) -> Result<(), StoreError> {
        let f = version_fields(doc, manifest, version)?;
        let manifest_bytes = protocol::encode(manifest, RESPONSE_FRAME_LIMIT)?;
        let version_bytes = protocol::encode(version, RESPONSE_FRAME_LIMIT)?;
        let head = HeadInfo {
            version_id: f.version_id,
            manifest_id: f.manifest_id,
            hlc: f.hlc,
            author: f.author,
            written,
        };
        let head_bytes = protocol::encode(&head, RESPONSE_FRAME_LIMIT)?;

        let txn = self.begin_write()?;
        {
            let mut heads = txn.open_table(HEADS).map_err(backend)?;
            let key = (doc, manifest.file_name.as_str());
            let actual = match heads.get(&key).map_err(backend)? {
                Some(g) => Some(decode_head(g.value())?.version_id),
                None => None,
            };
            if actual != expected_head {
                return Err(StoreError::HeadMoved {
                    expected: expected_head,
                    actual,
                });
            }
            let mut manifests = txn.open_table(MANIFESTS).map_err(backend)?;
            manifests
                .insert((doc, &f.manifest_id), manifest_bytes.as_slice())
                .map_err(backend)?;
            let mut versions = txn.open_table(VERSIONS).map_err(backend)?;
            versions
                .insert((doc, &f.version_id), version_bytes.as_slice())
                .map_err(backend)?;
            let mut doc_chunks = txn.open_table(DOC_CHUNKS).map_err(backend)?;
            for c in &manifest.chunks {
                doc_chunks.insert((doc, &c.hash), ()).map_err(backend)?;
            }
            let mut rej = txn.open_table(REJECTED).map_err(backend)?;
            for r in rejected {
                rej.insert((doc, r), ()).map_err(backend)?;
            }
            heads.insert(&key, head_bytes.as_slice()).map_err(backend)?;
        }
        txn.commit().map_err(backend)?;
        Ok(())
    }

    fn heads_for(&self, doc: &Hash) -> Result<Vec<(String, HeadInfo)>, StoreError> {
        let txn = self.begin_read()?;
        let t = txn.open_table(HEADS).map_err(backend)?;
        let mut out = Vec::new();
        for entry in t.range((doc, "")..).map_err(backend)? {
            let (k, v) = entry.map_err(backend)?;
            let (d, name) = k.value();
            if d != doc {
                break;
            }
            out.push((name.to_string(), decode_head(v.value())?));
        }
        Ok(out)
    }
}

fn decode_head(bytes: &[u8]) -> Result<HeadInfo, StoreError> {
    Ok(protocol::decode(bytes, RESPONSE_FRAME_LIMIT)?)
}

impl Store for RedbStore {
    fn has_chunk(&self, hash: &Hash) -> Result<bool, StoreError> {
        let txn = self.begin_read()?;
        let t = txn.open_table(CHUNKS).map_err(backend)?;
        Ok(t.get(hash).map_err(backend)?.is_some())
    }

    fn put_chunk(&self, hash: Hash, data: Vec<u8>) -> Result<(), StoreError> {
        check_chunk(&hash, &data)?;
        let txn = self.begin_write()?;
        {
            let mut t = txn.open_table(CHUNKS).map_err(backend)?;
            if t.get(&hash).map_err(backend)?.is_none() {
                t.insert(&hash, data.as_slice()).map_err(backend)?;
            }
        }
        txn.commit().map_err(backend)?;
        Ok(())
    }

    fn get_chunk(&self, hash: &Hash) -> Result<Option<Vec<u8>>, StoreError> {
        self.get_bytes(CHUNKS, &hash)
    }

    fn doc_has_chunk(&self, doc: &Hash, hash: &Hash) -> Result<bool, StoreError> {
        self.has_key(DOC_CHUNKS, &(doc, hash))
    }

    fn get_manifest(&self, doc: &Hash, id: &Hash) -> Result<Option<FileManifest>, StoreError> {
        match self.get_bytes(MANIFESTS, &(doc, id))? {
            Some(b) => Ok(Some(protocol::decode(&b, RESPONSE_FRAME_LIMIT)?)),
            None => Ok(None),
        }
    }

    fn version(&self, doc: &Hash, id: &VersionId) -> Result<Option<SyncMessage>, StoreError> {
        match self.get_bytes(VERSIONS, &(doc, id))? {
            Some(b) => Ok(Some(protocol::decode(&b, RESPONSE_FRAME_LIMIT)?)),
            None => Ok(None),
        }
    }

    fn is_rejected(&self, doc: &Hash, id: &VersionId) -> Result<bool, StoreError> {
        self.has_key(REJECTED, &(doc, id))
    }

    fn record_rejected(&self, doc: &Hash, version: &SyncMessage) -> Result<(), StoreError> {
        let id = version
            .version_id()
            .ok_or(StoreError::InvalidVersion("not a NewVersion"))?;
        if version.doc_id() != doc {
            return Err(StoreError::InvalidVersion("version names another document"));
        }
        let bytes = protocol::encode(version, RESPONSE_FRAME_LIMIT)?;
        let txn = self.begin_write()?;
        {
            let mut versions = txn.open_table(VERSIONS).map_err(backend)?;
            if versions.get((doc, &id)).map_err(backend)?.is_none() {
                versions
                    .insert((doc, &id), bytes.as_slice())
                    .map_err(backend)?;
            }
            let mut rej = txn.open_table(REJECTED).map_err(backend)?;
            rej.insert((doc, &id), ()).map_err(backend)?;
        }
        txn.commit().map_err(backend)?;
        Ok(())
    }

    fn record_version(&self, doc: &Hash, version: &SyncMessage) -> Result<(), StoreError> {
        let id = version
            .version_id()
            .ok_or(StoreError::InvalidVersion("not a NewVersion"))?;
        if version.doc_id() != doc {
            return Err(StoreError::InvalidVersion("version names another document"));
        }
        let bytes = protocol::encode(version, RESPONSE_FRAME_LIMIT)?;
        let txn = self.begin_write()?;
        {
            let mut versions = txn.open_table(VERSIONS).map_err(backend)?;
            if versions.get((doc, &id)).map_err(backend)?.is_none() {
                versions
                    .insert((doc, &id), bytes.as_slice())
                    .map_err(backend)?;
            }
        }
        txn.commit().map_err(backend)?;
        Ok(())
    }

    fn head(&self, doc: &Hash, file_name: &str) -> Result<Option<HeadInfo>, StoreError> {
        match self.get_bytes(HEADS, &(doc, file_name))? {
            Some(b) => Ok(Some(decode_head(&b)?)),
            None => Ok(None),
        }
    }

    fn heads(&self, doc: &Hash) -> Result<Vec<SyncMessage>, StoreError> {
        let heads = self.heads_for(doc)?;
        let txn = self.begin_read()?;
        let versions = txn.open_table(VERSIONS).map_err(backend)?;
        let mut out = Vec::with_capacity(heads.len());
        for (_, h) in heads {
            if let Some(v) = versions.get((doc, &h.version_id)).map_err(backend)? {
                out.push(protocol::decode(v.value(), RESPONSE_FRAME_LIMIT)?);
            }
        }
        Ok(out)
    }

    fn commit_version(
        &self,
        doc: &Hash,
        manifest: &FileManifest,
        version: &SyncMessage,
        expected_head: Option<VersionId>,
        written: bool,
    ) -> Result<(), StoreError> {
        self.commit(doc, manifest, version, expected_head, written, &[])
    }

    fn switch_branch(
        &self,
        doc: &Hash,
        manifest: &FileManifest,
        version: &SyncMessage,
        expected_head: VersionId,
        rejected: &[VersionId],
    ) -> Result<(), StoreError> {
        self.commit(doc, manifest, version, Some(expected_head), false, rejected)
    }

    fn mark_written(&self, doc: &Hash, file_name: &str, id: &VersionId) -> Result<(), StoreError> {
        let txn = self.begin_write()?;
        {
            let mut heads = txn.open_table(HEADS).map_err(backend)?;
            let key = (doc, file_name);
            let current = match heads.get(&key).map_err(backend)? {
                Some(g) => Some(decode_head(g.value())?),
                None => None,
            };
            match current {
                Some(mut h) if h.version_id == *id => {
                    h.written = true;
                    let bytes = protocol::encode(&h, RESPONSE_FRAME_LIMIT)?;
                    heads.insert(&key, bytes.as_slice()).map_err(backend)?;
                }
                other => {
                    return Err(StoreError::HeadMoved {
                        expected: Some(*id),
                        actual: other.map(|h| h.version_id),
                    })
                }
            }
        }
        txn.commit().map_err(backend)?;
        Ok(())
    }

    fn unwritten_heads(&self, doc: &Hash) -> Result<Vec<HeadInfo>, StoreError> {
        Ok(self
            .heads_for(doc)?
            .into_iter()
            .filter(|(_, h)| !h.written)
            .map(|(_, h)| h)
            .collect())
    }

    fn load_clock(&self) -> Result<Hlc, StoreError> {
        match self.get_bytes(META, &META_CLOCK)? {
            Some(b) => Ok(protocol::decode(&b, RESPONSE_FRAME_LIMIT)?),
            None => Ok(Hlc::default()),
        }
    }

    fn save_clock(&self, hlc: Hlc) -> Result<(), StoreError> {
        let bytes = protocol::encode(&hlc, RESPONSE_FRAME_LIMIT)?;
        let txn = self.begin_write()?;
        {
            let mut t = txn.open_table(META).map_err(backend)?;
            t.insert(META_CLOCK, bytes.as_slice()).map_err(backend)?;
        }
        txn.commit().map_err(backend)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capabilities::{CapabilityClaims, CapabilityToken};
    use crate::chunker::chunk_bytes;
    use crate::crypto::generate_signing_key;
    use ed25519_dalek::Signature;
    use std::sync::{Arc, Barrier};

    const DOC: Hash = [1u8; 32];
    const OTHER_DOC: Hash = [2u8; 32];
    const AUTHOR: [u8; 32] = [5u8; 32];

    fn token() -> CapabilityToken {
        let owner = generate_signing_key();
        CapabilityToken::issue(
            CapabilityClaims {
                doc_id: DOC,
                audience: AUTHOR,
                can_read: true,
                can_write: true,
                not_before: 0,
                expires_at: u64::MAX,
            },
            &owner,
        )
    }

    /// A `NewVersion` with a placeholder signature: the store never checks it.
    fn version(
        doc: Hash,
        manifest: &FileManifest,
        parent: Option<VersionId>,
        hlc: Hlc,
        author: [u8; 32],
    ) -> SyncMessage {
        SyncMessage::NewVersion {
            doc_id: doc,
            manifest_id: manifest.id(),
            parent,
            hlc,
            author,
            token: token(),
            signature: Signature::from_bytes(&[0u8; 64]),
        }
    }

    fn data(seed: u8, len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| (i as u8).wrapping_mul(seed).wrapping_add(seed))
            .collect()
    }

    fn suite<S: Store>(store: &S) {
        let payload = chunk_bytes("dir/a.bin", &data(3, 100_000)).unwrap();
        let m1 = payload.manifest.clone();

        // Chunks: hash checked, idempotent, missing reports false / None.
        let (r0, b0) = payload.iter().next().unwrap();
        assert!(!store.has_chunk(&r0.hash).unwrap());
        assert_eq!(store.get_chunk(&r0.hash).unwrap(), None);
        assert!(matches!(
            store.put_chunk([9u8; 32], b0.clone()),
            Err(StoreError::HashMismatch)
        ));
        assert!(!store.has_chunk(&[9u8; 32]).unwrap());
        assert!(matches!(
            store.put_chunk(chunk_hash(&[0u8; 40_000]), vec![0u8; 40_000]),
            Err(StoreError::ChunkTooLarge(40_000))
        ));
        for (r, b) in payload.iter() {
            store.put_chunk(r.hash, b.clone()).unwrap();
            store.put_chunk(r.hash, b.clone()).unwrap();
            assert!(store.has_chunk(&r.hash).unwrap());
            assert_eq!(store.get_chunk(&r.hash).unwrap().as_ref(), Some(b));
        }

        // SEC-3: not registered before commit.
        assert!(!store.doc_has_chunk(&DOC, &r0.hash).unwrap());
        assert_eq!(store.get_manifest(&DOC, &m1.id()).unwrap(), None);
        assert_eq!(store.head(&DOC, "dir/a.bin").unwrap(), None);
        assert!(store.heads(&DOC).unwrap().is_empty());

        // Commit v1 with the right expected head (None).
        let v1 = version(DOC, &m1, None, Hlc::new(10, 0), AUTHOR);
        let v1_id = v1.version_id().unwrap();
        // Wrong expected head changes nothing.
        let err = store
            .commit_version(&DOC, &m1, &v1, Some([7u8; 32]), true)
            .unwrap_err();
        assert!(matches!(
            err,
            StoreError::HeadMoved {
                expected: Some(_),
                actual: None
            }
        ));
        assert_eq!(store.head(&DOC, "dir/a.bin").unwrap(), None);
        assert!(!store.doc_has_chunk(&DOC, &r0.hash).unwrap());
        assert_eq!(store.version(&DOC, &v1_id).unwrap(), None);

        store.commit_version(&DOC, &m1, &v1, None, true).unwrap();
        // SEC-3: registered for DOC, not for another document.
        for c in &m1.chunks {
            assert!(store.doc_has_chunk(&DOC, &c.hash).unwrap());
            assert!(!store.doc_has_chunk(&OTHER_DOC, &c.hash).unwrap());
        }
        assert_eq!(
            store.get_manifest(&DOC, &m1.id()).unwrap(),
            Some(m1.clone())
        );
        assert_eq!(store.get_manifest(&OTHER_DOC, &m1.id()).unwrap(), None);
        let h1 = store.head(&DOC, "dir/a.bin").unwrap().unwrap();
        assert_eq!(
            h1,
            HeadInfo {
                version_id: v1_id,
                manifest_id: m1.id(),
                hlc: Hlc::new(10, 0),
                author: AUTHOR,
                written: true,
            }
        );
        assert_eq!(store.heads(&DOC).unwrap(), vec![v1.clone()]);
        assert_eq!(store.version(&DOC, &v1_id).unwrap(), Some(v1.clone()));
        assert!(!store.is_rejected(&DOC, &v1_id).unwrap());
        assert!(store.unwritten_heads(&DOC).unwrap().is_empty());

        // Committing v1 again from None fails: the head moved.
        assert!(matches!(
            store.commit_version(&DOC, &m1, &v1, None, true),
            Err(StoreError::HeadMoved { .. })
        ));

        // Fast-forward to v2, unwritten (remote apply).
        let p2 = chunk_bytes("dir/a.bin", &data(4, 120_000)).unwrap();
        let m2 = p2.manifest.clone();
        let v2 = version(DOC, &m2, Some(v1_id), Hlc::new(11, 0), AUTHOR);
        let v2_id = v2.version_id().unwrap();
        store
            .commit_version(&DOC, &m2, &v2, Some(v1_id), false)
            .unwrap();
        let h2 = store.head(&DOC, "dir/a.bin").unwrap().unwrap();
        assert_eq!(h2.version_id, v2_id);
        assert!(!h2.written);
        assert_eq!(store.unwritten_heads(&DOC).unwrap(), vec![h2]);
        assert_eq!(store.heads(&DOC).unwrap(), vec![v2.clone()]);
        // Old version stays retrievable.
        assert_eq!(store.version(&DOC, &v1_id).unwrap(), Some(v1.clone()));

        // mark_written with the wrong id fails and changes nothing.
        assert!(matches!(
            store.mark_written(&DOC, "dir/a.bin", &v1_id),
            Err(StoreError::HeadMoved { .. })
        ));
        assert!(!store.head(&DOC, "dir/a.bin").unwrap().unwrap().written);
        store.mark_written(&DOC, "dir/a.bin", &v2_id).unwrap();
        assert!(store.head(&DOC, "dir/a.bin").unwrap().unwrap().written);
        assert!(store.unwritten_heads(&DOC).unwrap().is_empty());

        // Second file: heads lists both, sorted by name.
        let p3 = chunk_bytes("b.txt", b"hello").unwrap();
        let m3 = p3.manifest.clone();
        let v3 = version(DOC, &m3, None, Hlc::new(12, 0), AUTHOR);
        store.commit_version(&DOC, &m3, &v3, None, true).unwrap();
        assert_eq!(store.heads(&DOC).unwrap(), vec![v3.clone(), v2.clone()]);
        assert!(store.heads(&OTHER_DOC).unwrap().is_empty());

        // record_rejected: stores the version, marks it, registers no chunks.
        let p4 = chunk_bytes("dir/a.bin", &data(9, 50_000)).unwrap();
        let m4 = p4.manifest.clone();
        let v4 = version(DOC, &m4, Some(v1_id), Hlc::new(11, 1), [6u8; 32]);
        let v4_id = v4.version_id().unwrap();
        store.record_rejected(&DOC, &v4).unwrap();
        assert!(store.is_rejected(&DOC, &v4_id).unwrap());
        assert_eq!(store.version(&DOC, &v4_id).unwrap(), Some(v4.clone()));
        assert_eq!(store.get_manifest(&DOC, &m4.id()).unwrap(), None);
        for c in &m4.chunks {
            if !m1.chunks.iter().any(|x| x.hash == c.hash)
                && !m2.chunks.iter().any(|x| x.hash == c.hash)
            {
                assert!(!store.doc_has_chunk(&DOC, &c.hash).unwrap());
            }
        }
        assert_eq!(
            store.head(&DOC, "dir/a.bin").unwrap().unwrap().version_id,
            v2_id
        );

        // record_version: stores an ancestor without moving the head,
        // registering chunks or marking it rejected.
        let p6 = chunk_bytes("dir/a.bin", &data(13, 30_000)).unwrap();
        let m6 = p6.manifest.clone();
        let v6 = version(DOC, &m6, Some([1u8; 32]), Hlc::new(3, 0), [2u8; 32]);
        let v6_id = v6.version_id().unwrap();
        store.record_version(&DOC, &v6).unwrap();
        assert_eq!(store.version(&DOC, &v6_id).unwrap(), Some(v6.clone()));
        assert!(!store.is_rejected(&DOC, &v6_id).unwrap());
        assert_eq!(
            store.head(&DOC, "dir/a.bin").unwrap().unwrap().version_id,
            v2_id
        );
        assert_eq!(store.get_manifest(&DOC, &m6.id()).unwrap(), None);
        for c in &m6.chunks {
            assert!(!store.doc_has_chunk(&DOC, &c.hash).unwrap());
        }
        // Recording it again, or recording an already rejected version, is a no-op.
        store.record_version(&DOC, &v6).unwrap();
        store.record_version(&DOC, &v4).unwrap();
        assert!(store.is_rejected(&DOC, &v4_id).unwrap());

        // switch_branch: fork winner replaces v2, marks v2 rejected, unwritten.
        let p5 = chunk_bytes("dir/a.bin", &data(11, 70_000)).unwrap();
        let m5 = p5.manifest.clone();
        let v5 = version(DOC, &m5, Some(v1_id), Hlc::new(10, 5), [4u8; 32]);
        let v5_id = v5.version_id().unwrap();
        assert!(matches!(
            store.switch_branch(&DOC, &m5, &v5, v1_id, &[v2_id]),
            Err(StoreError::HeadMoved { .. })
        ));
        assert!(!store.is_rejected(&DOC, &v2_id).unwrap());
        store
            .switch_branch(&DOC, &m5, &v5, v2_id, &[v2_id])
            .unwrap();
        let h5 = store.head(&DOC, "dir/a.bin").unwrap().unwrap();
        assert_eq!(h5.version_id, v5_id);
        assert!(!h5.written);
        assert!(store.is_rejected(&DOC, &v2_id).unwrap());
        assert!(!store.is_rejected(&DOC, &v5_id).unwrap());
        for c in &m5.chunks {
            assert!(store.doc_has_chunk(&DOC, &c.hash).unwrap());
        }
        // The rejected version's chunks stay registered.
        for c in &m2.chunks {
            assert!(store.doc_has_chunk(&DOC, &c.hash).unwrap());
        }
        assert_eq!(store.version(&DOC, &v2_id).unwrap(), Some(v2.clone()));

        // Inconsistent inputs are refused.
        assert!(matches!(
            store.commit_version(&OTHER_DOC, &m5, &v5, None, true),
            Err(StoreError::InvalidVersion(_))
        ));
        let have = SyncMessage::Have {
            doc_id: DOC,
            manifest_id: m5.id(),
            provider: AUTHOR,
            token: token(),
            signature: Signature::from_bytes(&[0u8; 64]),
        };
        assert!(matches!(
            store.commit_version(&DOC, &m5, &have, Some(v5_id), true),
            Err(StoreError::InvalidVersion(_))
        ));
        assert!(matches!(
            store.record_rejected(&DOC, &have),
            Err(StoreError::InvalidVersion(_))
        ));
        let mut wrong_manifest = m5.clone();
        wrong_manifest.total_size += 1;
        assert!(store
            .commit_version(&DOC, &wrong_manifest, &v5, Some(v5_id), true)
            .is_err());

        // Clock.
        assert_eq!(store.load_clock().unwrap(), Hlc::default());
        store.save_clock(Hlc::new(99, 3)).unwrap();
        assert_eq!(store.load_clock().unwrap(), Hlc::new(99, 3));
    }

    #[test]
    fn mem_store_suite() {
        suite(&MemStore::new());
    }

    #[test]
    fn redb_store_suite() {
        let dir = tempfile::tempdir().unwrap();
        let store = RedbStore::open(&dir.path().join("store.redb")).unwrap();
        suite(&store);
    }

    /// CON-1, CON-2: two threads committing from the same head; exactly one
    /// succeeds.
    fn concurrent_commit<S: Store>(store: Arc<S>) {
        let base = chunk_bytes("f", &data(1, 20_000)).unwrap().manifest;
        let v0 = version(DOC, &base, None, Hlc::new(1, 0), AUTHOR);
        store.commit_version(&DOC, &base, &v0, None, true).unwrap();
        let v0_id = v0.version_id().unwrap();

        let barrier = Arc::new(Barrier::new(2));
        let mut handles = Vec::new();
        for i in 0..2u8 {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                let m = chunk_bytes("f", &data(10 + i, 30_000)).unwrap().manifest;
                let v = version(DOC, &m, Some(v0_id), Hlc::new(2, u32::from(i)), [i; 32]);
                barrier.wait();
                store
                    .commit_version(&DOC, &m, &v, Some(v0_id), true)
                    .is_ok()
            }));
        }
        let results: Vec<bool> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        assert_eq!(results.iter().filter(|ok| **ok).count(), 1, "{results:?}");
        assert_ne!(store.head(&DOC, "f").unwrap().unwrap().version_id, v0_id);
    }

    #[test]
    fn mem_store_concurrent_commit() {
        concurrent_commit(Arc::new(MemStore::new()));
    }

    #[test]
    fn redb_store_concurrent_commit() {
        let dir = tempfile::tempdir().unwrap();
        let store = RedbStore::open(&dir.path().join("store.redb")).unwrap();
        concurrent_commit(Arc::new(store));
    }

    #[test]
    fn redb_store_survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("store.redb");
        let payload = chunk_bytes("x/y.bin", &data(7, 40_000)).unwrap();
        let m = payload.manifest.clone();
        let v = version(DOC, &m, None, Hlc::new(5, 0), AUTHOR);
        let v_id = v.version_id().unwrap();
        let rejected = version(DOC, &m, Some([3u8; 32]), Hlc::new(6, 0), [8u8; 32]);
        let rejected_id = rejected.version_id().unwrap();
        {
            let store = RedbStore::open(&path).unwrap();
            for (r, b) in payload.iter() {
                store.put_chunk(r.hash, b.clone()).unwrap();
            }
            store.commit_version(&DOC, &m, &v, None, false).unwrap();
            store.record_rejected(&DOC, &rejected).unwrap();
            store.save_clock(Hlc::new(1234, 5)).unwrap();
        }
        let store = RedbStore::open(&path).unwrap();
        assert_eq!(store.heads(&DOC).unwrap(), vec![v.clone()]);
        let head = store.head(&DOC, "x/y.bin").unwrap().unwrap();
        assert_eq!(head.version_id, v_id);
        assert!(!head.written);
        assert_eq!(store.unwritten_heads(&DOC).unwrap(), vec![head]);
        assert_eq!(store.load_clock().unwrap(), Hlc::new(1234, 5));
        assert_eq!(store.get_manifest(&DOC, &m.id()).unwrap(), Some(m.clone()));
        for (r, b) in payload.iter() {
            assert_eq!(store.get_chunk(&r.hash).unwrap().as_ref(), Some(b));
            assert!(store.doc_has_chunk(&DOC, &r.hash).unwrap());
        }
        assert!(store.is_rejected(&DOC, &rejected_id).unwrap());
        assert_eq!(store.version(&DOC, &rejected_id).unwrap(), Some(rejected));

        store.mark_written(&DOC, "x/y.bin", &v_id).unwrap();
        drop(store);
        let store = RedbStore::open(&path).unwrap();
        assert!(store.unwritten_heads(&DOC).unwrap().is_empty());
        assert!(store.head(&DOC, "x/y.bin").unwrap().unwrap().written);
    }
}
