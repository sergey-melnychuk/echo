//! Docs + blobs wiring for scenarios 4 and 6 (multi-source download, offline
//! catch-up). Built against iroh-docs 0.101.0, iroh-blobs 0.103.0 and
//! iroh-gossip 0.101.0, following the setup in iroh-docs' own README: blobs,
//! gossip and docs all share the one endpoint and are registered on the same
//! `Router` as the watch protocol, each under its own ALPN.
//!
//! Two roles:
//! - `share` (home): open or create one doc, import files into it keyed by
//!   file name, write a read ticket to `<data_dir>/ticket.txt`. The doc id is
//!   persisted, so a later run re-imports into the same doc and the ticket
//!   stays valid — that is how scenario 6 adds entries while a peer is down,
//!   and how scenario 4 re-imports a changed file under the same key.
//! - `join` (everyone else): import the ticket, log every `LiveEvent`, and
//!   export each entry's content to `<data_dir>/out/<key>` once it's ready.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result};
use futures_lite::{Stream, StreamExt};
use iroh::{Endpoint, protocol::RouterBuilder};
use iroh_blobs::{
    BlobsProtocol, Hash,
    api::blobs::{ExportMode, ImportMode},
    store::fs::FsStore,
};
use iroh_docs::{
    ContentStatus, DocTicket, Entry, NamespaceId,
    api::{
        Doc,
        protocol::{AddrInfoOptions, ShareMode},
    },
    engine::LiveEvent,
    protocol::Docs,
};
use iroh_gossip::net::Gossip;

use crate::log;

/// Blobs + gossip + docs, all persisted under one data directory.
pub struct DocsNode {
    docs: Docs,
    blobs: FsStore,
    gossip: Gossip,
    data_dir: PathBuf,
}

impl DocsNode {
    pub async fn spawn(endpoint: &Endpoint, data_dir: &Path) -> Result<Self> {
        let docs_dir = data_dir.join("docs");
        std::fs::create_dir_all(&docs_dir)?;
        let blobs = FsStore::load(data_dir.join("blobs")).await?;
        let gossip = Gossip::builder().spawn(endpoint.clone());
        let docs = Docs::persistent(docs_dir)
            .spawn(endpoint.clone(), (*blobs).clone(), gossip.clone())
            .await?;
        Ok(Self {
            docs,
            blobs,
            gossip,
            data_dir: data_dir.to_path_buf(),
        })
    }

    /// Adds the blobs, gossip and docs handlers to the router.
    pub fn register(&self, router: RouterBuilder) -> RouterBuilder {
        router
            .accept(iroh_blobs::ALPN, BlobsProtocol::new(&self.blobs, None))
            .accept(iroh_gossip::ALPN, self.gossip.clone())
            .accept(iroh_docs::ALPN, self.docs.clone())
    }

    /// Call after `Router::shutdown`, which already shuts down docs and gossip.
    /// The blob store drops (and so flushes) its database before replying,
    /// but the reply itself can get lost ("Sender closed") as the store's
    /// actors exit, so a failure here is logged rather than treated as fatal.
    pub async fn shutdown(&self, node_name: &str) {
        if let Err(e) = self.blobs.shutdown().await {
            log(node_name, "blobs_shutdown", None, Some(format!("{e:#}")));
        }
    }

    /// Home role: import `files` into this node's doc and publish a ticket.
    pub async fn share(&self, node_name: &str, files: &[PathBuf]) -> Result<()> {
        let doc = self.open_or_create_doc().await?;
        let author = self.docs.author_default().await?;
        let events = doc.subscribe().await?;
        tokio::spawn(watch_events(node_name.to_string(), events, None));

        for file in files {
            let path = std::path::absolute(file)?;
            let key = path
                .file_name()
                .with_context(|| format!("no file name in {}", path.display()))?
                .to_string_lossy()
                .into_owned();
            let started = Instant::now();
            let outcome = doc
                .import_file(&self.blobs, author, key.clone().into(), &path, ImportMode::Copy)
                .await?
                .await?;
            log(
                node_name,
                "import_done",
                None,
                Some(format!(
                    "key={key} hash={} size={} ms={}",
                    outcome.hash,
                    outcome.size,
                    started.elapsed().as_millis()
                )),
            );
        }

        // Read access is all the joining nodes need, and a read ticket holds
        // no namespace secret, so it is safe to post to the group and to
        // leave in probe.log.
        let ticket = doc.share(ShareMode::Read, AddrInfoOptions::Id).await?;
        std::fs::write(self.data_dir.join("ticket.txt"), ticket.to_string())?;
        log(node_name, "doc_ticket", None, Some(ticket.to_string()));
        Ok(())
    }

    /// Receiving role: join the doc behind `ticket` and watch it sync.
    pub async fn join(&self, node_name: &str, ticket: &str) -> Result<()> {
        let ticket: DocTicket = ticket.parse().context("invalid doc ticket")?;
        let (doc, events) = self.docs.import_and_subscribe(ticket).await?;
        log(node_name, "doc_joined", None, Some(doc.id().to_string()));
        let exporter = Arc::new(Exporter {
            doc,
            blobs: self.blobs.clone(),
            out_dir: self.data_dir.join("out"),
        });
        tokio::spawn(watch_events(node_name.to_string(), events, Some(exporter)));
        Ok(())
    }

    async fn open_or_create_doc(&self) -> Result<Doc> {
        let id_file = self.data_dir.join("doc_id.txt");
        if let Ok(id) = std::fs::read_to_string(&id_file) {
            let id: NamespaceId = id.trim().parse()?;
            if let Some(doc) = self.docs.open(id).await? {
                return Ok(doc);
            }
        }
        let doc = self.docs.create().await?;
        std::fs::write(&id_file, doc.id().to_string())?;
        Ok(doc)
    }
}

/// Exports each synced entry to disk once its content is available locally.
struct Exporter {
    doc: Doc,
    blobs: FsStore,
    out_dir: PathBuf,
}

impl Exporter {
    /// Runs the export as its own task so a large copy doesn't delay the
    /// timestamps on the events logged after it.
    fn spawn_export(self: &Arc<Self>, node_name: &str, entry: Entry) {
        let this = self.clone();
        let node_name = node_name.to_string();
        tokio::spawn(async move { this.export(&node_name, entry).await });
    }

    async fn export(&self, node_name: &str, entry: Entry) {
        let key = String::from_utf8_lossy(entry.key()).replace('/', "_");
        let started = Instant::now();
        let res: Result<u64> = async {
            std::fs::create_dir_all(&self.out_dir)?;
            let dest = std::path::absolute(self.out_dir.join(&key))?;
            let size = self
                .doc
                .export_file(&self.blobs, entry, dest, ExportMode::Copy)
                .await?
                .await?;
            Ok(size)
        }
        .await;
        match res {
            Ok(size) => log(
                node_name,
                "export_done",
                None,
                Some(format!("key={key} size={size} ms={}", started.elapsed().as_millis())),
            ),
            Err(e) => log(node_name, "export_failed", None, Some(format!("key={key} {e:#}"))),
        }
    }
}

/// Logs every `LiveEvent` as a `docs_event` line. `InsertRemote` (an entry
/// arrived) and `ContentReady` (its blob finished downloading and verified)
/// are the two that matter for timing: the gap between them per entry is the
/// scenario-4 transfer signal, and the gap from process start to the last
/// expected `ContentReady` is the scenario-6 catch-up signal.
async fn watch_events(
    node_name: String,
    mut events: impl Stream<Item = Result<LiveEvent>> + Unpin,
    exporter: Option<Arc<Exporter>>,
) {
    // ContentReady only carries the hash; remember which entry it belongs to.
    let mut pending: HashMap<Hash, Entry> = HashMap::new();
    while let Some(ev) = events.next().await {
        let ev = match ev {
            Ok(ev) => ev,
            Err(e) => {
                log(&node_name, "docs_error", None, Some(format!("{e:#}")));
                break;
            }
        };
        match ev {
            LiveEvent::InsertRemote {
                from,
                entry,
                content_status,
            } => {
                log(
                    &node_name,
                    "docs_event",
                    Some(&from.to_string()),
                    Some(format!(
                        "InsertRemote key={} hash={} size={} status={content_status:?}",
                        String::from_utf8_lossy(entry.key()),
                        entry.content_hash(),
                        entry.content_len()
                    )),
                );
                if let Some(exporter) = &exporter {
                    // Content we already hold never gets a ContentReady.
                    if matches!(content_status, ContentStatus::Complete) {
                        exporter.spawn_export(&node_name, entry);
                    } else {
                        pending.insert(entry.content_hash(), entry);
                    }
                }
            }
            LiveEvent::ContentReady { hash } => {
                log(
                    &node_name,
                    "docs_event",
                    None,
                    Some(format!("ContentReady hash={hash}")),
                );
                if let (Some(exporter), Some(entry)) = (&exporter, pending.remove(&hash)) {
                    exporter.spawn_export(&node_name, entry);
                }
            }
            other => log(&node_name, "docs_event", None, Some(format!("{other:?}"))),
        }
    }
    log(&node_name, "docs_watch_ended", None, None);
}
