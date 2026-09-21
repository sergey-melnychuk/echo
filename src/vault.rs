//! A vault: one docs replica, one author, one node, one folder.

use std::net::SocketAddr;
use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use iroh::{EndpointAddr, EndpointId};
use iroh_blobs::Hash;
use iroh_docs::api::protocol::{AddrInfoOptions, ShareMode};
use iroh_docs::api::Doc;
use iroh_docs::engine::LiveEvent;
use iroh_docs::store::Query;
use iroh_docs::{AuthorId, Capability, DocTicket, Entry, NamespaceId};
use n0_future::{Stream, TryStreamExt};

use crate::config::{self, Config, Layout};
use crate::node::{NetOptions, Node};

/// An open vault.
#[derive(Debug)]
pub struct Vault {
    layout: Layout,
    config: Config,
    node: Node,
    doc: Doc,
    author: AuthorId,
}

impl Vault {
    /// Create a new vault in `dir`: endpoint key, namespace, author, config.
    pub async fn init(dir: &Path, net: &NetOptions) -> Result<Vault> {
        let layout = Layout::new(dir);
        if layout.is_initialized() {
            bail!("{} is already a vault", dir.display());
        }
        layout.create_dirs()?;
        let secret = config::load_or_create_secret_key(&layout.endpoint_key())?;
        let node = Node::spawn(&layout, secret, net).await?;
        let doc = node.docs().create().await?;
        // The only way to get the namespace secret out of docs is a write ticket.
        let ticket = doc.share(ShareMode::Write, AddrInfoOptions::Id).await?;
        config::save_capability(&layout.vault_key(), &ticket.capability)?;
        let config = Config::new(doc.id(), true);
        config.save(&layout.config())?;
        let author = node.docs().author_default().await?;
        Ok(Vault {
            layout,
            config,
            node,
            doc,
            author,
        })
    }

    /// Join an existing vault from a docs ticket. Syncing starts with
    /// [`Vault::start_sync`].
    pub async fn join(dir: &Path, ticket: DocTicket, net: &NetOptions) -> Result<Vault> {
        let layout = Layout::new(dir);
        if layout.is_initialized() {
            bail!("{} is already a vault", dir.display());
        }
        layout.create_dirs()?;
        let secret = config::load_or_create_secret_key(&layout.endpoint_key())?;
        let node = Node::spawn(&layout, secret, net).await?;
        let write = matches!(ticket.capability, Capability::Write(_));
        config::save_capability(&layout.vault_key(), &ticket.capability)?;
        let doc = node
            .docs()
            .import_namespace(ticket.capability.clone())
            .await?;
        let mut peers = Vec::new();
        for peer in ticket.nodes {
            if peer.id != node.id() {
                config::merge_peer(&mut peers, peer);
            }
        }
        config::save_peers(&layout.peers(), &peers)?;
        let config = Config::new(doc.id(), write);
        config.save(&layout.config())?;
        let author = node.docs().author_default().await?;
        Ok(Vault {
            layout,
            config,
            node,
            doc,
            author,
        })
    }

    /// Open an existing vault.
    pub async fn open(dir: &Path, net: &NetOptions) -> Result<Vault> {
        let layout = Layout::new(dir);
        if !layout.is_initialized() {
            bail!(
                "{} is not a vault (no {}); run `init` or `join` first",
                dir.display(),
                layout.config().display()
            );
        }
        let config = Config::load(&layout.config())?;
        let id = config.namespace_id()?;
        let secret = config::load_secret_key(&layout.endpoint_key())?;
        let node = Node::spawn(&layout, secret, net).await?;
        let doc = node
            .docs()
            .open(id)
            .await?
            .ok_or_else(|| anyhow!("vault {id} is missing from the docs store"))?;
        let author = node.docs().author_default().await?;
        Ok(Vault {
            layout,
            config,
            node,
            doc,
            author,
        })
    }

    pub fn layout(&self) -> &Layout {
        &self.layout
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    pub fn node(&self) -> &Node {
        &self.node
    }

    pub fn doc(&self) -> &Doc {
        &self.doc
    }

    pub fn author(&self) -> AuthorId {
        self.author
    }

    pub fn id(&self) -> NamespaceId {
        self.doc.id()
    }

    pub fn endpoint_id(&self) -> EndpointId {
        self.node.id()
    }

    pub fn can_write(&self) -> bool {
        self.config.write
    }

    /// A ticket for a new member, carrying this node's addresses plus `extra`.
    pub async fn ticket(&self, mode: ShareMode, extra: &[SocketAddr]) -> Result<DocTicket> {
        let capability = config::load_capability(&self.layout.vault_key())?;
        let capability = restrict_capability(capability, mode)?;
        let mut addr = self.node.addr();
        for a in extra {
            addr = addr.with_ip_addr(*a);
        }
        Ok(DocTicket::new(capability, vec![addr]))
    }

    /// Known peers with addresses, from `.vault/peers.json`.
    pub fn peers(&self) -> Result<Vec<EndpointAddr>> {
        config::load_peers(&self.layout.peers())
    }

    /// Known peer ids, the providers for blob downloads.
    pub fn peer_ids(&self) -> Result<Vec<EndpointId>> {
        Ok(self.peers()?.into_iter().map(|p| p.id).collect())
    }

    /// Remember a peer's address for the next start.
    pub fn remember_peer_addr(&self, addr: EndpointAddr) -> Result<bool> {
        if addr.id == self.node.id() {
            return Ok(false);
        }
        let mut peers = self.peers()?;
        let changed = config::merge_peer(&mut peers, addr);
        if changed {
            config::save_peers(&self.layout.peers(), &peers)?;
        }
        Ok(changed)
    }

    /// Remember a peer seen in a live event, with whatever addresses iroh
    /// currently knows for it.
    pub async fn remember_peer(&self, id: EndpointId) -> Result<bool> {
        let addr = self
            .node
            .remote_addr(id)
            .await
            .unwrap_or_else(|| EndpointAddr::new(id));
        self.remember_peer_addr(addr)
    }

    /// Record this node's current addresses for `invite` to use.
    pub fn save_own_addr(&self) -> Result<()> {
        config::save_own_addr(&self.layout.own_addr(), &self.node.addr())
    }

    /// Start live sync with every known peer. Docs does not resume syncing on
    /// its own after a restart (NOTES.md).
    pub async fn start_sync(&self) -> Result<()> {
        let peers = self.peers()?;
        if peers.is_empty() {
            tracing::info!("no known peers yet; waiting for peers to connect");
        }
        self.doc.start_sync(peers).await
    }

    /// Write an entry under this device's author.
    pub async fn set(&self, key: impl Into<Vec<u8>>, value: impl Into<Vec<u8>>) -> Result<Hash> {
        if !self.config.write {
            bail!("this device holds a read-only capability and cannot publish (SEC-6)");
        }
        self.doc
            .set_bytes(self.author, key.into(), value.into())
            .await
    }

    pub async fn entries(&self, query: impl Into<Query>) -> Result<Vec<Entry>> {
        self.doc.get_many(query).await?.try_collect().await
    }

    pub async fn has_content(&self, hash: Hash) -> Result<bool> {
        Ok(self.node.blobs().has(hash).await?)
    }

    pub async fn content(&self, hash: Hash) -> Result<Vec<u8>> {
        Ok(self
            .node
            .blobs()
            .get_bytes(hash)
            .await
            .with_context(|| format!("reading content {}", hash.fmt_short()))?
            .to_vec())
    }

    pub async fn subscribe(
        &self,
    ) -> Result<impl Stream<Item = Result<LiveEvent>> + Send + Unpin + 'static> {
        self.doc.subscribe().await
    }

    /// Look up this device's own entry for `key`.
    pub async fn own_entry(&self, key: &str) -> Result<Option<Entry>> {
        self.doc.get_exact(self.author, key, false).await
    }

    /// Stop the node. The vault is unusable afterwards.
    pub async fn shutdown(&self) -> Result<()> {
        self.node.shutdown().await
    }
}

/// Narrow a stored capability to the requested share mode.
pub fn restrict_capability(capability: Capability, mode: ShareMode) -> Result<Capability> {
    match (mode, capability) {
        (ShareMode::Write, cap @ Capability::Write(_)) => Ok(cap),
        (ShareMode::Write, Capability::Read(_)) => {
            bail!("this device holds a read-only capability and cannot issue a write invite")
        }
        (ShareMode::Read, cap) => Ok(Capability::Read(cap.id())),
    }
}
