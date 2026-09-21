//! One iroh endpoint with the blobs, gossip and docs protocols mounted on a
//! router, backed by the persistent stores under `.vault/`.

use std::net::SocketAddr;

use anyhow::{bail, Context, Result};
use iroh::endpoint::presets;
use iroh::protocol::Router;
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayMode, SecretKey};
use iroh_blobs::api::Store as BlobStore;
use iroh_blobs::store::fs::FsStore;
use iroh_blobs::{BlobsProtocol, ALPN as BLOBS_ALPN};
use iroh_docs::protocol::Docs;
use iroh_docs::ALPN as DOCS_ALPN;
use iroh_gossip::net::Gossip;
use iroh_gossip::ALPN as GOSSIP_ALPN;

use crate::config::Layout;

/// Which network the endpoint joins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    /// n0's relays and address lookup (pkarr, DNS): the `N0` preset.
    Production,
    /// Loopback only: no relays, no address lookup. Peers are reached through
    /// the addresses carried in tickets. Used by tests and local demos.
    Loopback,
}

/// Endpoint options.
#[derive(Debug, Clone)]
pub struct NetOptions {
    pub network: Network,
    /// Bind to this UDP address instead of a random port.
    pub bind: Option<SocketAddr>,
}

impl NetOptions {
    pub fn production() -> Self {
        Self {
            network: Network::Production,
            bind: None,
        }
    }

    pub fn loopback() -> Self {
        Self {
            network: Network::Loopback,
            bind: None,
        }
    }
}

/// A running node: endpoint, stores, protocols and router.
#[derive(Debug)]
pub struct Node {
    endpoint: Endpoint,
    blobs: FsStore,
    docs: Docs,
    router: Router,
    /// Held for the node's lifetime; see [`Node::lock`].
    _lock: std::fs::File,
}

impl Node {
    /// Bind the endpoint, open the stores under `layout` and mount the protocols.
    pub async fn spawn(layout: &Layout, secret: SecretKey, net: &NetOptions) -> Result<Node> {
        layout.create_dirs()?;
        let lock = Self::lock(layout)?;
        let mut builder = match net.network {
            Network::Production => Endpoint::builder(presets::N0),
            Network::Loopback => Endpoint::builder(presets::Minimal)
                .relay_mode(RelayMode::Disabled)
                .clear_ip_transports()
                .bind_addr("127.0.0.1:0")?,
        };
        if let Some(addr) = net.bind {
            builder = builder.clear_ip_transports().bind_addr(addr)?;
        }
        let endpoint = builder
            .secret_key(secret)
            .bind()
            .await
            .context("binding the iroh endpoint")?;
        let blobs = FsStore::load(layout.blobs())
            .await
            .with_context(|| format!("opening blob store {}", layout.blobs().display()))?;
        let gossip = Gossip::builder().spawn(endpoint.clone());
        let docs = Docs::persistent(layout.docs())
            .spawn(endpoint.clone(), (*blobs).clone(), gossip.clone())
            .await
            .with_context(|| format!("opening docs store {}", layout.docs().display()))?;
        let router = Router::builder(endpoint.clone())
            .accept(BLOBS_ALPN, BlobsProtocol::new(&blobs, None))
            .accept(GOSSIP_ALPN, gossip)
            .accept(DOCS_ALPN, docs.clone())
            .spawn();
        Ok(Node {
            endpoint,
            blobs,
            docs,
            router,
            _lock: lock,
        })
    }

    /// Take the vault lock (`.vault/lock`, an advisory file lock) or fail at
    /// once. The redb stores are exclusive too, but a second opener blocks on
    /// them instead of failing, which made `status` hang while `run` was
    /// active (NOTES.md, stage 1).
    fn lock(layout: &Layout) -> Result<std::fs::File> {
        let path = layout.lock();
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&path)
            .with_context(|| format!("opening {}", path.display()))?;
        match file.try_lock() {
            Ok(()) => Ok(file),
            Err(std::fs::TryLockError::WouldBlock) => bail!(
                "{} is in use by another process (is `run` active?)",
                layout.root().display()
            ),
            Err(std::fs::TryLockError::Error(err)) => {
                Err(err).with_context(|| format!("locking {}", path.display()))
            }
        }
    }

    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    pub fn blobs(&self) -> &BlobStore {
        &self.blobs
    }

    pub fn docs(&self) -> &Docs {
        &self.docs
    }

    pub fn id(&self) -> EndpointId {
        self.endpoint.id()
    }

    /// This endpoint's id and currently known addresses.
    pub fn addr(&self) -> EndpointAddr {
        self.endpoint.addr()
    }

    /// The addresses iroh currently knows for a remote, if it has been in
    /// contact recently.
    pub async fn remote_addr(&self, id: EndpointId) -> Option<EndpointAddr> {
        let info = self.endpoint.remote_info(id).await?;
        Some(EndpointAddr::from_parts(
            id,
            info.into_addrs().map(|a| a.into_addr()),
        ))
    }

    /// Stop the protocols (which shuts the stores down) and close the endpoint.
    pub async fn shutdown(self) -> Result<()> {
        self.router
            .shutdown()
            .await
            .context("shutting the router down")?;
        self.endpoint.close().await;
        Ok(())
    }
}
