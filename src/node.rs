//! One iroh endpoint with the blobs, gossip and docs protocols mounted on a
//! router, backed by the persistent stores under `.vault/`.

use std::net::SocketAddr;

use anyhow::{bail, Context, Result};
use iroh::endpoint::presets;
use iroh::protocol::Router;
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayMode, SecretKey};
use iroh_blobs::api::downloader::Downloader;
use iroh_blobs::api::Store as BlobStore;
use iroh_blobs::store::fs::FsStore;
use iroh_blobs::{BlobsProtocol, ALPN as BLOBS_ALPN};
use iroh_docs::protocol::Docs;
use iroh_docs::ALPN as DOCS_ALPN;
use iroh_gossip::net::Gossip;
use iroh_gossip::ALPN as GOSSIP_ALPN;

use crate::auth::{self, AuthConfig};
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
    /// Override the authentication handshake timeout (tests).
    pub handshake_timeout: Option<std::time::Duration>,
    /// Override the number of authentication handshakes served at once (tests).
    pub max_in_flight: Option<usize>,
}

impl NetOptions {
    pub fn production() -> Self {
        Self {
            network: Network::Production,
            bind: None,
            handshake_timeout: None,
            max_in_flight: None,
        }
    }

    pub fn loopback() -> Self {
        Self {
            network: Network::Loopback,
            bind: None,
            handshake_timeout: None,
            max_in_flight: None,
        }
    }
}

/// A running node: endpoint, stores, protocols and router.
#[derive(Debug)]
pub struct Node {
    endpoint: Endpoint,
    blobs: FsStore,
    downloader: Downloader,
    docs: Docs,
    router: Router,
    /// The outgoing pre-authentication task, when admission is on.
    auth_task: Option<tokio::task::JoinHandle<()>>,
    /// Held until [`Node::shutdown`]; see [`Node::lock`].
    lock_file: std::fs::File,
}

impl Node {
    /// Bind the endpoint, open the stores under `layout` and mount the
    /// protocols. With `auth`, the endpoint hook gates every ALPN (SEC-1).
    pub async fn spawn(
        layout: &Layout,
        secret: SecretKey,
        net: &NetOptions,
        auth: Option<AuthConfig>,
    ) -> Result<Node> {
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
        let mut auth_parts = None;
        if let Some(config) = auth {
            let (hook, task, protocol) = auth::build(config);
            builder = builder.hooks(hook);
            auth_parts = Some((task, protocol));
        }
        let endpoint = builder
            .secret_key(secret)
            .bind()
            .await
            .context("binding the iroh endpoint")?;
        let blobs = FsStore::load(layout.blobs())
            .await
            .with_context(|| format!("opening blob store {}", layout.blobs().display()))?;
        let downloader = blobs.downloader(&endpoint);
        let gossip = Gossip::builder().spawn(endpoint.clone());
        let docs = Docs::persistent(layout.docs())
            .spawn(endpoint.clone(), (*blobs).clone(), gossip.clone())
            .await
            .with_context(|| format!("opening docs store {}", layout.docs().display()))?;
        let mut router = Router::builder(endpoint.clone())
            .accept(BLOBS_ALPN, BlobsProtocol::new(&blobs, None))
            .accept(GOSSIP_ALPN, gossip)
            .accept(DOCS_ALPN, docs.clone());
        let mut auth_task = None;
        if let Some((task, protocol)) = auth_parts {
            auth_task = Some(task.spawn(endpoint.clone()));
            router = router.accept(auth::ALPN, protocol);
        }
        let router = router.spawn();
        Ok(Node {
            endpoint,
            blobs,
            downloader,
            docs,
            router,
            auth_task,
            lock_file: lock,
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

    /// Multi-provider downloader over this endpoint.
    pub fn downloader(&self) -> &Downloader {
        &self.downloader
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

    /// Stop the protocols (which shuts the stores down), close the endpoint
    /// and release the vault lock, so the directory can be opened again even
    /// while this value is still alive.
    pub async fn shutdown(&self) -> Result<()> {
        self.router
            .shutdown()
            .await
            .context("shutting the router down")?;
        self.endpoint.close().await;
        if let Some(task) = &self.auth_task {
            task.abort();
        }
        if let Err(err) = self.lock_file.unlock() {
            tracing::warn!("releasing the vault lock: {err}");
        }
        Ok(())
    }
}
