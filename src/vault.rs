//! A vault: one docs replica, one author, one node, one folder, one token.

use std::net::SocketAddr;
use std::path::Path;
use std::time::{Duration, SystemTime};

use anyhow::{anyhow, bail, Context, Result};
use iroh::{EndpointAddr, EndpointId, SecretKey};
use iroh_blobs::Hash;
use iroh_docs::api::protocol::ShareMode;
use iroh_docs::api::Doc;
use iroh_docs::engine::LiveEvent;
use iroh_docs::store::Query;
use iroh_docs::{AuthorId, Capability, DocTicket, Entry, NamespaceId, NamespaceSecret};
use n0_future::{Stream, TryStreamExt};

use crate::auth::{self, AuthConfig, Verifier};
use crate::config::{self, Config, Layout};
use crate::invite::Invite;
use crate::node::{NetOptions, Node};

/// How long the owner's own token lives; `open` mints a fresh one when it
/// no longer admits this device.
pub const OWNER_TOKEN_TTL: Duration = Duration::from_secs(365 * 86_400);

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
    /// Create a new vault in `dir`: endpoint key, namespace, Biscuit root key,
    /// this device's own token, author, config.
    pub async fn init(dir: &Path, net: &NetOptions) -> Result<Vault> {
        let layout = Layout::new(dir);
        if layout.is_initialized() {
            bail!("{} is already a vault", dir.display());
        }
        layout.create_dirs()?;
        let secret = config::load_or_create_secret_key(&layout.endpoint_key())?;
        // The namespace is generated here rather than by docs, because the
        // owner's token must name the vault id before the node binds.
        let namespace = NamespaceSecret::from_bytes(&SecretKey::generate().to_bytes());
        let id = namespace.id();
        let root = auth::generate_root();
        config::save_bytes_private(&layout.root_key(), &auth::root_to_bytes(&root))?;
        let token = mint_owner_token(&root, &id.to_string(), &secret.public())?;
        config::save_bytes_private(&layout.token(), &token)?;
        let capability = Capability::Write(namespace);
        config::save_capability(&layout.vault_key(), &capability)?;
        let mut auth_config = AuthConfig::new(token, root.public(), id.to_string());
        apply_overrides(&mut auth_config, net);
        let node = Node::spawn(&layout, secret, net, Some(auth_config)).await?;
        let doc = node.docs().import_namespace(capability).await?;
        let mut config = Config::new(id, true);
        config.root_public_key = Some(auth::public_to_hex(&root.public()));
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

    /// Join an existing vault from an invite. Syncing starts with
    /// [`Vault::start_sync`].
    pub async fn join(dir: &Path, invite: &Invite, net: &NetOptions) -> Result<Vault> {
        let layout = Layout::new(dir);
        if layout.is_initialized() {
            bail!("{} is already a vault", dir.display());
        }
        layout.create_dirs()?;
        let secret = config::load_or_create_secret_key(&layout.endpoint_key())?;
        let ticket = invite.doc_ticket()?;
        let token = invite.token_bytes()?;
        let root = invite.root_key()?;
        let id = ticket.capability.id();
        // Refuse an invite that would not admit this device (SEC-2, checked
        // early so the failure is explained here rather than by silent peers).
        Verifier::new(root, id.to_string())
            .verify(&token, &secret.public(), SystemTime::now())
            .context(
                "this invite does not admit this device: wrong audience, expired, or another vault",
            )?;
        let write = matches!(ticket.capability, Capability::Write(_));
        config::save_capability(&layout.vault_key(), &ticket.capability)?;
        config::save_bytes_private(&layout.token(), &token)?;
        let mut peers = Vec::new();
        for peer in &ticket.nodes {
            if peer.id != secret.public() {
                config::merge_peer(&mut peers, peer.clone());
            }
        }
        config::save_peers(&layout.peers(), &peers)?;
        let mut auth_config = AuthConfig::new(token, root, id.to_string());
        apply_overrides(&mut auth_config, net);
        let node = Node::spawn(&layout, secret, net, Some(auth_config)).await?;
        let doc = node
            .docs()
            .import_namespace(ticket.capability.clone())
            .await?;
        let mut config = Config::new(id, write);
        config.root_public_key = Some(auth::public_to_hex(&root));
        config.token_delegatable = invite.delegatable;
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
        let auth_config = auth_config(&layout, &config, &secret, net)?;
        let node = Node::spawn(&layout, secret, net, auth_config).await?;
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

    /// A docs ticket for a new member, carrying this node's addresses plus `extra`.
    pub fn ticket(&self, mode: ShareMode, extra: &[SocketAddr]) -> Result<DocTicket> {
        let capability = config::load_capability(&self.layout.vault_key())?;
        let capability = restrict_capability(capability, mode)?;
        let mut addr = self.node.addr();
        for a in extra {
            addr = addr.with_ip_addr(*a);
        }
        Ok(DocTicket::new(capability, vec![addr]))
    }

    /// An invite for a new device: the owner mints from the root key; a
    /// member with a delegatable token narrows its own token. Without an
    /// audience the invite is a bearer secret, and itself delegatable.
    pub fn invite(
        &self,
        mode: ShareMode,
        audience: Option<EndpointId>,
        ttl: Duration,
    ) -> Result<Invite> {
        make_invite(
            &self.layout,
            &self.config,
            self.node.addr(),
            mode,
            audience,
            ttl,
        )
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

fn mint_owner_token(
    root: &biscuit_auth::KeyPair,
    vault_id: &str,
    own: &EndpointId,
) -> Result<Vec<u8>> {
    let authority = auth::mint_authority(root, vault_id)?;
    auth::attenuate(&authority, Some(own), SystemTime::now() + OWNER_TOKEN_TTL)?
        .to_vec()
        .map_err(|err| anyhow!("serializing the owner token: {err}"))
}

fn apply_overrides(config: &mut AuthConfig, net: &NetOptions) {
    if let Some(timeout) = net.handshake_timeout {
        config.handshake_timeout = timeout;
    }
    if let Some(max) = net.max_in_flight {
        config.max_in_flight = max;
    }
}

/// The admission config for an existing vault: the stored token, re-minted
/// by the owner when it no longer admits this device. `None` for vaults
/// without a root key (created before admission existed).
fn auth_config(
    layout: &Layout,
    config: &Config,
    secret: &SecretKey,
    net: &NetOptions,
) -> Result<Option<AuthConfig>> {
    let Some(root_hex) = &config.root_public_key else {
        tracing::warn!("this vault has no admission configured; every peer is accepted");
        return Ok(None);
    };
    let root = auth::public_from_hex(root_hex)?;
    let vault_id = config.vault_id.clone();
    let verifier = Verifier::new(root, vault_id.clone());
    let own = secret.public();
    let now = SystemTime::now();
    let stored = match config::load_bytes_private(&layout.token()) {
        Ok(stored) => stored,
        Err(err) => {
            tracing::warn!("ignoring an unreadable token file: {err:#}");
            None
        }
    };
    let token = match stored {
        Some(token) if verifier.verify(&token, &own, now).is_ok() => token,
        stored => match config::load_bytes_private(&layout.root_key())? {
            Some(root_bytes) => {
                let key_pair = auth::root_from_bytes(&root_bytes)?;
                if key_pair.public() != root {
                    bail!("the Biscuit root key does not match the configured public key");
                }
                tracing::info!("minting a fresh owner token");
                let fresh = mint_owner_token(&key_pair, &vault_id, &own)?;
                config::save_bytes_private(&layout.token(), &fresh)?;
                fresh
            }
            None if stored.is_none() => bail!("this device has no token; ask the owner for an invite"),
            None => bail!(
                "this device's token has expired or does not admit it; ask the owner for a new invite"
            ),
        },
    };
    let mut auth_config = AuthConfig::new(token, root, vault_id);
    apply_overrides(&mut auth_config, net);
    Ok(Some(auth_config))
}

/// Build an invite from the files under `.vault/`, without the stores:
/// capability, root key or own token, and `addr` for the new device to dial.
pub fn make_invite(
    layout: &Layout,
    config: &Config,
    addr: EndpointAddr,
    mode: ShareMode,
    audience: Option<EndpointId>,
    ttl: Duration,
) -> Result<Invite> {
    let capability = config::load_capability(&layout.vault_key())?;
    let capability = restrict_capability(capability, mode)?;
    let ticket = DocTicket::new(capability, vec![addr]);
    let root_hex = config.root_public_key.as_deref().ok_or_else(|| {
        anyhow!("this vault has no admission configured and cannot issue invites")
    })?;
    let root = auth::public_from_hex(root_hex)?;
    let expires = SystemTime::now() + ttl;
    let base = match config::load_bytes_private(&layout.root_key())? {
        Some(root_bytes) => {
            let key_pair = auth::root_from_bytes(&root_bytes)?;
            if key_pair.public() != root {
                bail!("the Biscuit root key does not match the configured public key");
            }
            auth::mint_authority(&key_pair, &config.vault_id)?
        }
        None => {
            if !config.token_delegatable {
                bail!(
                    "this device's token is bound to it and cannot be delegated; \
                     ask the owner for the invite"
                );
            }
            let token = config::load_bytes_private(&layout.token())?
                .ok_or_else(|| anyhow!("this device has no token"))?;
            auth::parse_token(&token, &root)?
        }
    };
    let token = auth::attenuate(&base, audience.as_ref(), expires)?
        .to_vec()
        .map_err(|err| anyhow!("serializing the invite token: {err}"))?;
    Ok(Invite::new(&ticket, &token, &root, audience.is_none()))
}
