//! Command implementations for the binary: `init`, `whoami`, `invite`,
//! `join`, `run` and `status`. `main.rs` only parses arguments and calls
//! [`execute`]; keeping the logic here lets tests drive it directly.
//!
//! Everything the tool owns lives under `<dir>/.p2p-sync/` (section 10):
//! `node.key` and `owner.key` (hex, mode 0600), `config.toml` (mode 0600,
//! holds the salt and token), `store.redb`, `tmp/` and `rejected/`.

use crate::capabilities::{CapabilityClaims, CapabilityToken};
use crate::clock::unix_now_secs;
use crate::crypto::{derive_topic_id, generate_signing_key, random_bytes32, short_hex};
use crate::gossip::GossipNode;
use crate::manifest::INTERNAL_DIR;
use crate::protocol;
use crate::storage::{RedbStore, Store};
use crate::sync::{
    spawn_catch_up_task, spawn_gossip_driver, DocContext, PublishOutcome, SyncEngine,
    CATCH_UP_INTERVAL,
};
use crate::transport::{bind_endpoint, router_builder, EndpointOptions, SyncProtocol};
use crate::watcher::FileWatcher;
use crate::Hash;
use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use iroh::{EndpointAddr, EndpointId, RelayUrl, SecretKey};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{info, warn};

/// Largest encoded invite accepted.
pub const INVITE_LIMIT: usize = 64 * 1024;
/// Validity of the token the owner issues to itself at `init`.
pub const OWNER_TOKEN_TTL: Duration = Duration::from_secs(365 * 24 * 3600);
/// Default `--ttl` for invites.
pub const DEFAULT_INVITE_TTL: &str = "24h";

/// `p2p-sync-poc`: sync a directory between peers with no central server.
#[derive(Parser, Debug, Clone, PartialEq, Eq)]
#[command(name = "p2p-sync-poc", version, about)]
pub struct Cli {
    /// The command.
    #[command(subcommand)]
    pub command: Command,
}

/// The commands from section 12, stage 9.
#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// Create a new document in `dir`: document ID, salt, owner key and node key.
    Init {
        /// Directory to sync (created if missing).
        dir: PathBuf,
    },
    /// Print this peer's node ID for `dir` (creating its node key if needed).
    Whoami {
        /// Directory to sync.
        dir: PathBuf,
    },
    /// Owner only: print an invite carrying a token bound to one peer.
    Invite {
        /// Directory of the document.
        dir: PathBuf,
        /// Node ID (hex) of the peer being invited.
        #[arg(long)]
        audience: String,
        /// Grant read.
        #[arg(long)]
        read: bool,
        /// Grant write.
        #[arg(long)]
        write: bool,
        /// Token lifetime, e.g. `30m`, `12h`, `7d` or seconds.
        #[arg(long, default_value = DEFAULT_INVITE_TTL)]
        ttl: String,
        /// Direct address(es) of this node to include for peers without relay
        /// or discovery, e.g. `192.168.1.5:11204`.
        #[arg(long = "addr")]
        addrs: Vec<SocketAddr>,
    },
    /// Join a document from an invite, storing its config in `dir`.
    Join {
        /// Directory to sync (created if missing).
        dir: PathBuf,
        /// The invite string printed by `invite`.
        invite: String,
    },
    /// Start the endpoint, gossip, watcher and sync engine.
    Run {
        /// Directory of the document.
        dir: PathBuf,
        /// Bind to 127.0.0.1 with relays disabled (local testing).
        #[arg(long)]
        loopback: bool,
        /// UDP port to bind (default: random).
        #[arg(long)]
        port: Option<u16>,
    },
    /// Print heads and kept rejected versions.
    Status {
        /// Directory of the document.
        dir: PathBuf,
    },
}

/// CLI failures.
#[derive(Debug, thiserror::Error)]
pub enum CliError {
    /// `init` on a directory that already has a config.
    #[error("{0} is already initialized")]
    AlreadyInitialized(PathBuf),
    /// A command that needs a config found none.
    #[error("{0} is not initialized or joined (no .p2p-sync/config.toml)")]
    NotInitialized(PathBuf),
    /// `invite` without the owner key.
    #[error("only the owner can invite: {0} has no .p2p-sync/owner.key")]
    NotOwner(PathBuf),
    /// `invite` with neither `--read` nor `--write`.
    #[error("an invite must grant --read and/or --write")]
    NoPermission,
    /// The invite's token is bound to another node.
    #[error("this invite is for node {audience}, but this node is {me}")]
    InviteNotForThisNode {
        /// Token audience.
        audience: String,
        /// Our node ID.
        me: String,
    },
    /// The invite's token does not verify against its owner key.
    #[error("invite token is invalid: {0}")]
    InvalidInvite(String),
    /// A value could not be parsed.
    #[error("invalid {what}: {value}")]
    Parse {
        /// What was being parsed.
        what: &'static str,
        /// The offending text.
        value: String,
    },
    /// Filesystem failure.
    #[error("io error at {path}: {source}")]
    Io {
        /// The path.
        path: PathBuf,
        /// The error.
        #[source]
        source: std::io::Error,
    },
    /// Config encoding or decoding failed.
    #[error("config error: {0}")]
    Config(String),
    /// A library layer failed.
    #[error(transparent)]
    Sync(#[from] crate::sync::SyncError),
    /// Storage failed.
    #[error(transparent)]
    Store(#[from] crate::storage::StoreError),
    /// `status` while `run` holds the store lock.
    #[error("the store in {0} is in use by a running node; stop it and retry")]
    StoreBusy(PathBuf),
    /// Transport failed.
    #[error(transparent)]
    Transport(#[from] crate::transport::TransportError),
    /// Gossip failed.
    #[error(transparent)]
    Gossip(#[from] crate::gossip::GossipError),
    /// The watcher failed.
    #[error(transparent)]
    Watcher(#[from] crate::watcher::WatcherError),
}

fn io(path: &Path) -> impl FnOnce(std::io::Error) -> CliError + '_ {
    move |source| CliError::Io {
        path: path.to_path_buf(),
        source,
    }
}

// ---------------------------------------------------------------------------
// Files on disk
// ---------------------------------------------------------------------------

/// One bootstrap peer as stored in `config.toml`: plain strings so the file
/// stays readable.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct BootstrapEntry {
    /// Node ID, hex.
    pub id: String,
    /// Direct socket addresses.
    #[serde(default)]
    pub addrs: Vec<String>,
    /// Relay URLs.
    #[serde(default)]
    pub relays: Vec<String>,
}

impl BootstrapEntry {
    /// Convert to an `EndpointAddr`, skipping unparsable parts.
    pub fn to_endpoint_addr(&self) -> Result<EndpointAddr, CliError> {
        let id = parse_node_id(&self.id)?;
        let mut addr = EndpointAddr::new(id);
        for a in &self.addrs {
            match a.parse::<SocketAddr>() {
                Ok(sa) => addr = addr.with_ip_addr(sa),
                Err(_) => warn!(addr = %a, "ignoring unparsable bootstrap address"),
            }
        }
        for r in &self.relays {
            match RelayUrl::from_str(r) {
                Ok(url) => addr = addr.with_relay_url(url),
                Err(_) => warn!(relay = %r, "ignoring unparsable relay url"),
            }
        }
        Ok(addr)
    }

    /// Build from an `EndpointAddr`.
    pub fn from_endpoint_addr(addr: &EndpointAddr) -> Self {
        BootstrapEntry {
            id: addr.id.to_string(),
            addrs: addr.ip_addrs().map(|a| a.to_string()).collect(),
            relays: addr.relay_urls().map(|r| r.to_string()).collect(),
        }
    }
}

/// `config.toml`. The salt and token are secrets: the file is mode 0600.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Config {
    /// Document ID, hex.
    pub doc_id: String,
    /// Owner public key, hex (SEC-1).
    pub owner_key: String,
    /// Topic salt, hex. Secret.
    pub salt: String,
    /// This node's capability token, hex of its wire encoding. Secret.
    pub token: String,
    /// Peers to dial at startup.
    #[serde(default)]
    pub bootstrap: Vec<BootstrapEntry>,
}

/// The decoded form of [`Config`].
#[derive(Clone, Debug)]
pub struct Loaded {
    /// Document ID.
    pub doc_id: Hash,
    /// Owner public key.
    pub owner_key: [u8; 32],
    /// Topic salt.
    pub salt: [u8; 32],
    /// This node's token.
    pub token: CapabilityToken,
    /// Bootstrap peers.
    pub bootstrap: Vec<EndpointAddr>,
}

impl Config {
    /// Encode a loaded config.
    pub fn from_loaded(l: &Loaded) -> Result<Self, CliError> {
        Ok(Config {
            doc_id: hex::encode(l.doc_id),
            owner_key: hex::encode(l.owner_key),
            salt: hex::encode(l.salt),
            token: hex::encode(
                protocol::encode(&l.token, INVITE_LIMIT)
                    .map_err(|e| CliError::Config(e.to_string()))?,
            ),
            bootstrap: l
                .bootstrap
                .iter()
                .map(BootstrapEntry::from_endpoint_addr)
                .collect(),
        })
    }

    /// Decode into typed values.
    pub fn load(&self) -> Result<Loaded, CliError> {
        let token_bytes = hex::decode(&self.token).map_err(|_| CliError::Parse {
            what: "token",
            value: "<hex>".into(),
        })?;
        let token: CapabilityToken = protocol::decode(&token_bytes, INVITE_LIMIT)
            .map_err(|e| CliError::Config(format!("token: {e}")))?;
        let mut bootstrap = Vec::new();
        for b in &self.bootstrap {
            bootstrap.push(b.to_endpoint_addr()?);
        }
        Ok(Loaded {
            doc_id: parse_hash("doc_id", &self.doc_id)?,
            owner_key: parse_hash("owner_key", &self.owner_key)?,
            salt: parse_hash("salt", &self.salt)?,
            token,
            bootstrap,
        })
    }
}

/// The tool's directory inside `dir`.
pub fn internal_dir(dir: &Path) -> PathBuf {
    dir.join(INTERNAL_DIR)
}

fn config_path(dir: &Path) -> PathBuf {
    internal_dir(dir).join("config.toml")
}

fn node_key_path(dir: &Path) -> PathBuf {
    internal_dir(dir).join("node.key")
}

fn owner_key_path(dir: &Path) -> PathBuf {
    internal_dir(dir).join("owner.key")
}

fn store_path(dir: &Path) -> PathBuf {
    internal_dir(dir).join("store.redb")
}

/// Write `contents` to `path` readable by the owner only.
fn write_secret(path: &Path, contents: &[u8]) -> Result<(), CliError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(io(parent))?;
    }
    std::fs::write(path, contents).map_err(io(path))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(io(path))?;
    }
    Ok(())
}

fn read_key_file(path: &Path) -> Result<Option<[u8; 32]>, CliError> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(Some(parse_hash("key file", text.trim())?)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(io(path)(e)),
    }
}

/// Load this node's endpoint key, creating one if there is none yet.
pub fn load_or_create_node_key(dir: &Path) -> Result<SecretKey, CliError> {
    let path = node_key_path(dir);
    if let Some(bytes) = read_key_file(&path)? {
        return Ok(SecretKey::from_bytes(&bytes));
    }
    let key = SecretKey::generate();
    write_secret(
        &path,
        format!("{}\n", hex::encode(key.to_bytes())).as_bytes(),
    )?;
    Ok(key)
}

/// Load the owner signing key if this is the owner's machine.
pub fn load_owner_key(dir: &Path) -> Result<Option<SigningKey>, CliError> {
    Ok(read_key_file(&owner_key_path(dir))?.map(|b| SigningKey::from_bytes(&b)))
}

/// Read and decode `config.toml`.
pub fn load_config(dir: &Path) -> Result<Loaded, CliError> {
    let path = config_path(dir);
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(CliError::NotInitialized(dir.to_path_buf()))
        }
        Err(e) => return Err(io(&path)(e)),
    };
    let config: Config = toml::from_str(&text).map_err(|e| CliError::Config(e.to_string()))?;
    config.load()
}

/// Encode and write `config.toml` with mode 0600.
pub fn save_config(dir: &Path, loaded: &Loaded) -> Result<(), CliError> {
    let config = Config::from_loaded(loaded)?;
    let text = toml::to_string_pretty(&config).map_err(|e| CliError::Config(e.to_string()))?;
    write_secret(&config_path(dir), text.as_bytes())
}

fn parse_hash(what: &'static str, s: &str) -> Result<[u8; 32], CliError> {
    let bytes = hex::decode(s).map_err(|_| CliError::Parse {
        what,
        value: s.to_string(),
    })?;
    <[u8; 32]>::try_from(bytes).map_err(|_| CliError::Parse {
        what,
        value: s.to_string(),
    })
}

/// Parse a node ID from hex.
pub fn parse_node_id(s: &str) -> Result<EndpointId, CliError> {
    EndpointId::from_str(s.trim()).map_err(|_| CliError::Parse {
        what: "node id",
        value: s.to_string(),
    })
}

/// Parse `30s`, `10m`, `12h`, `7d`, or plain seconds.
pub fn parse_duration(s: &str) -> Result<Duration, CliError> {
    let s = s.trim();
    let err = || CliError::Parse {
        what: "duration",
        value: s.to_string(),
    };
    let (num, mult) = match s.chars().last() {
        Some('s') => (&s[..s.len() - 1], 1u64),
        Some('m') => (&s[..s.len() - 1], 60),
        Some('h') => (&s[..s.len() - 1], 3600),
        Some('d') => (&s[..s.len() - 1], 86_400),
        Some(c) if c.is_ascii_digit() => (s, 1),
        _ => return Err(err()),
    };
    let n: u64 = num.parse().map_err(|_| err())?;
    n.checked_mul(mult).map(Duration::from_secs).ok_or_else(err)
}

// ---------------------------------------------------------------------------
// Invites
// ---------------------------------------------------------------------------

/// The bundle a new peer needs to join (section 1 glossary).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Invite {
    /// Document ID.
    pub doc_id: Hash,
    /// Owner public key (SEC-1).
    pub owner_key: [u8; 32],
    /// Topic salt. Secret.
    pub salt: [u8; 32],
    /// Token bound to the invited node (SEC-2).
    pub token: CapabilityToken,
    /// Peers to dial first.
    pub bootstrap: Vec<EndpointAddr>,
}

impl Invite {
    /// Encode as a hex string for copy and paste.
    pub fn encode(&self) -> Result<String, CliError> {
        let bytes =
            protocol::encode(self, INVITE_LIMIT).map_err(|e| CliError::Config(e.to_string()))?;
        Ok(hex::encode(bytes))
    }

    /// Decode from the string printed by `invite`.
    pub fn decode(s: &str) -> Result<Invite, CliError> {
        let bytes = hex::decode(s.trim()).map_err(|_| CliError::InvalidInvite("not hex".into()))?;
        protocol::decode(&bytes, INVITE_LIMIT).map_err(|e| CliError::InvalidInvite(e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

/// Result of `init`: what was created.
#[derive(Debug, Clone)]
pub struct InitOutcome {
    /// The new document.
    pub doc_id: Hash,
    /// This node.
    pub node_id: EndpointId,
    /// The owner public key.
    pub owner_key: [u8; 32],
}

/// `init <dir>`.
pub fn init(dir: &Path) -> Result<InitOutcome, CliError> {
    if config_path(dir).exists() {
        return Err(CliError::AlreadyInitialized(dir.to_path_buf()));
    }
    std::fs::create_dir_all(dir).map_err(io(dir))?;
    let node_key = load_or_create_node_key(dir)?;
    let owner = generate_signing_key();
    write_secret(
        &owner_key_path(dir),
        format!("{}\n", hex::encode(owner.to_bytes())).as_bytes(),
    )?;
    let doc_id = random_bytes32();
    let salt = random_bytes32();
    let now = unix_now_secs();
    let token = CapabilityToken::issue(
        CapabilityClaims {
            doc_id,
            audience: *node_key.public().as_bytes(),
            can_read: true,
            can_write: true,
            not_before: now.saturating_sub(60),
            expires_at: now.saturating_add(OWNER_TOKEN_TTL.as_secs()),
        },
        &owner,
    );
    let loaded = Loaded {
        doc_id,
        owner_key: owner.verifying_key().to_bytes(),
        salt,
        token,
        bootstrap: Vec::new(),
    };
    save_config(dir, &loaded)?;
    Ok(InitOutcome {
        doc_id,
        node_id: node_key.public(),
        owner_key: loaded.owner_key,
    })
}

/// `whoami <dir>`.
pub fn whoami(dir: &Path) -> Result<EndpointId, CliError> {
    std::fs::create_dir_all(dir).map_err(io(dir))?;
    Ok(load_or_create_node_key(dir)?.public())
}

/// `invite <dir> --audience <id> [--read] [--write] --ttl <d> [--addr a]...`
pub fn invite(
    dir: &Path,
    audience: EndpointId,
    read: bool,
    write: bool,
    ttl: Duration,
    addrs: &[SocketAddr],
) -> Result<Invite, CliError> {
    if !read && !write {
        return Err(CliError::NoPermission);
    }
    let owner = load_owner_key(dir)?.ok_or_else(|| CliError::NotOwner(dir.to_path_buf()))?;
    let loaded = load_config(dir)?;
    let me = load_or_create_node_key(dir)?.public();
    let now = unix_now_secs();
    let token = CapabilityToken::issue(
        CapabilityClaims {
            doc_id: loaded.doc_id,
            audience: *audience.as_bytes(),
            can_read: read,
            can_write: write,
            not_before: now.saturating_sub(60),
            expires_at: now.saturating_add(ttl.as_secs()),
        },
        &owner,
    );
    let mut mine = EndpointAddr::new(me);
    for a in addrs {
        mine = mine.with_ip_addr(*a);
    }
    let mut bootstrap = vec![mine];
    for b in &loaded.bootstrap {
        if b.id != me && b.id != audience {
            bootstrap.push(b.clone());
        }
    }
    Ok(Invite {
        doc_id: loaded.doc_id,
        owner_key: loaded.owner_key,
        salt: loaded.salt,
        token,
        bootstrap,
    })
}

/// `join <dir> <invite>`. Refuses an invite bound to another node (SEC-2)
/// or whose token does not verify against its owner key.
pub fn join(dir: &Path, invite: &Invite) -> Result<Loaded, CliError> {
    std::fs::create_dir_all(dir).map_err(io(dir))?;
    let me = load_or_create_node_key(dir)?.public();
    if invite.token.claims.audience != *me.as_bytes() {
        return Err(CliError::InviteNotForThisNode {
            audience: hex::encode(invite.token.claims.audience),
            me: me.to_string(),
        });
    }
    if invite.token.claims.doc_id != invite.doc_id {
        return Err(CliError::InvalidInvite(
            "token names another document".into(),
        ));
    }
    invite
        .token
        .verify(&invite.owner_key, unix_now_secs())
        .map_err(|e| CliError::InvalidInvite(e.to_string()))?;
    let loaded = Loaded {
        doc_id: invite.doc_id,
        owner_key: invite.owner_key,
        salt: invite.salt,
        token: invite.token.clone(),
        bootstrap: invite
            .bootstrap
            .iter()
            .filter(|b| b.id != me)
            .cloned()
            .collect(),
    };
    save_config(dir, &loaded)?;
    Ok(loaded)
}

/// One line of `status` output per file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeadLine {
    /// The file.
    pub file_name: String,
    /// Head version.
    pub version: String,
    /// Head author (short).
    pub author: String,
    /// Head clock.
    pub hlc: String,
    /// Whether the file on disk holds it.
    pub written: bool,
}

/// `status <dir>`: heads from the store and kept files under `rejected/`.
/// Known providers exist only while `run` is active and are not shown.
pub fn status(dir: &Path) -> Result<(Vec<HeadLine>, Vec<PathBuf>), CliError> {
    let loaded = load_config(dir)?;
    let mut heads = Vec::new();
    let path = store_path(dir);
    if path.exists() {
        let store = match RedbStore::open_read_only(&path) {
            Ok(s) => s,
            Err(crate::storage::StoreError::Locked) => {
                return Err(CliError::StoreBusy(dir.to_path_buf()))
            }
            Err(e) => return Err(e.into()),
        };
        for msg in store.heads(&loaded.doc_id)? {
            let Some(manifest) = store.get_manifest(&loaded.doc_id, msg.manifest_id())? else {
                continue;
            };
            let Some(h) = store.head(&loaded.doc_id, &manifest.file_name)? else {
                continue;
            };
            heads.push(HeadLine {
                file_name: manifest.file_name,
                version: short_hex(&h.version_id),
                author: short_hex(&h.author),
                hlc: format!("{}.{}", h.hlc.wall_ms, h.hlc.counter),
                written: h.written,
            });
        }
    }
    let mut rejected = Vec::new();
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
    walk(&internal_dir(dir).join("rejected"), &mut rejected);
    rejected.sort();
    Ok((heads, rejected))
}

/// Everything `run` starts, so it can be shut down in order.
pub struct Running {
    /// The engine.
    pub engine: SyncEngine,
    endpoint: iroh::Endpoint,
    router: iroh::protocol::Router,
    gossip: GossipNode,
    watcher: FileWatcher,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Running {
    /// This node's address.
    pub fn addr(&self) -> EndpointAddr {
        self.endpoint.addr()
    }

    /// Stop everything.
    pub async fn shutdown(self) {
        self.watcher.stop();
        for t in self.tasks {
            t.abort();
        }
        self.gossip.shutdown().await;
        let _ = self.router.shutdown().await;
        self.endpoint.close().await;
    }
}

/// `run <dir>`: start everything and return the handles. Also publishes any
/// file in the directory that has no head or differs from it, so a
/// directory populated before the first `run` is shared.
pub async fn start(dir: &Path, loopback: bool, port: Option<u16>) -> Result<Running, CliError> {
    let loaded = load_config(dir)?;
    let secret = load_or_create_node_key(dir)?;
    let store: Arc<dyn Store> = Arc::new(RedbStore::open(&store_path(dir))?);

    let mut opts = if loopback {
        EndpointOptions::loopback(secret.clone())
    } else {
        EndpointOptions::production(secret.clone())
    };
    if let Some(p) = port {
        let ip = if loopback {
            std::net::Ipv4Addr::LOCALHOST
        } else {
            std::net::Ipv4Addr::UNSPECIFIED
        };
        opts.bind_addr = Some(std::net::SocketAddrV4::new(ip, p));
    }
    let bound = bind_endpoint(opts).await?;
    for b in &loaded.bootstrap {
        bound.add_addr(b.clone());
    }
    let sync = SyncProtocol::new(Arc::clone(&store));
    sync.add_document(loaded.doc_id, loaded.owner_key);
    let gossip = GossipNode::spawn(bound.endpoint.clone());
    let router = router_builder(bound.endpoint.clone(), sync.clone())
        .accept(GossipNode::alpn(), gossip.handler())
        .spawn();
    let pool = Arc::new(crate::transport::ConnectionPool::new(
        bound.endpoint.clone(),
    ));

    let ctx = DocContext {
        doc_id: loaded.doc_id,
        owner_key: loaded.owner_key,
        token: loaded.token.clone(),
        doc_dir: dir.canonicalize().map_err(io(dir))?,
        secret: secret.clone(),
    };
    let (tx, outbox) = mpsc::unbounded_channel();
    let engine = SyncEngine::new(ctx, store, pool, tx)?;
    let repaired = engine.repair_unwritten_heads().await?;
    if repaired > 0 {
        info!(repaired, "wrote heads left unwritten by a previous run");
    }

    let bootstrap_ids: Vec<EndpointId> = loaded.bootstrap.iter().map(|b| b.id).collect();
    for id in &bootstrap_ids {
        engine.add_peer(*id);
    }
    let topic = derive_topic_id(&loaded.salt, &loaded.doc_id);
    let sub = gossip.subscribe(topic, bootstrap_ids).await?;
    let mut tasks = vec![spawn_gossip_driver(engine.clone(), sub, outbox)];
    tasks.push(spawn_catch_up_task(engine.clone(), CATCH_UP_INTERVAL));

    if engine.ctx().can_write() {
        publish_existing(&engine, dir).await;
    }
    let watcher = FileWatcher::spawn(engine.clone())?;
    info!(node = %bound.endpoint.id(), doc = %short_hex(&loaded.doc_id), "running");
    Ok(Running {
        engine,
        endpoint: bound.endpoint,
        router,
        gossip,
        watcher,
        tasks,
    })
}

/// Publish every regular file under `dir` (outside `.p2p-sync/`) that has no
/// head or differs from it.
async fn publish_existing(engine: &SyncEngine, dir: &Path) {
    fn walk(root: &Path, dir: &Path, out: &mut Vec<String>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                if p.file_name().is_some_and(|n| n == INTERNAL_DIR) {
                    continue;
                }
                walk(root, &p, out);
            } else if let Ok(rel) = p.strip_prefix(root) {
                let name = rel
                    .components()
                    .map(|c| c.as_os_str().to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
                    .join("/");
                out.push(name);
            }
        }
    }
    let mut files = Vec::new();
    walk(dir, dir, &mut files);
    files.sort();
    for name in files {
        match engine.publish_file(&name).await {
            Ok(PublishOutcome::Published(v)) => {
                info!(file = %name, version = %short_hex(&v), "published existing file")
            }
            Ok(_) => {}
            Err(e) => warn!(file = %name, "could not publish existing file: {e}"),
        }
    }
}

/// Run a parsed command to completion, printing to stdout.
pub async fn execute(cli: Cli) -> Result<(), CliError> {
    match cli.command {
        Command::Init { dir } => {
            let out = init(&dir)?;
            println!("initialized {}", dir.display());
            println!("document: {}", hex::encode(out.doc_id));
            println!("owner key: {}", hex::encode(out.owner_key));
            println!("node id: {}", out.node_id);
        }
        Command::Whoami { dir } => {
            println!("{}", whoami(&dir)?);
        }
        Command::Invite {
            dir,
            audience,
            read,
            write,
            ttl,
            addrs,
        } => {
            let audience = parse_node_id(&audience)?;
            let ttl = parse_duration(&ttl)?;
            let inv = invite(&dir, audience, read, write, ttl, &addrs)?;
            println!("{}", inv.encode()?);
        }
        Command::Join { dir, invite } => {
            let inv = Invite::decode(&invite)?;
            let loaded = join(&dir, &inv)?;
            println!("joined document {}", hex::encode(loaded.doc_id));
            println!(
                "read: {}, write: {}, expires: {}",
                loaded.token.claims.can_read,
                loaded.token.claims.can_write,
                loaded.token.claims.expires_at
            );
        }
        Command::Run {
            dir,
            loopback,
            port,
        } => {
            let running = start(&dir, loopback, port).await?;
            let addr = running.addr();
            println!("node id: {}", addr.id);
            for a in addr.ip_addrs() {
                println!("direct address: {a}");
            }
            println!("syncing {} (ctrl-c to stop)", dir.display());
            let _ = tokio::signal::ctrl_c().await;
            println!("stopping");
            running.shutdown().await;
        }
        Command::Status { dir } => {
            let (heads, rejected) = status(&dir)?;
            println!("heads: {}", heads.len());
            for h in heads {
                println!(
                    "  {}  version {}  author {}  hlc {}  {}",
                    h.file_name,
                    h.version,
                    h.author,
                    h.hlc,
                    if h.written { "on disk" } else { "NOT WRITTEN" }
                );
            }
            println!("kept rejected/displaced copies: {}", rejected.len());
            for r in rejected {
                println!("  {}", r.display());
            }
            println!("known providers are tracked only while `run` is active");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_durations() {
        assert_eq!(parse_duration("30s").unwrap(), Duration::from_secs(30));
        assert_eq!(parse_duration("10m").unwrap(), Duration::from_secs(600));
        assert_eq!(parse_duration("2h").unwrap(), Duration::from_secs(7200));
        assert_eq!(parse_duration("7d").unwrap(), Duration::from_secs(604_800));
        assert_eq!(parse_duration("45").unwrap(), Duration::from_secs(45));
        assert!(parse_duration("").is_err());
        assert!(parse_duration("x").is_err());
        assert!(parse_duration("5w").is_err());
        assert!(parse_duration("-3s").is_err());
    }

    #[test]
    fn config_round_trips_through_toml() {
        let owner = generate_signing_key();
        let token = CapabilityToken::issue(
            CapabilityClaims {
                doc_id: [1; 32],
                audience: [2; 32],
                can_read: true,
                can_write: false,
                not_before: 1,
                expires_at: 2,
            },
            &owner,
        );
        let peer = SecretKey::generate().public();
        let loaded = Loaded {
            doc_id: [1; 32],
            owner_key: owner.verifying_key().to_bytes(),
            salt: [3; 32],
            token: token.clone(),
            bootstrap: vec![EndpointAddr::new(peer).with_ip_addr("127.0.0.1:4000".parse().unwrap())],
        };
        let config = Config::from_loaded(&loaded).unwrap();
        let text = toml::to_string_pretty(&config).unwrap();
        let back: Config = toml::from_str(&text).unwrap();
        assert_eq!(back, config);
        let l2 = back.load().unwrap();
        assert_eq!(l2.doc_id, loaded.doc_id);
        assert_eq!(l2.token, token);
        assert_eq!(l2.bootstrap, loaded.bootstrap);
        assert!(text.contains("[[bootstrap]]"));
    }
}
