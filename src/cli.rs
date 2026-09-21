//! Command line interface: `init`, `whoami`, `invite`, `join`, `run`, `status`.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use iroh::EndpointAddr;
use iroh_docs::api::protocol::ShareMode;
use iroh_docs::engine::LiveEvent;
use iroh_docs::store::Query;
use iroh_docs::DocTicket;
use n0_future::StreamExt;

use crate::config::{self, Config, Layout};
use crate::node::NetOptions;
use crate::vault::{restrict_capability, Vault};

#[derive(Parser, Debug)]
#[command(
    name = "vaultsync",
    version,
    about = "Folder sync on iroh, iroh-docs and Automerge"
)]
pub struct Cli {
    /// Loopback-only networking: no relays, no address lookup. Peers are
    /// reached through the addresses in tickets. For tests and local demos.
    #[arg(long, global = true)]
    pub loopback: bool,
    /// Bind the endpoint to this UDP address instead of a random port.
    #[arg(long, global = true)]
    pub bind: Option<SocketAddr>,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Create a new vault in DIR.
    Init { dir: PathBuf },
    /// Print this device's endpoint id (creates the key on first use).
    Whoami { dir: PathBuf },
    /// Print an invite for a new device.
    Invite {
        dir: PathBuf,
        /// Invite with write access (requires a write capability here).
        #[arg(long, conflicts_with = "read")]
        write: bool,
        /// Invite with read-only access.
        #[arg(long)]
        read: bool,
        /// Extra direct addresses of this node to include, for peers that
        /// cannot use address lookup (LAN, loopback).
        #[arg(long)]
        addr: Vec<SocketAddr>,
    },
    /// Join a vault from an invite and start syncing.
    Join { dir: PathBuf, invite: String },
    /// Start the node and sync until Ctrl-C.
    Run { dir: PathBuf },
    /// Show the vault id, this device's id, known peers and entry count.
    Status { dir: PathBuf },
}

impl Cli {
    fn net(&self) -> NetOptions {
        let mut net = if self.loopback {
            NetOptions::loopback()
        } else {
            NetOptions::production()
        };
        net.bind = self.bind;
        net
    }
}

pub async fn execute(cli: Cli) -> Result<()> {
    let net = cli.net();
    match cli.command {
        Command::Init { dir } => {
            let vault = Vault::init(&dir, &net).await?;
            println!("vault {}", vault.id());
            println!("device {}", vault.endpoint_id());
            println!("state in {}", vault.layout().dot().display());
            vault.shutdown().await
        }
        Command::Whoami { dir } => {
            let layout = Layout::new(&dir);
            std::fs::create_dir_all(layout.dot())?;
            let key = config::load_or_create_secret_key(&layout.endpoint_key())?;
            println!("{}", key.public());
            Ok(())
        }
        Command::Invite {
            dir,
            write,
            read,
            addr,
        } => {
            if !write && !read {
                bail!("choose --write or --read");
            }
            let mode = if write {
                ShareMode::Write
            } else {
                ShareMode::Read
            };
            let ticket = make_invite(&Layout::new(&dir), mode, &addr)?;
            println!("{ticket}");
            Ok(())
        }
        Command::Join { dir, invite } => {
            let ticket: DocTicket = invite
                .trim()
                .parse()
                .context("the invite is not a valid docs ticket")?;
            let vault = Vault::join(&dir, ticket, &net).await?;
            run_until_ctrl_c(vault).await
        }
        Command::Run { dir } => {
            let vault = Vault::open(&dir, &net).await?;
            run_until_ctrl_c(vault).await
        }
        Command::Status { dir } => status(&dir).await,
    }
}

/// Build an invite from the files under `.vault/` without opening the stores,
/// so it works while `run` holds them.
pub fn make_invite(layout: &Layout, mode: ShareMode, extra: &[SocketAddr]) -> Result<DocTicket> {
    if !layout.is_initialized() {
        bail!("{} is not a vault", layout.root().display());
    }
    let capability = config::load_capability(&layout.vault_key())?;
    let capability = restrict_capability(capability, mode)?;
    let key = config::load_secret_key(&layout.endpoint_key())?;
    let mut addr = config::load_own_addr(&layout.own_addr())?
        .filter(|a| a.id == key.public())
        .unwrap_or_else(|| EndpointAddr::new(key.public()));
    for a in extra {
        addr = addr.with_ip_addr(*a);
    }
    Ok(DocTicket::new(capability, vec![addr]))
}

async fn run_until_ctrl_c(vault: Vault) -> Result<()> {
    vault.save_own_addr()?;
    println!("vault {}", vault.id());
    println!("device {}", vault.endpoint_id());
    for addr in vault.node().addr().addrs {
        println!("address {addr:?}");
    }
    println!(
        "peers known: {}; {}",
        vault.peers()?.len(),
        if vault.can_write() {
            "read-write"
        } else {
            "read-only"
        }
    );
    vault.start_sync().await?;
    let mut events = vault.subscribe().await?;
    println!("syncing; press Ctrl-C to stop");
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            event = events.next() => match event {
                Some(Ok(event)) => handle_event(&vault, event).await,
                Some(Err(err)) => tracing::warn!("event stream error: {err:#}"),
                None => {
                    tracing::warn!("event stream ended");
                    tokio::signal::ctrl_c().await?;
                    break;
                }
            },
        }
    }
    println!("shutting down");
    vault.shutdown().await
}

async fn handle_event(vault: &Vault, event: LiveEvent) {
    match event {
        LiveEvent::NeighborUp(id) => {
            tracing::info!("peer up {}", id.fmt_short());
            if let Err(err) = vault.remember_peer(id).await {
                tracing::warn!("remembering peer {}: {err:#}", id.fmt_short());
            }
        }
        LiveEvent::NeighborDown(id) => tracing::info!("peer down {}", id.fmt_short()),
        LiveEvent::InsertRemote { from, entry, .. } => tracing::info!(
            "entry {} from {} ({} bytes)",
            String::from_utf8_lossy(entry.key()),
            from.fmt_short(),
            entry.content_len()
        ),
        LiveEvent::ContentReady { hash } => {
            tracing::debug!("content ready {}", hash.fmt_short())
        }
        LiveEvent::SyncFinished(event) => tracing::debug!(
            "sync with {} finished: {:?}",
            event.peer.fmt_short(),
            event.result
        ),
        LiveEvent::InsertLocal { .. } | LiveEvent::PendingContentReady => {}
    }
}

async fn status(dir: &Path) -> Result<()> {
    let layout = Layout::new(dir);
    if !layout.is_initialized() {
        bail!("{} is not a vault", dir.display());
    }
    let config = Config::load(&layout.config())?;
    let key = config::load_secret_key(&layout.endpoint_key())?;
    println!("vault {}", config.vault_id);
    println!("device {}", key.public());
    println!(
        "capability {}",
        if config.write {
            "read-write"
        } else {
            "read-only"
        }
    );
    let peers = config::load_peers(&layout.peers())?;
    println!("peers known: {}", peers.len());
    for peer in &peers {
        println!("  {} {:?}", peer.id.fmt_short(), peer.addrs);
    }
    // The stores are exclusive; while `run` is active this fails.
    match Vault::open(dir, &NetOptions::loopback()).await {
        Ok(vault) => {
            let entries = vault.entries(Query::all()).await?;
            let mut ready = 0usize;
            for entry in &entries {
                if vault.has_content(entry.content_hash()).await? {
                    ready += 1;
                }
            }
            println!("entries: {} ({ready} with content present)", entries.len());
            vault.shutdown().await?;
        }
        Err(err) => {
            println!("entries: unavailable, the stores are in use (is `run` active?): {err:#}");
        }
    }
    Ok(())
}
