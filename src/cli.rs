//! Command line interface: `init`, `whoami`, `invite`, `join`, `run`, `status`.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use iroh::{EndpointAddr, EndpointId};
use iroh_docs::api::protocol::ShareMode;
use iroh_docs::store::Query;

use crate::config::{self, Config, Layout};
use crate::engine::Engine;
use crate::invite::{self, Invite};
use crate::node::NetOptions;
use crate::vault::{self, Vault};
use crate::watcher::DEFAULT_DEBOUNCE;

#[derive(Parser, Debug)]
#[command(
    name = "echosync",
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
    /// Print an invite for a new device: a docs ticket, a Biscuit token and
    /// the root public key. Treat it like a password.
    Invite {
        dir: PathBuf,
        /// Invite with write access (requires a write capability here).
        #[arg(long, conflicts_with = "read")]
        write: bool,
        /// Invite with read-only access.
        #[arg(long)]
        read: bool,
        /// Endpoint id of the invited device (its `whoami`). Without it the
        /// invite is a bearer token that admits whoever holds it until it
        /// expires, and that the holder may delegate further.
        #[arg(long)]
        audience: Option<String>,
        /// Time to live of the token: seconds, or with a suffix s, m, h, d, w.
        #[arg(long, default_value = "7d")]
        ttl: String,
        /// Extra direct addresses of this node to include, for peers that
        /// cannot use address lookup (LAN, loopback).
        #[arg(long)]
        addr: Vec<SocketAddr>,
    },
    /// Join a vault from an invite and start syncing.
    Join { dir: PathBuf, invite: String },
    /// Start the node and sync until Ctrl-C.
    Run { dir: PathBuf },
    /// Show the vault id, this device's id, known peers, conflicts and entry count.
    Status { dir: PathBuf },
    /// List conflicted paths, or export the losing versions of one path to
    /// `.vault/conflicts/` (the node must not be running).
    Conflict {
        dir: PathBuf,
        #[command(subcommand)]
        action: ConflictAction,
    },
}

#[derive(Subcommand, Debug)]
pub enum ConflictAction {
    /// List every path with losing versions.
    List,
    /// Export the losing versions of PATH to `.vault/conflicts/`.
    Export { path: String },
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
            audience,
            ttl,
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
            let audience =
                match audience {
                    Some(text) => Some(text.trim().parse::<EndpointId>().map_err(|err| {
                        anyhow::anyhow!("--audience is not an endpoint id: {err}")
                    })?),
                    None => None,
                };
            let ttl = invite::parse_duration(&ttl)?;
            let invite = make_invite(&Layout::new(&dir), mode, audience, ttl, &addr)?;
            if invite.delegatable {
                eprintln!(
                    "note: without --audience this invite admits whoever holds it until it expires"
                );
            }
            println!("{invite}");
            Ok(())
        }
        Command::Join { dir, invite } => {
            let invite: Invite = invite.parse().context("parsing the invite")?;
            let vault = Vault::join(&dir, &invite, &net).await?;
            run_until_ctrl_c(vault).await
        }
        Command::Run { dir } => {
            let vault = Vault::open(&dir, &net).await?;
            run_until_ctrl_c(vault).await
        }
        Command::Status { dir } => status(&dir).await,
        Command::Conflict { dir, action } => conflict(&dir, action, &net).await,
    }
}

async fn conflict(dir: &Path, action: ConflictAction, net: &NetOptions) -> Result<()> {
    let layout = Layout::new(dir);
    if !layout.is_initialized() {
        bail!("{} is not a vault", dir.display());
    }
    match action {
        ConflictAction::List => {
            let index = config::load_conflicts(&layout.conflicts_index())?;
            print_conflicts(&index);
            Ok(())
        }
        ConflictAction::Export { path } => {
            let vault = Arc::new(Vault::open(dir, net).await?);
            let engine = Engine::new(vault.clone())?;
            let result = engine.export_conflicts(&path).await;
            vault.shutdown().await?;
            let copies = result?;
            if copies.is_empty() {
                println!("{path}: no losing versions");
            }
            for copy in copies {
                println!("{}", copy.display());
            }
            Ok(())
        }
    }
}

fn print_conflicts(index: &config::ConflictIndex) {
    println!("conflicts: {}", index.len());
    for (key, losers) in index {
        for loser in losers {
            println!(
                "  {key}: losing {} version {} by {}",
                loser.kind, loser.id, loser.actor
            );
        }
    }
}

/// Build an invite from the files under `.vault/` without opening the stores,
/// so it works while `run` holds them. The node's address comes from the
/// file `run` writes, plus `extra`.
pub fn make_invite(
    layout: &Layout,
    mode: ShareMode,
    audience: Option<EndpointId>,
    ttl: Duration,
    extra: &[SocketAddr],
) -> Result<Invite> {
    if !layout.is_initialized() {
        bail!("{} is not a vault", layout.root().display());
    }
    let config = Config::load(&layout.config())?;
    let key = config::load_secret_key(&layout.endpoint_key())?;
    let mut addr = config::load_own_addr(&layout.own_addr())?
        .filter(|a| a.id == key.public())
        .unwrap_or_else(|| EndpointAddr::new(key.public()));
    for a in extra {
        addr = addr.with_ip_addr(*a);
    }
    vault::make_invite(layout, &config, addr, mode, audience, ttl)
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
    let vault = Arc::new(vault);
    let engine = Arc::new(Engine::new(vault.clone())?);
    let running = engine.start(DEFAULT_DEBOUNCE).await?;
    println!(
        "syncing {}; press Ctrl-C to stop",
        vault.layout().root().display()
    );
    tokio::signal::ctrl_c().await?;
    println!("shutting down");
    running.stop().await?;
    vault.shutdown().await
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
    print_conflicts(&config::load_conflicts(&layout.conflicts_index())?);
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
