//! Shared helpers for the engine-level integration tests: a peer (vault plus
//! running engine) on loopback, file helpers and deadline-based waits.
//! Each test binary uses a subset, hence the allow.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Result};
use iroh_docs::store::Query;
use iroh_docs::DocTicket;
use vaultsync::engine::{Engine, Running};
use vaultsync::filedoc::{actor_for, Content, FileDoc, Visible};
use vaultsync::node::NetOptions;
use vaultsync::vault::Vault;

pub const DEADLINE: Duration = Duration::from_secs(60);
pub const DEBOUNCE: Duration = Duration::from_millis(100);

pub struct Peer {
    pub dir: PathBuf,
    pub vault: Arc<Vault>,
    pub engine: Arc<Engine>,
    pub running: Option<Running>,
}

pub fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .with_test_writer()
        .try_init();
}

impl Peer {
    pub async fn init(dir: &Path) -> Result<Peer> {
        init_tracing();
        let vault = Vault::init(dir, &NetOptions::loopback()).await?;
        Self::start(dir, vault).await
    }

    pub async fn join(dir: &Path, ticket: &DocTicket) -> Result<Peer> {
        init_tracing();
        let vault = Vault::join(dir, ticket.clone(), &NetOptions::loopback()).await?;
        Self::start(dir, vault).await
    }

    pub async fn open(dir: &Path) -> Result<Peer> {
        let vault = Vault::open(dir, &NetOptions::loopback()).await?;
        Self::start(dir, vault).await
    }

    async fn start(dir: &Path, vault: Vault) -> Result<Peer> {
        vault.start_sync().await?;
        let vault = Arc::new(vault);
        let engine = Arc::new(Engine::new(vault.clone())?);
        let running = engine.clone().start(DEBOUNCE).await?;
        Ok(Peer {
            dir: dir.to_path_buf(),
            vault,
            engine,
            running: Some(running),
        })
    }

    pub async fn stop_engine(&mut self) -> Result<()> {
        if let Some(running) = self.running.take() {
            running.stop().await?;
        }
        Ok(())
    }

    pub async fn stop(mut self) -> Result<()> {
        self.stop_engine().await?;
        self.vault.shutdown().await
    }

    pub fn path(&self, key: &str) -> PathBuf {
        self.dir.join(key)
    }

    pub fn write(&self, key: &str, text: &str) -> Result<()> {
        write_file(&self.path(key), text.as_bytes())
    }

    pub fn read(&self, key: &str) -> Option<String> {
        std::fs::read_to_string(self.path(key)).ok()
    }

    pub fn read_bytes(&self, key: &str) -> Option<Vec<u8>> {
        std::fs::read(self.path(key)).ok()
    }

    pub fn actor_bytes(&self) -> Vec<u8> {
        actor_for(&self.vault.author()).to_bytes().to_vec()
    }
}

pub fn write_file(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, bytes)?;
    Ok(())
}

pub fn random_bytes(size: usize, mut seed: u64) -> Vec<u8> {
    let mut data = Vec::with_capacity(size + 8);
    while data.len() < size {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        data.extend_from_slice(&seed.to_le_bytes());
    }
    data.truncate(size);
    data
}

pub fn hash_hex(bytes: &[u8]) -> String {
    data_encoding::HEXLOWER.encode(blake3::hash(bytes).as_bytes())
}

/// Poll `check` until it returns true or the deadline passes.
pub async fn wait_until<F, Fut>(what: &str, mut check: F) -> Result<()>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<bool>>,
{
    let deadline = Instant::now() + DEADLINE;
    loop {
        if check().await? {
            return Ok(());
        }
        if Instant::now() > deadline {
            bail!("timeout waiting for {what}");
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

pub async fn wait_for_file(peer: &Peer, key: &str, expected: Option<&str>) -> Result<()> {
    let deadline = Instant::now() + DEADLINE;
    loop {
        if peer.read(key).as_deref() == expected {
            return Ok(());
        }
        if Instant::now() > deadline {
            bail!(
                "timeout waiting for {key} = {expected:?} on {}, found {:?}",
                peer.dir.display(),
                peer.read(key)
            );
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// Wait until the file holds exactly `expected` (compared by hash), or is
/// absent when `expected` is `None`.
pub async fn wait_for_bytes(peer: &Peer, key: &str, expected: Option<&[u8]>) -> Result<()> {
    let want = expected.map(hash_hex);
    let deadline = Instant::now() + DEADLINE;
    loop {
        let have = peer.read_bytes(key).map(|b| hash_hex(&b));
        if have == want {
            return Ok(());
        }
        if Instant::now() > deadline {
            bail!(
                "timeout waiting for the bytes of {key} on {} (have {have:?}, want {want:?})",
                peer.dir.display()
            );
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// The merged document on this peer, if every snapshot is available locally.
pub async fn merged_doc(peer: &Peer, key: &str) -> Result<Option<FileDoc>> {
    let actor = actor_for(&peer.vault.author());
    let mut doc: Option<FileDoc> = None;
    for entry in peer.vault.entries(Query::all().key_exact(key)).await? {
        if !peer.vault.has_content(entry.content_hash()).await? {
            return Ok(None);
        }
        let bytes = peer.vault.content(entry.content_hash()).await?;
        match &mut doc {
            None => doc = Some(FileDoc::load(&bytes, actor.clone())?),
            Some(doc) => doc.merge_bytes(&bytes)?,
        }
    }
    Ok(doc)
}

pub async fn merged_visible(peer: &Peer, key: &str) -> Result<Option<Visible>> {
    Ok(match merged_doc(peer, key).await? {
        Some(doc) => Some(doc.visible()?),
        None => None,
    })
}

pub async fn merged_content(peer: &Peer, key: &str) -> Result<Option<Content>> {
    Ok(merged_visible(peer, key).await?.map(|v| v.content))
}

pub async fn wait_for_merged(peer: &Peer, key: &str, expected: &Content) -> Result<()> {
    let deadline = Instant::now() + DEADLINE;
    loop {
        if merged_content(peer, key).await?.as_ref() == Some(expected) {
            return Ok(());
        }
        if Instant::now() > deadline {
            bail!("timeout waiting for the merged document of {key}");
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}
