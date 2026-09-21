//! Stage 2 gate tests: two nodes converge on text files, including a
//! partitioned concurrent edit, offline catch-up and deletion; a local edit
//! made before a remote apply is never overwritten (CRD-1); hostile keys are
//! ignored (CRD-7, SEC-4). Loopback only, no fixed sleeps.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Result};
use iroh_docs::api::protocol::ShareMode;
use iroh_docs::store::Query;
use iroh_docs::DocTicket;
use vaultsync::config::{Config, Layout};
use vaultsync::engine::{Engine, Outcome, Running};
use vaultsync::filedoc::{actor_for, Content, FileDoc};
use vaultsync::node::NetOptions;
use vaultsync::vault::Vault;

const DEADLINE: Duration = Duration::from_secs(30);
const DEBOUNCE: Duration = Duration::from_millis(100);

struct Peer {
    dir: PathBuf,
    vault: Arc<Vault>,
    engine: Arc<Engine>,
    running: Option<Running>,
}

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .with_test_writer()
        .try_init();
}

impl Peer {
    async fn init(dir: &Path) -> Result<Peer> {
        init_tracing();
        let vault = Vault::init(dir, &NetOptions::loopback()).await?;
        Self::start(dir, vault).await
    }

    async fn join(dir: &Path, ticket: &DocTicket) -> Result<Peer> {
        let vault = Vault::join(dir, ticket.clone(), &NetOptions::loopback()).await?;
        Self::start(dir, vault).await
    }

    async fn open(dir: &Path) -> Result<Peer> {
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

    async fn stop_engine(&mut self) -> Result<()> {
        if let Some(running) = self.running.take() {
            running.stop().await?;
        }
        Ok(())
    }

    async fn stop(mut self) -> Result<()> {
        self.stop_engine().await?;
        self.vault.shutdown().await
    }

    fn path(&self, key: &str) -> PathBuf {
        self.dir.join(key)
    }

    fn write(&self, key: &str, text: &str) -> Result<()> {
        write_file(&self.path(key), text.as_bytes())
    }

    fn read(&self, key: &str) -> Option<String> {
        std::fs::read_to_string(self.path(key)).ok()
    }
}

fn write_file(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, bytes)?;
    Ok(())
}

async fn wait_for_file(peer: &Peer, key: &str, expected: Option<&str>) -> Result<()> {
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

/// The visible content of the merged document on this peer, if every
/// snapshot is available locally.
async fn merged_content(peer: &Peer, key: &str) -> Result<Option<Content>> {
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
    Ok(match doc {
        Some(doc) => Some(doc.visible()?.content),
        None => None,
    })
}

async fn wait_for_merged(peer: &Peer, key: &str, expected: &Content) -> Result<()> {
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

#[tokio::test]
async fn text_files_sync_both_ways_including_delete() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let a_dir = tmp.path().join("a");
    // A file that exists before the engine starts is picked up by the scan.
    write_file(&a_dir.join("pre.txt"), b"before start\n")?;
    let a = Peer::init(&a_dir).await?;
    let ticket = a.vault.ticket(ShareMode::Write, &[]).await?;
    let b = Peer::join(&tmp.path().join("b"), &ticket).await?;
    wait_for_file(&b, "pre.txt", Some("before start\n")).await?;

    a.write("notes/a.txt", "hello from a\n")?;
    wait_for_file(&b, "notes/a.txt", Some("hello from a\n")).await?;
    // Materialized files are echo-suppressed: publishing them is a no-op.
    assert_eq!(
        b.engine.publish_path("notes/a.txt").await?,
        Outcome::Unchanged
    );

    b.write("notes/a.txt", "hello from a\nand b\n")?;
    wait_for_file(&a, "notes/a.txt", Some("hello from a\nand b\n")).await?;

    std::fs::remove_file(a.path("notes/a.txt"))?;
    wait_for_file(&b, "notes/a.txt", None).await?;
    wait_for_merged(&b, "notes/a.txt", &Content::Deleted).await?;

    // A file recreated after a delete comes back.
    b.write("notes/a.txt", "third life\n")?;
    wait_for_file(&a, "notes/a.txt", Some("third life\n")).await?;

    // Binary content is not synced before stage 3, and does not disturb the rest.
    write_file(&a.path("img.bin"), &[0u8, 1, 2, 255, 0, 7])?;
    a.write("after.txt", "after the binary\n")?;
    wait_for_file(&b, "after.txt", Some("after the binary\n")).await?;
    assert!(!b.path("img.bin").exists());

    // Removing a directory removes every file inside it.
    a.write("dir/one.txt", "1\n")?;
    a.write("dir/sub/two.txt", "2\n")?;
    wait_for_file(&b, "dir/one.txt", Some("1\n")).await?;
    wait_for_file(&b, "dir/sub/two.txt", Some("2\n")).await?;
    std::fs::remove_dir_all(a.path("dir"))?;
    wait_for_file(&b, "dir/one.txt", None).await?;
    wait_for_file(&b, "dir/sub/two.txt", None).await?;

    // Renaming a file moves it; renaming a directory moves its files.
    a.write("old-name.txt", "renamed content\n")?;
    wait_for_file(&b, "old-name.txt", Some("renamed content\n")).await?;
    std::fs::rename(a.path("old-name.txt"), a.path("new-name.txt"))?;
    wait_for_file(&b, "new-name.txt", Some("renamed content\n")).await?;
    wait_for_file(&b, "old-name.txt", None).await?;
    a.write("moved/inner/x.txt", "x\n")?;
    wait_for_file(&b, "moved/inner/x.txt", Some("x\n")).await?;
    std::fs::rename(a.path("moved"), a.path("elsewhere"))?;
    wait_for_file(&b, "elsewhere/inner/x.txt", Some("x\n")).await?;
    wait_for_file(&b, "moved/inner/x.txt", None).await?;

    assert!(Layout::new(&a.dir).state().is_file());
    a.stop().await?;
    b.stop().await?;
    Ok(())
}

#[tokio::test]
async fn offline_catch_up_and_partitioned_concurrent_edit() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let a = Peer::init(&tmp.path().join("a")).await?;
    let ticket = a.vault.ticket(ShareMode::Write, &[]).await?;
    let b_dir = tmp.path().join("b");
    let b = Peer::join(&b_dir, &ticket).await?;
    a.write("f.txt", "line1\nline2\nline3\n")?;
    wait_for_file(&b, "f.txt", Some("line1\nline2\nline3\n")).await?;
    a.write("only-while-offline.txt", "x\n")?;
    wait_for_file(&b, "only-while-offline.txt", Some("x\n")).await?;
    b.stop().await?;

    // A edits the first line and deletes a file while B is offline.
    a.write("f.txt", "LINE1\nline2\nline3\n")?;
    std::fs::remove_file(a.path("only-while-offline.txt"))?;
    wait_for_merged(&a, "f.txt", &Content::Text("LINE1\nline2\nline3\n".into())).await?;
    wait_for_merged(&a, "only-while-offline.txt", &Content::Deleted).await?;

    // B edits the last line while offline, then comes back.
    write_file(&b_dir.join("f.txt"), b"line1\nline2\nLINE3\n")?;
    let b = Peer::open(&b_dir).await?;
    let merged = "LINE1\nline2\nLINE3\n";
    wait_for_file(&b, "f.txt", Some(merged)).await?;
    wait_for_file(&a, "f.txt", Some(merged)).await?;
    wait_for_file(&b, "only-while-offline.txt", None).await?;

    a.stop().await?;
    b.stop().await?;
    Ok(())
}

#[tokio::test]
async fn local_edit_before_remote_apply_is_not_overwritten() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let a = Peer::init(&tmp.path().join("a")).await?;
    let ticket = a.vault.ticket(ShareMode::Write, &[]).await?;
    let mut b = Peer::join(&tmp.path().join("b"), &ticket).await?;
    a.write("f.txt", "one\ntwo\nthree\n")?;
    wait_for_file(&b, "f.txt", Some("one\ntwo\nthree\n")).await?;

    // B's engine is paused; its docs keep syncing.
    b.stop_engine().await?;
    a.write("f.txt", "ONE\ntwo\nthree\n")?;
    wait_for_merged(&b, "f.txt", &Content::Text("ONE\ntwo\nthree\n".into())).await?;
    assert_eq!(b.read("f.txt").as_deref(), Some("one\ntwo\nthree\n"));

    // An unpublished local edit sits on B's disk when the remote apply runs:
    // it is published first, against the version B's user saw, and the file
    // ends up as the three-way merge.
    b.write("f.txt", "one\ntwo\nTHREE\n")?;
    b.engine.apply_path("f.txt").await?;
    let merged = "ONE\ntwo\nTHREE\n";
    assert_eq!(b.read("f.txt").as_deref(), Some(merged));
    assert_eq!(
        merged_content(&b, "f.txt").await?,
        Some(Content::Text(merged.into()))
    );
    wait_for_file(&a, "f.txt", Some(merged)).await?;

    // The same through the publishing flow (what the watcher triggers).
    a.write("g.txt", "alpha\nbeta\ngamma\n")?;
    wait_for_merged(&b, "g.txt", &Content::Text("alpha\nbeta\ngamma\n".into())).await?;
    b.engine.apply_path("g.txt").await?;
    assert_eq!(b.read("g.txt").as_deref(), Some("alpha\nbeta\ngamma\n"));
    a.write("g.txt", "ALPHA\nbeta\ngamma\n")?;
    wait_for_merged(&b, "g.txt", &Content::Text("ALPHA\nbeta\ngamma\n".into())).await?;
    b.write("g.txt", "alpha\nbeta\nGAMMA\n")?;
    assert_eq!(b.engine.publish_path("g.txt").await?, Outcome::Published);
    assert_eq!(b.read("g.txt").as_deref(), Some("ALPHA\nbeta\nGAMMA\n"));
    wait_for_file(&a, "g.txt", Some("ALPHA\nbeta\nGAMMA\n")).await?;

    a.stop().await?;
    b.stop().await?;
    Ok(())
}

#[tokio::test]
async fn hostile_keys_are_ignored() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let a = Peer::init(&tmp.path().join("a")).await?;
    let ticket = a.vault.ticket(ShareMode::Write, &[]).await?;
    let b = Peer::join(&tmp.path().join("b"), &ticket).await?;
    let b_config_before = std::fs::read_to_string(Layout::new(&b.dir).config())?;

    let mut evil = FileDoc::new(actor_for(&a.vault.author()));
    evil.apply_local(&Content::Text("evil\n".into()))?;
    let snapshot = evil.save();
    for key in [
        "../evil.txt",
        "/abs.txt",
        ".vault/config.json",
        ".vault/state.json",
        "x/../../y.txt",
        "ok\\win.txt",
        "dir/./dot.txt",
    ] {
        a.vault
            .set(key.as_bytes().to_vec(), snapshot.clone())
            .await?;
    }
    a.write("fine.txt", "fine\n")?;
    wait_for_file(&b, "fine.txt", Some("fine\n")).await?;
    // The hostile entries arrived too.
    let deadline = Instant::now() + DEADLINE;
    while b.vault.entries(Query::all()).await?.len() < 8 {
        if Instant::now() > deadline {
            bail!("hostile entries did not arrive");
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    // Give B one more full round: apply everything it knows.
    b.engine.scan().await?;

    for path in [
        tmp.path().join("evil.txt"),
        tmp.path().join("y.txt"),
        b.dir.join("abs.txt"),
        b.dir.join("evil.txt"),
        b.dir.join("y.txt"),
        b.dir.join("ok\\win.txt"),
        b.dir.join("ok").join("win.txt"),
        b.dir.join("dir").join("dot.txt"),
        PathBuf::from("/abs.txt"),
    ] {
        assert!(!path.exists(), "{} must not exist", path.display());
    }
    assert_eq!(
        std::fs::read_to_string(Layout::new(&b.dir).config())?,
        b_config_before
    );
    let config = Config::load(&Layout::new(&b.dir).config())?;
    assert_eq!(config.namespace_id()?, b.vault.id());

    a.stop().await?;
    b.stop().await?;
    Ok(())
}

#[tokio::test]
async fn read_only_member_materializes_but_never_publishes() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let a = Peer::init(&tmp.path().join("a")).await?;
    let ticket = a.vault.ticket(ShareMode::Read, &[]).await?;
    let b = Peer::join(&tmp.path().join("b"), &ticket).await?;
    assert!(!b.vault.can_write());
    a.write("f.txt", "v1\n")?;
    wait_for_file(&b, "f.txt", Some("v1\n")).await?;

    b.write("f.txt", "local edit on a read-only device\n")?;
    assert!(matches!(
        b.engine.publish_path("f.txt").await?,
        Outcome::Skipped(_)
    ));
    a.write("f.txt", "v2\n")?;
    wait_for_file(&b, "f.txt", Some("v2\n")).await?;

    let authors: std::collections::HashSet<_> = b
        .vault
        .entries(Query::all())
        .await?
        .iter()
        .map(|e| e.author())
        .collect();
    assert_eq!(authors.len(), 1);
    assert!(authors.contains(&a.vault.author()));

    a.stop().await?;
    b.stop().await?;
    Ok(())
}
