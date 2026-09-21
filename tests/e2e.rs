//! Stage 5: three-node end-to-end scenarios for every success criterion in
//! SPEC.md section 1, a kill during materialization, and resource limits.

mod common;

use std::collections::HashMap;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use common::{
    merged_visible, random_bytes, wait_for_bytes, wait_for_file, wait_until, write_file, Peer,
    DEADLINE, DEBOUNCE,
};
use iroh::endpoint::ConnectionError;
use iroh_blobs::api::blobs::BlobStatus;
use iroh_blobs::Hash;
use iroh_docs::api::protocol::ShareMode;
use vaultsync::chunker::MIN_CHUNK;
use vaultsync::config::{self, Config, Layout};
use vaultsync::engine::{Engine, Limits, Outcome};
use vaultsync::filedoc::{Content, VersionKind};
use vaultsync::node::{NetOptions, Node};
use vaultsync::vault::Vault;

async fn chunk_blobs(peer: &Peer) -> Result<HashMap<Hash, u64>> {
    let store = peer.vault.node().blobs();
    let mut inventory = HashMap::new();
    for hash in store.blobs().list().hashes().await? {
        if let BlobStatus::Complete { size } = store.blobs().status(hash).await? {
            if size >= MIN_CHUNK as u64 {
                inventory.insert(hash, size);
            }
        }
    }
    Ok(inventory)
}

fn conflicts_of(dir: &Path) -> Result<config::ConflictIndex> {
    config::load_conflicts(&Layout::new(dir).conflicts_index())
}

/// Criteria 1 and 2: a 10 MiB file reaches B and C byte-identical, and a
/// one-byte edit costs each of them at most 3 chunks.
#[tokio::test]
async fn three_nodes_share_a_ten_mib_file_and_a_one_byte_edit() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let a = Peer::init(&tmp.path().join("a")).await?;
    let invite = a.write_invite()?;
    let b = Peer::join(&tmp.path().join("b"), &invite).await?;
    let c = Peer::join(&tmp.path().join("c"), &invite).await?;

    let data = random_bytes(10 << 20, 0xe2e);
    let started = Instant::now();
    write_file(&a.path("big.bin"), &data)?;
    wait_for_bytes(&b, "big.bin", Some(&data)).await?;
    wait_for_bytes(&c, "big.bin", Some(&data)).await?;
    println!("10 MiB reached B and C after {:?}", started.elapsed());
    let before_b = chunk_blobs(&b).await?;
    let before_c = chunk_blobs(&c).await?;
    assert!(before_b.len() >= 40 && before_c.len() >= 40);

    let mut edited = data.clone();
    edited[data.len() / 2] ^= 0x5a;
    let started = Instant::now();
    write_file(&a.path("big.bin"), &edited)?;
    wait_for_bytes(&b, "big.bin", Some(&edited)).await?;
    wait_for_bytes(&c, "big.bin", Some(&edited)).await?;
    println!(
        "one-byte edit reached B and C after {:?}",
        started.elapsed()
    );
    for (peer, before) in [(&b, before_b), (&c, before_c)] {
        let after = chunk_blobs(peer).await?;
        let new = after.keys().filter(|h| !before.contains_key(*h)).count();
        assert!(
            (1..=3).contains(&new),
            "{}: {new} new chunk-sized blobs",
            peer.dir.display()
        );
    }

    a.stop().await?;
    b.stop().await?;
    c.stop().await?;
    Ok(())
}

/// Criterion 4: partitioned concurrent edits. Text merges without loss on
/// all three; a binary file has one winner everywhere, a copy of the loser
/// for its author, a flag on every peer until the next write.
#[tokio::test]
async fn three_nodes_partitioned_edits_text_and_binary() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let a = Peer::init(&tmp.path().join("a")).await?;
    let invite = a.write_invite()?;
    let b_dir = tmp.path().join("b");
    let b = Peer::join(&b_dir, &invite).await?;
    let c = Peer::join(&tmp.path().join("c"), &invite).await?;

    a.write("notes.txt", "alpha\nbeta\ngamma\n")?;
    let v0 = random_bytes(300 << 10, 11);
    write_file(&a.path("bin.dat"), &v0)?;
    for peer in [&b, &c] {
        wait_for_file(peer, "notes.txt", Some("alpha\nbeta\ngamma\n")).await?;
        wait_for_bytes(peer, "bin.dat", Some(&v0)).await?;
    }

    // Partition B.
    b.stop().await?;
    a.write("notes.txt", "ALPHA\nbeta\ngamma\n")?;
    let v1 = random_bytes(300 << 10, 12);
    write_file(&a.path("bin.dat"), &v1)?;
    wait_for_file(&c, "notes.txt", Some("ALPHA\nbeta\ngamma\n")).await?;
    wait_for_bytes(&c, "bin.dat", Some(&v1)).await?;
    write_file(&b_dir.join("notes.txt"), b"alpha\nbeta\nGAMMA\n")?;
    let v2 = random_bytes(300 << 10, 13);
    write_file(&b_dir.join("bin.dat"), &v2)?;
    let b = Peer::open(&b_dir).await?;

    // Text: both edits survive everywhere.
    for peer in [&a, &b, &c] {
        wait_for_file(peer, "notes.txt", Some("ALPHA\nbeta\nGAMMA\n")).await?;
    }
    // Binary: one winner everywhere, decided by actor id on the tie.
    let a_wins = a.actor_bytes() < b.actor_bytes();
    let (winner, loser, loser_peer) = if a_wins {
        (&v1, &v2, &b)
    } else {
        (&v2, &v1, &a)
    };
    for peer in [&a, &b, &c] {
        wait_for_bytes(peer, "bin.dat", Some(winner)).await?;
        wait_until(&format!("flag on {}", peer.dir.display()), || async {
            Ok(conflicts_of(&peer.dir)?.contains_key("bin.dat"))
        })
        .await?;
        let visible = merged_visible(peer, "bin.dat").await?.expect("merged");
        assert_eq!(visible.losers.len(), 1);
    }
    let visible = merged_visible(&c, "bin.dat").await?.expect("merged");
    let VersionKind::Blob { manifest, .. } = &visible.losers[0].kind else {
        bail!("loser is not a blob");
    };
    let id = data_encoding::HEXLOWER.encode(&manifest[..4]);
    let copy = Layout::new(&loser_peer.dir)
        .conflicts()
        .join(format!("bin.dat.{id}"));
    wait_until("loser copy", || async {
        Ok(std::fs::read(&copy).ok().as_deref() == Some(loser.as_slice()))
    })
    .await?;
    // C, a bystander, can retrieve the loser on demand.
    let exported = c.engine.export_conflicts("bin.dat").await?;
    assert_eq!(exported.len(), 1);
    assert_eq!(std::fs::read(&exported[0])?, *loser);

    // The next write, from C, resolves it everywhere.
    let v3 = random_bytes(100 << 10, 14);
    write_file(&c.path("bin.dat"), &v3)?;
    for peer in [&a, &b, &c] {
        wait_for_bytes(peer, "bin.dat", Some(&v3)).await?;
        wait_until(
            &format!("flag cleared on {}", peer.dir.display()),
            || async { Ok(!conflicts_of(&peer.dir)?.contains_key("bin.dat")) },
        )
        .await?;
    }

    a.stop().await?;
    b.stop().await?;
    c.stop().await?;
    Ok(())
}

/// Criterion 5: an offline peer catches up, deletions included.
#[tokio::test]
async fn offline_peer_catches_up_and_deletions_propagate() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let a = Peer::init(&tmp.path().join("a")).await?;
    let invite = a.write_invite()?;
    let b = Peer::join(&tmp.path().join("b"), &invite).await?;
    let c_dir = tmp.path().join("c");
    let c = Peer::join(&c_dir, &invite).await?;
    a.write("keep.txt", "keep\n")?;
    a.write("gone.txt", "gone\n")?;
    write_file(&a.path("blob.bin"), &random_bytes(64 << 10, 5))?;
    for peer in [&b, &c] {
        wait_for_file(peer, "keep.txt", Some("keep\n")).await?;
        wait_for_file(peer, "gone.txt", Some("gone\n")).await?;
        wait_for_bytes(peer, "blob.bin", Some(&random_bytes(64 << 10, 5))).await?;
    }
    c.stop().await?;

    // While C is away: A deletes, B edits and adds, A replaces the blob.
    std::fs::remove_file(a.path("gone.txt"))?;
    b.write("keep.txt", "keep\nand more\n")?;
    b.write("new/from-b.txt", "new\n")?;
    let blob2 = random_bytes(64 << 10, 6);
    write_file(&a.path("blob.bin"), &blob2)?;
    wait_for_file(&b, "gone.txt", None).await?;
    wait_for_file(&a, "keep.txt", Some("keep\nand more\n")).await?;
    wait_for_file(&a, "new/from-b.txt", Some("new\n")).await?;
    wait_for_bytes(&b, "blob.bin", Some(&blob2)).await?;

    let started = Instant::now();
    let c = Peer::open(&c_dir).await?;
    wait_for_file(&c, "gone.txt", None).await?;
    wait_for_file(&c, "keep.txt", Some("keep\nand more\n")).await?;
    wait_for_file(&c, "new/from-b.txt", Some("new\n")).await?;
    wait_for_bytes(&c, "blob.bin", Some(&blob2)).await?;
    println!("C caught up after {:?}", started.elapsed());
    // And C's own change while it was away is not lost either.
    a.stop().await?;
    b.stop().await?;
    c.stop().await?;
    Ok(())
}

/// Criterion 3 with three members running: a fourth node without a valid
/// token gets nowhere on any protocol.
#[tokio::test]
async fn fourth_node_without_a_valid_token_is_refused_by_everyone() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let a = Peer::init(&tmp.path().join("a")).await?;
    let invite = a.write_invite()?;
    let b = Peer::join(&tmp.path().join("b"), &invite).await?;
    let c = Peer::join(&tmp.path().join("c"), &invite).await?;
    a.write("f.txt", "members only\n")?;
    wait_for_file(&b, "f.txt", Some("members only\n")).await?;
    wait_for_file(&c, "f.txt", Some("members only\n")).await?;

    let d_layout = Layout::new(tmp.path().join("d"));
    d_layout.create_dirs()?;
    let d_key = config::load_or_create_secret_key(&d_layout.endpoint_key())?;
    let d = Node::spawn(&d_layout, d_key, &NetOptions::loopback(), None).await?;
    for peer in [&a, &b, &c] {
        for alpn in [iroh_docs::ALPN, iroh_blobs::ALPN, iroh_gossip::ALPN] {
            let conn = d.endpoint().connect(peer.vault.node().addr(), alpn).await?;
            match tokio::time::timeout(Duration::from_secs(10), conn.closed()).await? {
                ConnectionError::ApplicationClosed(close) => {
                    assert_eq!(close.error_code.into_inner(), 403)
                }
                other => bail!("unexpected close: {other}"),
            }
        }
    }
    d.shutdown().await?;
    // An expired invite is refused by `join` itself.
    let expired = a
        .vault
        .invite(ShareMode::Read, None, Duration::from_secs(1))?;
    tokio::time::sleep(Duration::from_millis(1200)).await;
    assert!(
        Vault::join(&tmp.path().join("e"), &expired, &NetOptions::loopback())
            .await
            .is_err()
    );

    a.stop().await?;
    b.stop().await?;
    c.stop().await?;
    Ok(())
}

fn spawn_binary(args: &[&str]) -> Result<Child> {
    Command::new(env!("CARGO_BIN_EXE_vaultsync"))
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("spawning vaultsync")
}

/// A kill during materialization leaves a consistent folder after restart:
/// the file is either absent or complete, `.vault/tmp` is empty, and the
/// state file matches the disk.
#[tokio::test]
async fn kill_during_materialization_leaves_a_consistent_folder() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let a = Peer::init(&tmp.path().join("a")).await?;
    let invite = a.write_invite()?.to_string();
    let data = random_bytes(10 << 20, 0xdead);
    write_file(&a.path("big.bin"), &data)?;
    a.write("small.txt", "small\n")?;
    wait_until("A published", || async {
        Ok(matches!(
            merged_visible(&a, "big.bin").await?.map(|v| v.content),
            Some(Content::Blob { .. })
        ))
    })
    .await?;

    // B is a real process; kill it while it is materializing.
    let b_dir = tmp.path().join("b");
    let b_dir_str = b_dir.to_string_lossy().to_string();
    let mut child = spawn_binary(&["--loopback", "join", &b_dir_str, &invite])?;
    let tmp_dir = Layout::new(&b_dir).tmp();
    let deadline = Instant::now() + DEADLINE;
    loop {
        let materializing = std::fs::read_dir(&tmp_dir)
            .map(|d| d.flatten().next().is_some())
            .unwrap_or(false);
        if materializing || b_dir.join("big.bin").exists() {
            break;
        }
        if Instant::now() > deadline {
            bail!("B never started materializing");
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    child.kill()?;
    child.wait()?;
    let partial = b_dir.join("big.bin");
    if partial.exists() {
        assert_eq!(
            std::fs::read(&partial)?.len(),
            data.len(),
            "never a partial file"
        );
    }

    // Restart B in-process and check the folder converges and is clean.
    let b = Peer::open(&b_dir).await?;
    wait_for_bytes(&b, "big.bin", Some(&data)).await?;
    wait_for_file(&b, "small.txt", Some("small\n")).await?;
    let leftovers = std::fs::read_dir(&tmp_dir)?.flatten().count();
    assert_eq!(leftovers, 0, "tmp files left behind");
    assert_eq!(b.engine.publish_path("big.bin").await?, Outcome::Unchanged);
    assert_eq!(
        b.engine.publish_path("small.txt").await?,
        Outcome::Unchanged
    );
    // No spurious version was created by the restart.
    let entries = b
        .vault
        .entries(iroh_docs::store::Query::all().key_exact("big.bin"))
        .await?;
    assert!(entries.len() <= 2, "{} entries for big.bin", entries.len());

    a.stop().await?;
    b.stop().await?;
    Ok(())
}

/// Resource limits: oversized files and paths beyond the entry cap are not
/// published; remote content still materializes.
#[tokio::test]
async fn limits_skip_oversized_files_and_cap_new_paths() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let a = Peer::init(&tmp.path().join("a")).await?;
    let invite = a.write_invite()?;
    // B runs with tight limits, set through its config file.
    let b_dir = tmp.path().join("b");
    let b_vault = Vault::join(&b_dir, &invite, &NetOptions::loopback()).await?;
    let mut cfg = Config::load(&Layout::new(&b_dir).config())?;
    cfg.max_file_bytes = Some(4096);
    cfg.max_entries = Some(2);
    cfg.save(&Layout::new(&b_dir).config())?;
    assert_eq!(Limits::from_config(&cfg).max_entries, 2);
    b_vault.start_sync().await?;
    let b_vault = Arc::new(b_vault);
    let engine = Arc::new(Engine::with_limits(
        b_vault.clone(),
        Limits::from_config(&cfg),
    )?);
    let running = engine.clone().start(DEBOUNCE).await?;
    let b = Peer {
        dir: b_dir.clone(),
        vault: b_vault,
        engine,
        running: Some(running),
    };

    // Too large for B's limit: never published, so A never sees it.
    write_file(&b.path("huge.bin"), &random_bytes(8192, 3))?;
    assert!(matches!(
        b.engine.publish_path("huge.bin").await?,
        Outcome::Skipped(_)
    ));
    // Two new paths fit, the third does not.
    b.write("one.txt", "1\n")?;
    b.write("two.txt", "2\n")?;
    wait_for_file(&a, "one.txt", Some("1\n")).await?;
    wait_for_file(&a, "two.txt", Some("2\n")).await?;
    b.write("three.txt", "3\n")?;
    assert!(matches!(
        b.engine.publish_path("three.txt").await?,
        Outcome::Skipped(_)
    ));
    // Existing paths still update, and remote content still arrives.
    b.write("one.txt", "1 again\n")?;
    wait_for_file(&a, "one.txt", Some("1 again\n")).await?;
    write_file(&a.path("from-a.bin"), &random_bytes(20_000, 4))?;
    wait_for_bytes(&b, "from-a.bin", Some(&random_bytes(20_000, 4))).await?;
    assert!(!a.path("huge.bin").exists());
    assert!(!a.path("three.txt").exists());

    a.stop().await?;
    b.stop().await?;
    Ok(())
}
