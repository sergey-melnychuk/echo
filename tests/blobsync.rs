//! Stage 3 gate tests: a 10 MiB file transfers intact; a one-byte edit
//! transfers at most 3 chunks; a partitioned concurrent binary edit has one
//! winner everywhere, a local copy of the loser for its author and a flag
//! until the next write; a text file that becomes binary switches mode.

mod common;

use std::collections::HashMap;

use anyhow::{bail, Result};
use common::{
    hash_hex, merged_visible, random_bytes, wait_for_bytes, wait_for_file, wait_for_merged,
    wait_until, write_file, Peer,
};
use iroh_blobs::api::blobs::BlobStatus;
use iroh_blobs::Hash;
use iroh_docs::api::protocol::ShareMode;
use vaultsync::chunker::MIN_CHUNK;
use vaultsync::config::{self, Layout};
use vaultsync::filedoc::{Content, VersionKind};

/// Every complete blob on a peer with its size.
async fn blob_inventory(peer: &Peer) -> Result<HashMap<Hash, u64>> {
    let store = peer.vault.node().blobs();
    let mut inventory = HashMap::new();
    for hash in store.blobs().list().hashes().await? {
        if let BlobStatus::Complete { size } = store.blobs().status(hash).await? {
            inventory.insert(hash, size);
        }
    }
    Ok(inventory)
}

fn conflicts_of(peer: &Peer) -> Result<config::ConflictIndex> {
    config::load_conflicts(&Layout::new(&peer.dir).conflicts_index())
}

#[tokio::test]
async fn ten_mib_file_transfers_intact_and_an_edit_moves_one_chunk() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let a_dir = tmp.path().join("a");
    let data = random_bytes(10 << 20, 0x1234_5678);
    // Present before the engine starts: imported by the scan.
    write_file(&a_dir.join("big.bin"), &data)?;
    let a = Peer::init(&a_dir).await?;
    let ticket = a.vault.ticket(ShareMode::Write, &[]).await?;
    let b = Peer::join(&tmp.path().join("b"), &ticket).await?;
    wait_for_bytes(&b, "big.bin", Some(&data)).await?;
    let before = blob_inventory(&b).await?;
    let chunks_before = before.values().filter(|s| **s >= MIN_CHUNK as u64).count();
    assert!(chunks_before >= 40, "{chunks_before} chunk-sized blobs");

    // One byte in the middle: at most 3 new chunks arrive.
    let mut edited = data.clone();
    edited[data.len() / 2] ^= 0xff;
    write_file(&a.path("big.bin"), &edited)?;
    wait_for_bytes(&b, "big.bin", Some(&edited)).await?;
    let after = blob_inventory(&b).await?;
    let new_chunks = after
        .iter()
        .filter(|(hash, size)| !before.contains_key(*hash) && **size >= MIN_CHUNK as u64)
        .count();
    assert!(new_chunks <= 3, "{new_chunks} new chunk-sized blobs");
    assert!(new_chunks >= 1);

    // The document records a blob version with the right size.
    match merged_visible(&b, "big.bin").await?.map(|v| v.content) {
        Some(Content::Blob { size, .. }) => assert_eq!(size, data.len() as u64),
        other => bail!("unexpected content {other:?}"),
    }
    // B edits too, and A follows.
    let mut edited2 = edited.clone();
    edited2[100] ^= 0x55;
    write_file(&b.path("big.bin"), &edited2)?;
    wait_for_bytes(&a, "big.bin", Some(&edited2)).await?;

    a.stop().await?;
    b.stop().await?;
    Ok(())
}

#[tokio::test]
async fn partitioned_concurrent_binary_edit_has_one_winner_and_keeps_the_loser() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let a = Peer::init(&tmp.path().join("a")).await?;
    let ticket = a.vault.ticket(ShareMode::Write, &[]).await?;
    let b_dir = tmp.path().join("b");
    let b = Peer::join(&b_dir, &ticket).await?;
    let v0 = random_bytes(200 << 10, 1);
    write_file(&a.path("bin.dat"), &v0)?;
    wait_for_bytes(&b, "bin.dat", Some(&v0)).await?;
    b.stop().await?;

    // Partitioned writes: A while B is offline, B on disk while down.
    let v1 = random_bytes(200 << 10, 2);
    let v2 = random_bytes(200 << 10, 3);
    write_file(&a.path("bin.dat"), &v1)?;
    wait_until("A published v1", || async {
        Ok(matches!(
            merged_visible(&a, "bin.dat").await?.map(|v| v.content),
            Some(Content::Blob { size, .. }) if size == v1.len() as u64
                && a.read_bytes("bin.dat").as_deref() == Some(v1.as_slice())
        ) && hash_hex(&a.read_bytes("bin.dat").unwrap_or_default()) != hash_hex(&v0))
    })
    .await?;
    write_file(&b_dir.join("bin.dat"), &v2)?;
    let b = Peer::open(&b_dir).await?;

    // Both wrote once on the same base: same Lamport counter, so the lower
    // actor id wins, on every peer.
    let a_wins = a.actor_bytes() < b.actor_bytes();
    let (winner, loser, loser_peer, other_peer) = if a_wins {
        (&v1, &v2, &b, &a)
    } else {
        (&v2, &v1, &a, &b)
    };
    wait_for_bytes(&a, "bin.dat", Some(winner)).await?;
    wait_for_bytes(&b, "bin.dat", Some(winner)).await?;

    // The flag and the loser's manifest, identical on both peers.
    let mut loser_id = None;
    for peer in [&a, &b] {
        wait_until("conflict flagged", || async {
            Ok(conflicts_of(peer)?.contains_key("bin.dat"))
        })
        .await?;
        let visible = merged_visible(peer, "bin.dat").await?.expect("merged");
        assert!(visible.is_conflict());
        assert_eq!(visible.losers.len(), 1);
        let VersionKind::Blob { manifest, size } = &visible.losers[0].kind else {
            bail!("loser is not a blob");
        };
        assert_eq!(*size, loser.len() as u64);
        let id = data_encoding::HEXLOWER.encode(&manifest[..4]);
        if let Some(previous) = &loser_id {
            assert_eq!(previous, &id);
        }
        loser_id = Some(id);
    }
    let loser_id = loser_id.expect("loser id");

    // The loser's author has a local copy under .vault/conflicts/.
    let copy = Layout::new(&loser_peer.dir)
        .conflicts()
        .join(format!("bin.dat.{loser_id}"));
    wait_until("conflict copy", || async {
        Ok(std::fs::read(&copy).ok().as_deref() == Some(loser.as_slice()))
    })
    .await?;
    // The other peer has no copy yet and exports on demand, fetching the
    // loser's chunks from the network.
    let other_copy = Layout::new(&other_peer.dir)
        .conflicts()
        .join(format!("bin.dat.{loser_id}"));
    assert!(!other_copy.exists());
    let exported = other_peer.engine.export_conflicts("bin.dat").await?;
    assert_eq!(exported, vec![other_copy.clone()]);
    assert_eq!(std::fs::read(&other_copy)?, *loser);

    // The next write, by anyone, supersedes both versions and clears the flag.
    let v3 = random_bytes(150 << 10, 4);
    write_file(&other_peer.path("bin.dat"), &v3)?;
    wait_for_bytes(&a, "bin.dat", Some(&v3)).await?;
    wait_for_bytes(&b, "bin.dat", Some(&v3)).await?;
    for peer in [&a, &b] {
        wait_until("conflict cleared", || async {
            Ok(!conflicts_of(peer)?.contains_key("bin.dat"))
        })
        .await?;
        assert!(!merged_visible(peer, "bin.dat")
            .await?
            .expect("merged")
            .is_conflict());
    }
    // The loser stays retrievable from history and from the copy.
    assert_eq!(std::fs::read(&copy)?, *loser);

    a.stop().await?;
    b.stop().await?;
    Ok(())
}

#[tokio::test]
async fn text_file_switches_to_binary_and_back_and_is_deleted() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let a = Peer::init(&tmp.path().join("a")).await?;
    let ticket = a.vault.ticket(ShareMode::Write, &[]).await?;
    let b = Peer::join(&tmp.path().join("b"), &ticket).await?;

    a.write("f.dat", "plain text first\n")?;
    wait_for_file(&b, "f.dat", Some("plain text first\n")).await?;

    let mut binary = random_bytes(100 << 10, 9);
    binary[0] = 0; // a NUL makes it binary regardless of the rest
    write_file(&a.path("f.dat"), &binary)?;
    wait_for_bytes(&b, "f.dat", Some(&binary)).await?;
    assert!(matches!(
        merged_visible(&b, "f.dat").await?.map(|v| v.content),
        Some(Content::Blob { .. })
    ));

    b.write("f.dat", "text again\n")?;
    wait_for_file(&a, "f.dat", Some("text again\n")).await?;
    wait_for_merged(&a, "f.dat", &Content::Text("text again\n".into())).await?;

    // Large text is a blob too: over 1 MiB of valid UTF-8.
    let big_text = "0123456789abcdef\n".repeat(70_000);
    assert!(big_text.len() > 1 << 20);
    a.write("large.txt", &big_text)?;
    wait_for_bytes(&b, "large.txt", Some(big_text.as_bytes())).await?;
    assert!(matches!(
        merged_visible(&b, "large.txt").await?.map(|v| v.content),
        Some(Content::Blob { .. })
    ));

    std::fs::remove_file(a.path("f.dat"))?;
    std::fs::remove_file(a.path("large.txt"))?;
    wait_for_bytes(&b, "f.dat", None).await?;
    wait_for_bytes(&b, "large.txt", None).await?;

    a.stop().await?;
    b.stop().await?;
    Ok(())
}
