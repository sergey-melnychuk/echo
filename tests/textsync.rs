//! Stage 2 gate tests: two nodes converge on text files, including a
//! partitioned concurrent edit, offline catch-up and deletion; a local edit
//! made before a remote apply is never overwritten (CRD-1); hostile keys are
//! ignored (CRD-7, SEC-4). Loopback only, no fixed sleeps.

mod common;

use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{bail, Result};
use common::{
    merged_content, wait_for_bytes, wait_for_file, wait_for_merged, write_file, Peer, DEADLINE,
};
use iroh_docs::store::Query;
use vaultsync::config::{Config, Layout};
use vaultsync::engine::Outcome;
use vaultsync::filedoc::{actor_for, Content, FileDoc};

#[tokio::test]
async fn text_files_sync_both_ways_including_delete() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let a_dir = tmp.path().join("a");
    // A file that exists before the engine starts is picked up by the scan.
    write_file(&a_dir.join("pre.txt"), b"before start\n")?;
    let a = Peer::init(&a_dir).await?;
    let invite = a.write_invite()?;
    let b = Peer::join(&tmp.path().join("b"), &invite).await?;
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

    // Binary content syncs too (stage 3), next to the text files.
    let binary = [0u8, 1, 2, 255, 0, 7];
    write_file(&a.path("img.bin"), &binary)?;
    a.write("after.txt", "after the binary\n")?;
    wait_for_file(&b, "after.txt", Some("after the binary\n")).await?;
    wait_for_bytes(&b, "img.bin", Some(&binary)).await?;

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
    let invite = a.write_invite()?;
    let b_dir = tmp.path().join("b");
    let b = Peer::join(&b_dir, &invite).await?;
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
    let invite = a.write_invite()?;
    let mut b = Peer::join(&tmp.path().join("b"), &invite).await?;
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
    let invite = a.write_invite()?;
    let b = Peer::join(&tmp.path().join("b"), &invite).await?;
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
    let invite = a.read_invite()?;
    let b = Peer::join(&tmp.path().join("b"), &invite).await?;
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
