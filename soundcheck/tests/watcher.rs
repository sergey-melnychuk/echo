//! Stage 8: the file watcher publishes quiet files once, ignores `.p2p-sync/`,
//! and never re-announces or silently overwrites.

mod common;

use common::*;
use p2p_sync_poc::gossip::SyncMessage;
use p2p_sync_poc::sync::ApplyOutcome;
use p2p_sync_poc::watcher::{FileWatcher, WatcherEvent, DEBOUNCE};
use std::time::Duration;
use tokio::sync::broadcast;

/// Wait for the next watcher event about `file` that is not a `Skipped`.
async fn next_for(rx: &mut broadcast::Receiver<WatcherEvent>, file: &str) -> WatcherEvent {
    with_timeout(async {
        loop {
            match rx.recv().await.expect("watcher events") {
                WatcherEvent::Skipped { .. } => continue,
                ev => {
                    let name = match &ev {
                        WatcherEvent::Published { file_name, .. }
                        | WatcherEvent::Unchanged { file_name }
                        | WatcherEvent::Rejected { file_name }
                        | WatcherEvent::Failed { file_name, .. } => file_name.clone(),
                        WatcherEvent::Skipped { .. } => unreachable!(),
                    };
                    if name == file {
                        return ev;
                    }
                }
            }
        }
    })
    .await
}

/// Collect every non-skipped event for `quiet` after the last one.
async fn settle(rx: &mut broadcast::Receiver<WatcherEvent>, quiet: Duration) -> Vec<WatcherEvent> {
    let mut out = Vec::new();
    loop {
        match tokio::time::timeout(quiet, rx.recv()).await {
            Ok(Ok(WatcherEvent::Skipped { .. })) => continue,
            Ok(Ok(ev)) => out.push(ev),
            Ok(Err(_)) | Err(_) => return out,
        }
    }
}

fn new_versions(msgs: &[SyncMessage]) -> usize {
    msgs.iter()
        .filter(|m| matches!(m, SyncMessage::NewVersion { .. }))
        .count()
}

#[tokio::test]
async fn create_and_modify_each_produce_one_publish() {
    let doc = Doc::new();
    let mut h = Harness::new(&doc, true).await;
    let watcher = FileWatcher::spawn(h.engine.clone()).unwrap();
    let mut rx = watcher.subscribe();

    h.write("notes/a.txt", b"first");
    let ev = next_for(&mut rx, "notes/a.txt").await;
    assert!(matches!(ev, WatcherEvent::Published { .. }), "{ev:?}");
    let extra = settle(&mut rx, DEBOUNCE * 3).await;
    assert!(
        extra
            .iter()
            .all(|e| matches!(e, WatcherEvent::Unchanged { .. })),
        "{extra:?}"
    );
    assert_eq!(new_versions(&h.drain_outbox()), 1);

    h.write("notes/a.txt", b"second");
    let ev = next_for(&mut rx, "notes/a.txt").await;
    assert!(matches!(ev, WatcherEvent::Published { .. }), "{ev:?}");
    let extra = settle(&mut rx, DEBOUNCE * 3).await;
    assert!(
        extra
            .iter()
            .all(|e| matches!(e, WatcherEvent::Unchanged { .. })),
        "{extra:?}"
    );
    assert_eq!(new_versions(&h.drain_outbox()), 1);
    assert_eq!(h.engine.heads().unwrap().len(), 1);
    watcher.stop();
    h.shutdown().await;
}

#[tokio::test]
async fn ten_rapid_writes_coalesce_into_one_publish() {
    let doc = Doc::new();
    let mut h = Harness::new(&doc, true).await;
    let watcher = FileWatcher::spawn(h.engine.clone()).unwrap();
    let mut rx = watcher.subscribe();
    for i in 0..10u8 {
        h.write("burst.bin", &seeded_bytes(u64::from(i), 20_000));
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let ev = next_for(&mut rx, "burst.bin").await;
    assert!(matches!(ev, WatcherEvent::Published { .. }), "{ev:?}");
    let extra = settle(&mut rx, DEBOUNCE * 3).await;
    let published = 1 + extra
        .iter()
        .filter(|e| matches!(e, WatcherEvent::Published { .. }))
        .count();
    assert_eq!(published, 1, "{extra:?}");
    assert_eq!(new_versions(&h.drain_outbox()), 1);
    assert_eq!(h.read("burst.bin"), seeded_bytes(9, 20_000));
    watcher.stop();
    h.shutdown().await;
}

#[tokio::test]
async fn changes_under_internal_directory_are_ignored() {
    let doc = Doc::new();
    let mut h = Harness::new(&doc, true).await;
    let watcher = FileWatcher::spawn(h.engine.clone()).unwrap();
    let mut rx = watcher.subscribe();
    let internal = h.doc_dir().join(".p2p-sync");
    std::fs::create_dir_all(internal.join("rejected/deep")).unwrap();
    std::fs::write(internal.join("rejected/deep/old.txt.abcd1234"), b"kept").unwrap();
    std::fs::write(internal.join("rejected/x.txt.unpublished.ff"), b"kept").unwrap();
    std::fs::write(internal.join("config.toml"), b"secret").unwrap();
    std::fs::write(internal.join("tmp").join("partial"), b"partial").unwrap();

    // The watcher reports them as skipped and publishes nothing.
    let skipped = with_timeout(async {
        let mut n = 0;
        while n < 1 {
            if let WatcherEvent::Skipped { path, reason } = rx.recv().await.unwrap() {
                assert!(path.starts_with(".p2p-sync"), "{path}");
                assert_eq!(reason, "internal directory");
                n += 1;
            }
        }
        n
    })
    .await;
    assert!(skipped >= 1);
    let extra = settle(&mut rx, DEBOUNCE * 3).await;
    assert!(extra.is_empty(), "{extra:?}");
    assert!(h.drain_outbox().is_empty());
    assert!(h.engine.heads().unwrap().is_empty());
    watcher.stop();
    h.shutdown().await;
}

#[tokio::test]
async fn file_written_by_apply_is_not_announced_again() {
    let doc = Doc::new();
    let bytes = seeded_bytes(77, 30_000);
    let p = TestNode::spawn().await;
    p.sync.add_document(doc.id, doc.owner_pub);
    let pl = payload("remote.bin", &bytes);
    let v = version_by(&doc, p.secret(), &pl, None, past_hlc(0));
    seed(p.store.as_ref(), &doc, &pl, &v);

    let mut h = Harness::new(&doc, true).await;
    h.node.know(&p);
    let watcher = FileWatcher::spawn(h.engine.clone()).unwrap();
    let mut rx = watcher.subscribe();
    let r = with_timeout(h.engine.apply_remote(&v, &[p.id()]))
        .await
        .unwrap();
    assert!(matches!(r, ApplyOutcome::Applied { .. }));
    assert_eq!(h.read("remote.bin"), bytes);

    // Whatever the watcher sees of the engine's write, it publishes nothing.
    let seen = settle(&mut rx, DEBOUNCE * 4).await;
    assert!(
        seen.iter()
            .all(|e| matches!(e, WatcherEvent::Unchanged { .. })),
        "{seen:?}"
    );
    let out = h.drain_outbox();
    assert_eq!(new_versions(&out), 0, "{out:?}");
    assert_eq!(out.len(), 1, "exactly the Have: {out:?}");
    assert_eq!(
        h.node
            .store
            .head(&doc.id, "remote.bin")
            .unwrap()
            .unwrap()
            .version_id,
        vid(&v)
    );
    watcher.stop();
    h.shutdown().await;
    p.shutdown().await;
}

/// An edit that lands while a remote version of the same file is being
/// applied ends as a kept, rejected local edit, never as a silent overwrite.
#[tokio::test]
async fn edit_during_remote_apply_is_kept_not_overwritten() {
    let doc = Doc::new();
    let theirs = seeded_bytes(88, 25_000);
    let p = TestNode::spawn().await;
    p.sync.add_document(doc.id, doc.owner_pub);
    let pl = payload("shared.txt", &theirs);
    let v = version_by(&doc, p.secret(), &pl, None, past_hlc(0));
    seed(p.store.as_ref(), &doc, &pl, &v);

    let h = Harness::new(&doc, true).await;
    h.node.know(&p);
    let watcher = FileWatcher::spawn(h.engine.clone()).unwrap();
    let mut rx = watcher.subscribe();

    // The local edit lands, and the remote version is applied before the
    // watcher's debounce fires.
    let mine = b"my concurrent edit".to_vec();
    h.write("shared.txt", &mine);
    let r = with_timeout(h.engine.apply_remote(&v, &[p.id()]))
        .await
        .unwrap();
    assert!(matches!(r, ApplyOutcome::Applied { .. }), "{r:?}");

    let _ = settle(&mut rx, DEBOUNCE * 4).await;
    assert_eq!(
        h.read("shared.txt"),
        theirs,
        "disk holds the remote version"
    );
    let kept = h.rejected_files();
    assert!(
        kept.iter().any(|k| std::fs::read(k).unwrap() == mine),
        "the local edit must be kept: {kept:?}"
    );
    assert_eq!(
        h.node
            .store
            .head(&doc.id, "shared.txt")
            .unwrap()
            .unwrap()
            .version_id,
        vid(&v)
    );
    assert!(!h.engine.rejections().is_empty());
    watcher.stop();
    h.shutdown().await;
    p.shutdown().await;
}
