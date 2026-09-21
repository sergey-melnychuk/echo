//! Stage 2 spike: what does notify-debouncer-full report for creates, edits,
//! renames and `remove_dir_all` on this platform, and are the paths canonical?
//!
//! Throwaway code. Findings go to NOTES.md.

use std::time::Duration;

use echo::watcher::Watcher;
use tokio::sync::mpsc;

async fn drain(rx: &mut mpsc::UnboundedReceiver<Vec<std::path::PathBuf>>, label: &str) {
    tokio::time::sleep(Duration::from_millis(400)).await;
    println!("-- {label}");
    while let Ok(batch) = rx.try_recv() {
        println!("   batch of {}", batch.len());
        for path in batch {
            println!("   {} exists={}", path.display(), path.exists());
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let tmp = tempfile::tempdir()?;
    let root = tmp.path().join("vault");
    std::fs::create_dir_all(&root)?;
    println!("root      {}", root.display());
    println!("canonical {}", root.canonicalize()?.display());
    let (tx, mut rx) = mpsc::unbounded_channel::<Vec<std::path::PathBuf>>();
    let watcher = Watcher::spawn(&root, Duration::from_millis(100), tx)?;
    tokio::time::sleep(Duration::from_millis(200)).await;

    std::fs::write(root.join("a.txt"), "a\n")?;
    drain(&mut rx, "create a.txt").await;
    std::fs::write(root.join("a.txt"), "aa\n")?;
    drain(&mut rx, "edit a.txt").await;
    std::fs::create_dir_all(root.join("dir/sub"))?;
    std::fs::write(root.join("dir/one.txt"), "1\n")?;
    std::fs::write(root.join("dir/sub/two.txt"), "2\n")?;
    drain(&mut rx, "create dir/one.txt, dir/sub/two.txt").await;
    std::fs::rename(root.join("a.txt"), root.join("b.txt"))?;
    drain(&mut rx, "rename a.txt -> b.txt").await;
    std::fs::remove_dir_all(root.join("dir"))?;
    drain(&mut rx, "remove_dir_all dir").await;
    std::fs::remove_file(root.join("b.txt"))?;
    drain(&mut rx, "remove b.txt").await;
    std::fs::create_dir_all(root.join("moved/inner"))?;
    std::fs::write(root.join("moved/inner/x.txt"), "x\n")?;
    drain(&mut rx, "create moved/inner/x.txt").await;
    std::fs::rename(root.join("moved"), root.join("elsewhere"))?;
    drain(&mut rx, "rename dir moved -> elsewhere").await;
    watcher.stop();
    Ok(())
}
