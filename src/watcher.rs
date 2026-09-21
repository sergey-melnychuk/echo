//! File watcher: `notify` with `notify-debouncer-full`, which coalesces bursts.
//! Every path of every debounced event is forwarded, one batch per debounce
//! window; the engine decides what a path means (created, changed, removed, a
//! directory) by looking at the disk, and reconciles known files that
//! disappeared after each batch, because renames report only the new name and
//! a removed directory is reported once, without its contents (NOTES.md).

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use notify_debouncer_full::notify::{RecommendedWatcher, RecursiveMode};
use notify_debouncer_full::{new_debouncer, DebounceEventResult, Debouncer, RecommendedCache};
use tokio::sync::mpsc;

/// The debounce window used by `run` (SPEC.md section 5.3).
pub const DEFAULT_DEBOUNCE: Duration = Duration::from_millis(500);

pub struct Watcher {
    debouncer: Debouncer<RecommendedWatcher, RecommendedCache>,
}

impl Watcher {
    /// Watch `root` recursively and send the affected paths of each debounce
    /// window to `tx` as one batch.
    pub fn spawn(
        root: &Path,
        debounce: Duration,
        tx: mpsc::UnboundedSender<Vec<PathBuf>>,
    ) -> Result<Watcher> {
        let handler = move |result: DebounceEventResult| match result {
            Ok(events) => {
                let batch: Vec<PathBuf> = events
                    .iter()
                    .flat_map(|event| event.event.paths.iter().cloned())
                    .collect();
                if !batch.is_empty() {
                    let _ = tx.send(batch);
                }
            }
            Err(errors) => {
                for error in errors {
                    tracing::warn!("file watcher error: {error}");
                }
            }
        };
        let mut debouncer =
            new_debouncer(debounce, None, handler).context("starting the file watcher")?;
        debouncer
            .watch(root, RecursiveMode::Recursive)
            .with_context(|| format!("watching {}", root.display()))?;
        Ok(Watcher { debouncer })
    }

    /// Stop watching; waits for the debouncer thread to finish.
    pub fn stop(self) {
        self.debouncer.stop();
    }
}

impl std::fmt::Debug for Watcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Watcher")
    }
}
