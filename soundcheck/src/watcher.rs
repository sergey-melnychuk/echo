//! `notify` integration with per-path debounce and echo suppression.
//!
//! Filesystem events are forwarded from notify's thread into a channel. A
//! debounce task waits until a path has been quiet for [`DEBOUNCE`], then
//! asks the engine to publish it. Anything under `.p2p-sync/` is ignored.
//! Echo suppression is content based: [`SyncEngine::publish_file`] returns
//! `Unchanged` when the bytes already equal the current head, which covers
//! both no-op saves and files the engine wrote itself.

use crate::manifest::{validate_file_name, INTERNAL_DIR};
use crate::sync::{PublishOutcome, SyncEngine, SyncError};
use crate::VersionId;
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher as _};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

/// A path is published once no event has arrived for it for this long.
pub const DEBOUNCE: Duration = Duration::from_millis(500);

/// Watcher failures.
#[derive(Debug, thiserror::Error)]
pub enum WatcherError {
    /// The OS watcher could not be created or the directory watched.
    #[error("filesystem watcher error: {0}")]
    Notify(#[from] notify::Error),
    /// The document directory could not be resolved.
    #[error("document directory error: {0}")]
    Path(String),
}

/// What the watcher did with a quiet path. Mainly for tests and `status`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WatcherEvent {
    /// A new version was published.
    Published {
        /// The file.
        file_name: String,
        /// The version.
        version_id: VersionId,
    },
    /// The content already equals the head (no-op save or engine echo).
    Unchanged {
        /// The file.
        file_name: String,
    },
    /// The publish lost to a moved head; the bytes were kept.
    Rejected {
        /// The file.
        file_name: String,
    },
    /// The path was not published; the reason says why.
    Skipped {
        /// The path relative to the document directory, `/` separated.
        path: String,
        /// Why.
        reason: &'static str,
    },
    /// Publishing failed.
    Failed {
        /// The file.
        file_name: String,
        /// The error text.
        error: String,
    },
}

/// Watches a document directory and publishes changed files through the
/// engine. Dropping it stops watching.
pub struct FileWatcher {
    _watcher: RecommendedWatcher,
    task: JoinHandle<()>,
    events: broadcast::Sender<WatcherEvent>,
}

impl FileWatcher {
    /// Start watching the engine's document directory recursively.
    pub fn spawn(engine: SyncEngine) -> Result<FileWatcher, WatcherError> {
        let doc_dir = engine.ctx().doc_dir.clone();
        let canonical = doc_dir
            .canonicalize()
            .map_err(|e| WatcherError::Path(format!("{}: {e}", doc_dir.display())))?;
        let (tx, rx) = mpsc::unbounded_channel::<notify::Result<Event>>();
        let mut watcher = notify::recommended_watcher(move |res| {
            let _ = tx.send(res);
        })?;
        watcher.watch(&doc_dir, RecursiveMode::Recursive)?;
        let (events, _) = broadcast::channel(1024);
        let task = tokio::spawn(run(engine, doc_dir, canonical, rx, events.clone()));
        info!("watching for changes");
        Ok(FileWatcher {
            _watcher: watcher,
            task,
            events,
        })
    }

    /// Subscribe to watcher events.
    pub fn subscribe(&self) -> broadcast::Receiver<WatcherEvent> {
        self.events.subscribe()
    }

    /// Stop watching and publishing.
    pub fn stop(self) {
        self.task.abort();
    }
}

/// Turn an event path into a document-relative file name, or a reason to skip it.
fn classify(
    path: &Path,
    doc_dir: &Path,
    canonical: &Path,
) -> Result<String, (String, &'static str)> {
    let rel = path
        .strip_prefix(doc_dir)
        .or_else(|_| path.strip_prefix(canonical))
        .map_err(|_| (path.display().to_string(), "outside the document directory"))?;
    let name = rel
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("/");
    if name.is_empty() {
        return Err((name, "the document directory itself"));
    }
    if rel
        .components()
        .next()
        .is_some_and(|c| c.as_os_str() == INTERNAL_DIR)
    {
        return Err((name, "internal directory"));
    }
    if path.is_dir() {
        return Err((name, "directory"));
    }
    if let Err(e) = validate_file_name(&name) {
        debug!(%name, "ignoring path: {e}");
        return Err((name, "invalid file name"));
    }
    Ok(name)
}

fn relevant(kind: &EventKind) -> bool {
    !matches!(kind, EventKind::Access(_))
}

async fn run(
    engine: SyncEngine,
    doc_dir: PathBuf,
    canonical: PathBuf,
    mut rx: mpsc::UnboundedReceiver<notify::Result<Event>>,
    events: broadcast::Sender<WatcherEvent>,
) {
    let mut pending: HashMap<String, Instant> = HashMap::new();
    loop {
        let next_deadline = pending.values().min().copied();
        tokio::select! {
            item = rx.recv() => {
                let Some(item) = item else { break };
                let event = match item {
                    Ok(e) => e,
                    Err(e) => {
                        warn!("watcher error: {e}");
                        continue;
                    }
                };
                if !relevant(&event.kind) {
                    continue;
                }
                for path in event.paths {
                    match classify(&path, &doc_dir, &canonical) {
                        Ok(name) => {
                            pending.insert(name, Instant::now() + DEBOUNCE);
                        }
                        Err((path, reason)) => {
                            let _ = events.send(WatcherEvent::Skipped { path, reason });
                        }
                    }
                }
            }
            _ = wait_until(next_deadline) => {
                let now = Instant::now();
                let due: Vec<String> = pending
                    .iter()
                    .filter(|(_, d)| **d <= now)
                    .map(|(k, _)| k.clone())
                    .collect();
                for name in due {
                    pending.remove(&name);
                    let ev = publish(&engine, &name).await;
                    let _ = events.send(ev);
                }
            }
        }
    }
}

async fn wait_until(deadline: Option<Instant>) {
    match deadline {
        Some(d) => tokio::time::sleep_until(d.into()).await,
        None => std::future::pending::<()>().await,
    }
}

async fn publish(engine: &SyncEngine, file_name: &str) -> WatcherEvent {
    match engine.publish_file(file_name).await {
        Ok(PublishOutcome::Published(version_id)) => WatcherEvent::Published {
            file_name: file_name.to_string(),
            version_id,
        },
        Ok(PublishOutcome::Unchanged) => WatcherEvent::Unchanged {
            file_name: file_name.to_string(),
        },
        Ok(PublishOutcome::Rejected { .. }) => WatcherEvent::Rejected {
            file_name: file_name.to_string(),
        },
        Err(SyncError::Io { source, .. }) if source.kind() == std::io::ErrorKind::NotFound => {
            WatcherEvent::Skipped {
                path: file_name.to_string(),
                reason: "removed before it could be read",
            }
        }
        Err(SyncError::NotWritable) => WatcherEvent::Skipped {
            path: file_name.to_string(),
            reason: "this node has no write token",
        },
        Err(e) => {
            warn!(file = file_name, "publish failed: {e}");
            WatcherEvent::Failed {
                file_name: file_name.to_string(),
                error: e.to_string(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_relative_paths_and_skips() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let canon = root.canonicalize().unwrap();
        std::fs::create_dir_all(root.join("sub")).unwrap();
        std::fs::write(root.join("sub/a.txt"), b"x").unwrap();
        assert_eq!(
            classify(&root.join("sub/a.txt"), &root, &canon).unwrap(),
            "sub/a.txt"
        );
        // Canonical form of the same path (as macOS reports it).
        assert_eq!(
            classify(&canon.join("sub/a.txt"), &root, &canon).unwrap(),
            "sub/a.txt"
        );
        assert_eq!(
            classify(&root.join(".p2p-sync/rejected/a.txt.1234"), &root, &canon)
                .unwrap_err()
                .1,
            "internal directory"
        );
        assert_eq!(
            classify(&root.join("sub"), &root, &canon).unwrap_err().1,
            "directory"
        );
        assert_eq!(
            classify(&root, &root, &canon).unwrap_err().1,
            "the document directory itself"
        );
        assert_eq!(
            classify(Path::new("/elsewhere/x"), &root, &canon)
                .unwrap_err()
                .1,
            "outside the document directory"
        );
        // A removed file still classifies (it is not a directory).
        assert_eq!(
            classify(&root.join("gone.txt"), &root, &canon).unwrap(),
            "gone.txt"
        );
    }

    #[test]
    fn access_events_are_irrelevant() {
        assert!(!relevant(&EventKind::Access(
            notify::event::AccessKind::Any
        )));
        assert!(relevant(&EventKind::Create(notify::event::CreateKind::Any)));
        assert!(relevant(&EventKind::Modify(notify::event::ModifyKind::Any)));
        assert!(relevant(&EventKind::Remove(notify::event::RemoveKind::Any)));
        assert!(relevant(&EventKind::Any));
    }
}
