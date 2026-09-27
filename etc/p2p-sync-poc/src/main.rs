//! Geo-distributed NAT/relay probe, built against iroh 1.2.0. The watch
//! protocol below covers the connection scenarios (1-3, 5); `docs` adds
//! iroh-docs/iroh-blobs on the same endpoint for the transfer and catch-up
//! scenarios (4, 6) when `--share` or `--join` is given.

mod docs;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use clap::Parser;
use futures_lite::StreamExt;
use iroh::{
    Endpoint, EndpointAddr, EndpointId, SecretKey,
    endpoint::{Connection, PathList, presets},
    protocol::{AcceptError, ProtocolHandler, Router},
};
use serde::Serialize;

const WATCH_ALPN: &[u8] = b"probe/watch/v1";

#[derive(Parser)]
struct Args {
    /// This node's short name, used only in logs and Telegram messages.
    #[arg(long)]
    name: String,

    /// Directory for local state: the printed-ID file, plus the blobs/docs
    /// stores, `doc_id.txt`, `ticket.txt` and exported files when docs is on.
    #[arg(long, default_value = "./probe-data")]
    data_dir: PathBuf,

    /// Peer endpoint IDs to connect to and watch, as printed by their own
    /// `--name` startup line. Discovery (via the N0 preset) resolves the ID
    /// to a real address — you do not need to hand-carry addresses.
    #[arg(long, value_delimiter = ',')]
    peers: Vec<String>,

    /// Disable the public relay (for loopback-only tests per EXPERIMENT.md
    /// section 9). Real geo-distributed runs should NOT set this.
    #[arg(long)]
    no_relay: bool,

    /// Scenarios 4/6, sharing side: import these files into this node's doc
    /// (created on first use, reused after) and write a read ticket to
    /// `<data-dir>/ticket.txt`.
    #[arg(long, value_delimiter = ',', conflicts_with = "join")]
    share: Vec<PathBuf>,

    /// Scenarios 4/6, receiving side: join the doc behind this ticket and
    /// export its files to `<data-dir>/out/` as they arrive.
    #[arg(long)]
    join: Option<String>,

    /// Print this node's endpoint id (creating its key if needed) and exit.
    /// Lets the harness collect ids for `--peers` without starting a probe.
    #[arg(long)]
    print_id: bool,
}

/// One structured log line, emitted as JSON to stdout. Redirect each node's
/// run to a file (`> probe.log 2>&1`) and collect the files afterwards.
#[derive(Serialize)]
struct Event<'a> {
    ts_ms: i64,
    node: &'a str,
    kind: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    peer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
}

fn log(node: &str, kind: &str, peer: Option<&str>, detail: Option<String>) {
    let ev = Event {
        ts_ms: chrono::Utc::now().timestamp_millis(),
        node,
        kind,
        peer: peer.map(str::to_string),
        detail,
    };
    println!("{}", serde_json::to_string(&ev).unwrap());
}

/// Formats one open path the way the JSON log wants it: which kind (ip vs
/// relay), whether it's the one actually carrying traffic, and its RTT.
/// This is the direct replacement for the old, no-longer-existing
/// `Endpoint::conn_type()` — the signal now lives per-connection, per-path,
/// on `Connection::paths()` / `paths_stream()`, and a connection can have
/// more than one path open at once (this is what makes migration and
/// multi-path visible instead of collapsed into one enum value).
fn describe_paths(list: &PathList<'_>) -> String {
    let parts: Vec<String> = list
        .iter()
        .map(|p| {
            let kind = if p.is_relay() {
                "relay"
            } else if p.is_ip() {
                "ip"
            } else {
                "custom"
            };
            format!(
                "{{id:{:?},kind:{},selected:{},rtt_ms:{}}}",
                p.id(),
                kind,
                p.is_selected(),
                p.rtt().as_millis()
            )
        })
        .collect();
    format!("[{}]", parts.join(","))
}

/// Loads this node's endpoint key from `<data_dir>/secret.key`, creating it
/// on first run, so the endpoint id — and everything that carries it, like
/// peers.txt entries and doc tickets — stays the same across restarts.
fn load_or_create_secret_key(data_dir: &Path) -> Result<SecretKey> {
    let path = data_dir.join("secret.key");
    if let Ok(bytes) = std::fs::read(&path) {
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("{} is not a 32-byte key", path.display()))?;
        return Ok(SecretKey::from_bytes(&bytes));
    }
    let key = SecretKey::generate();
    std::fs::write(&path, key.to_bytes())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(key)
}

/// The watch protocol's accept-side handler. It just holds the connection
/// open and logs; the actual watching (via `paths_stream`) happens on both
/// sides symmetrically in `watch_connection` below, driven from whichever
/// side dialed and from whichever side accepted.
#[derive(Debug, Clone)]
struct WatchHandler {
    node_name: Arc<str>,
}

impl ProtocolHandler for WatchHandler {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        let remote = connection.remote_id();
        log(
            &self.node_name,
            "accepted",
            Some(&remote.to_string()),
            None,
        );
        watch_connection(self.node_name.to_string(), remote.to_string(), connection).await;
        Ok(())
    }
}

/// Watches one connection's paths for as long as it stays open, logging a
/// `paths` event every time the open-path set or the selected path changes
/// (paths_stream only yields on change, plus once immediately — no manual
/// polling interval needed, unlike the old conn_type-on-a-timer approach).
async fn watch_connection(node_name: String, peer: String, conn: Connection) {
    let mut stream = conn.paths_stream();
    while let Some(list) = stream.next().await {
        let detail = describe_paths(&list);
        log(&node_name, "paths", Some(&peer), Some(detail));
    }
    log(&node_name, "disconnected", Some(&peer), None);
}

#[tokio::main]
async fn main() -> Result<()> {
    // stderr, and no colour codes unless it's a terminal: under the harness
    // both streams go to probe.log, where stdout is the JSON event stream.
    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "warn".into()))
        .with_writer(std::io::stderr)
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr()))
        .init();

    let args = Args::parse();
    std::fs::create_dir_all(&args.data_dir)?;
    let secret_key = load_or_create_secret_key(&args.data_dir)?;
    if args.print_id {
        println!("{}", secret_key.public());
        return Ok(());
    }

    // Real 1.2.0 construction API: a `Preset` argument, not a method chain.
    // presets::N0 is n0's public discovery + relay set — this is what lets
    // nodes behind NAT find each other's current address without hand-
    // carrying addresses, and what makes hole-punching/relay-fallback work
    // at all. presets::N0DisableRelay exists for the loopback-only tests in
    // EXPERIMENT.md section 9; --no-relay here is a placeholder for that
    // distinction (verify presets::N0DisableRelay is the right choice for
    // "relay disabled but discovery still on" vs presets::Minimal).
    let endpoint = if args.no_relay {
        Endpoint::builder(presets::N0DisableRelay)
            .secret_key(secret_key)
            .alpns(vec![WATCH_ALPN.to_vec()])
            .bind()
            .await?
    } else {
        Endpoint::builder(presets::N0)
            .secret_key(secret_key)
            .alpns(vec![WATCH_ALPN.to_vec()])
            .bind()
            .await?
    };

    let my_id: EndpointId = endpoint.id();
    println!("# node {} id: {}", args.name, my_id);
    std::fs::write(args.data_dir.join("my_id.txt"), my_id.to_string())?;
    log(&args.name, "started", None, Some(my_id.to_string()));

    // Router dispatches accepted connections by ALPN to a handler — same
    // shape as SPEC2 assumed, confirmed present in the real protocol.rs.
    let mut router = Router::builder(endpoint.clone()).accept(
        WATCH_ALPN,
        WatchHandler {
            node_name: Arc::from(args.name.as_str()),
        },
    );
    let docs_node = if args.share.is_empty() && args.join.is_none() {
        None
    } else {
        let node = docs::DocsNode::spawn(&endpoint, &args.data_dir).await?;
        router = node.register(router);
        Some(node)
    };
    let router = router.spawn();

    if let Some(node) = &docs_node {
        if !args.share.is_empty() {
            node.share(&args.name, &args.share).await?;
        }
        if let Some(ticket) = &args.join {
            node.join(&args.name, ticket).await?;
        }
    }

    // Dial every configured peer. `EndpointId` converts directly into
    // `EndpointAddr` (confirmed: `impl From<EndpointId> for EndpointAddr`
    // in iroh-base), so a bare ID plus discovery is enough — no manual
    // address exchange needed beyond sharing the ID itself.
    let peers: Vec<EndpointId> = args
        .peers
        .iter()
        .map(|s| s.parse())
        .collect::<std::result::Result<_, _>>()?;

    for peer in peers {
        let ep = endpoint.clone();
        let name = args.name.clone();
        tokio::spawn(async move {
            loop {
                let addr: EndpointAddr = peer.into();
                match ep.connect(addr, WATCH_ALPN).await {
                    Ok(conn) => {
                        log(&name, "connected", Some(&peer.to_string()), None);
                        watch_connection(name.clone(), peer.to_string(), conn).await;
                        // watch_connection returns once the connection closes;
                        // loop back around and redial after a short backoff.
                    }
                    Err(e) => {
                        log(
                            &name,
                            "connect_failed",
                            Some(&peer.to_string()),
                            Some(e.to_string()),
                        );
                    }
                }
                tokio::time::sleep(Duration::from_secs(3)).await;
            }
        });
    }

    println!("# ready. Ctrl-C to stop.");
    tokio::signal::ctrl_c().await?;
    router.shutdown().await?;
    if let Some(node) = &docs_node {
        node.shutdown(&args.name).await;
    }
    Ok(())
}
