//! Stage 0 spike, iroh 1.2 + iroh-docs 0.101 + iroh-blobs 0.103 on loopback:
//!
//! A. two nodes sync a docs entry and its content; a third joins late and
//!    catches up; state survives a restart.
//! B. a 10 MiB file as FastCDC chunks plus a HashSeq; one-byte edit; measure
//!    how much a second node downloads.
//! C. a Biscuit-verified auth hook gates the docs, blobs and gossip ALPNs.
//!
//! Throwaway code. Findings go to NOTES.md.

use std::collections::HashMap;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use fastcdc::v2020::StreamCDC;
use iroh::endpoint::{presets, Connection};
use iroh::protocol::Router;
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayMode, SecretKey};
use iroh_blobs::api::Store as BlobStore;
use iroh_blobs::hashseq::HashSeq;
use iroh_blobs::store::fs::FsStore;
use iroh_blobs::{BlobFormat, BlobsProtocol, Hash, HashAndFormat, ALPN as BLOBS_ALPN};
use iroh_docs::api::protocol::{AddrInfoOptions, ShareMode};
use iroh_docs::engine::LiveEvent;
use iroh_docs::protocol::Docs;
use iroh_docs::store::Query;
use iroh_docs::{DocTicket, ALPN as DOCS_ALPN};
use iroh_gossip::net::Gossip;
use iroh_gossip::ALPN as GOSSIP_ALPN;
use n0_future::StreamExt;
use tokio::time::timeout;

const T: Duration = Duration::from_secs(20);

struct Node {
    dir: PathBuf,
    endpoint: Endpoint,
    blobs: FsStore,
    docs: Docs,
    router: Router,
}

impl Node {
    async fn spawn(dir: &Path, secret: SecretKey, auth: Option<auth::Config>) -> Result<Node> {
        std::fs::create_dir_all(dir.join("blobs"))?;
        std::fs::create_dir_all(dir.join("docs"))?;
        let mut builder = Endpoint::builder(presets::Minimal)
            .secret_key(secret)
            .relay_mode(RelayMode::Disabled)
            .clear_ip_transports()
            .bind_addr("127.0.0.1:0")?;
        let mut auth_parts = None;
        if let Some(cfg) = auth {
            let (hook, task, protocol) = auth::build(cfg);
            builder = builder.hooks(hook);
            auth_parts = Some((task, protocol));
        }
        let endpoint = builder.bind().await?;
        let blobs = FsStore::load(dir.join("blobs")).await?;
        let gossip = Gossip::builder().spawn(endpoint.clone());
        let docs = Docs::persistent(dir.join("docs"))
            .spawn(endpoint.clone(), (*blobs).clone(), gossip.clone())
            .await?;
        let mut router = Router::builder(endpoint.clone())
            .accept(BLOBS_ALPN, BlobsProtocol::new(&blobs, None))
            .accept(GOSSIP_ALPN, gossip)
            .accept(DOCS_ALPN, docs.clone());
        if let Some((task, protocol)) = auth_parts {
            task.spawn(endpoint.clone());
            router = router.accept(auth::ALPN, protocol);
        }
        let router = router.spawn();
        Ok(Node {
            dir: dir.to_path_buf(),
            endpoint,
            blobs,
            docs,
            router,
        })
    }

    fn store(&self) -> &BlobStore {
        &self.blobs
    }

    fn addr(&self) -> EndpointAddr {
        self.endpoint.addr()
    }

    async fn shutdown(self) -> Result<()> {
        self.router.shutdown().await?;
        self.endpoint.close().await;
        Ok(())
    }
}

async fn wait_for_key(
    events: &mut (impl StreamExt<Item = Result<LiveEvent>> + Unpin),
    key: &[u8],
) -> Result<Hash> {
    let deadline = Instant::now() + T;
    let mut pending: Option<Hash> = None;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        let ev = timeout(left, events.next())
            .await
            .context("timeout waiting for event")?
            .ok_or_else(|| anyhow!("event stream ended"))?;
        match ev? {
            LiveEvent::InsertRemote {
                entry,
                content_status,
                ..
            } if entry.key() == key => {
                if content_status == iroh_docs::ContentStatus::Complete {
                    return Ok(entry.content_hash());
                }
                pending = Some(entry.content_hash());
            }
            LiveEvent::ContentReady { hash } if Some(hash) == pending => return Ok(hash),
            _ => {}
        }
    }
}

async fn poll_until<F, Fut>(mut f: F, what: &str) -> Result<()>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<bool>>,
{
    let deadline = Instant::now() + T;
    loop {
        if f().await? {
            return Ok(());
        }
        if Instant::now() > deadline {
            bail!("timeout: {what}");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

// ---------------------------------------------------------------------------
// A. docs sync
// ---------------------------------------------------------------------------

async fn phase_a(root: &Path) -> Result<()> {
    println!("== A. docs sync ==");
    let sk1 = SecretKey::from_bytes(&[1u8; 32]);
    let sk2 = SecretKey::from_bytes(&[2u8; 32]);
    let sk3 = SecretKey::from_bytes(&[3u8; 32]);
    let n1 = Node::spawn(&root.join("n1"), sk1, None).await?;
    let n2 = Node::spawn(&root.join("n2"), sk2.clone(), None).await?;
    println!("n1 addr: {:?}", n1.addr());

    let author1 = n1.docs.author_create().await?;
    let doc1 = n1.docs.create().await?;
    let mut events1 = doc1.subscribe().await?;
    doc1.set_bytes(author1, "hello", "world").await?;
    let ticket = doc1
        .share(ShareMode::Write, AddrInfoOptions::Addresses)
        .await?;
    let ticket_str = ticket.to_string();
    println!(
        "ticket ({} chars): {}...",
        ticket_str.len(),
        &ticket_str[..24]
    );
    let ticket: DocTicket = ticket_str.parse()?;

    let t0 = Instant::now();
    let (doc2, mut events2) = n2.docs.import_and_subscribe(ticket.clone()).await?;
    let hash = wait_for_key(&mut events2, b"hello").await?;
    let content = n2.store().get_bytes(hash).await?;
    assert_eq!(&content[..], b"world");
    println!("n2 received hello=world after {:?}", t0.elapsed());

    // Write back from n2.
    let author2 = n2.docs.author_create().await?;
    doc2.set_bytes(author2, "from-b", "b-content").await?;
    let hash = wait_for_key(&mut events1, b"from-b").await?;
    assert_eq!(&n1.store().get_bytes(hash).await?[..], b"b-content");
    println!("n1 received from-b");

    // Two entries for the same key from two authors: Query::all().key_exact.
    doc2.set_bytes(author2, "hello", "world-from-b").await?;
    wait_for_key(&mut events1, b"hello").await?;
    let entries: Vec<_> = doc1
        .get_many(Query::all().key_exact("hello"))
        .await?
        .try_collect()
        .await?;
    println!(
        "entries for key hello on n1: {} (authors {:?})",
        entries.len(),
        entries
            .iter()
            .map(|e| e.author().fmt_short())
            .collect::<Vec<_>>()
    );
    assert_eq!(entries.len(), 2);
    let peers = doc1.get_sync_peers().await?;
    println!("n1 sync peers: {:?}", peers.map(|p| p.len()));
    let peers = doc2.get_sync_peers().await?;
    println!("n2 sync peers: {:?}", peers.map(|p| p.len()));

    // Late joiner catches up with everything.
    let n3 = Node::spawn(&root.join("n3"), sk3, None).await?;
    let (doc3, mut events3) = n3.docs.import_and_subscribe(ticket.clone()).await?;
    let t0 = Instant::now();
    poll_until(
        || async {
            let entries: Vec<_> = doc3.get_many(Query::all()).await?.try_collect().await?;
            let mut all = true;
            for e in &entries {
                all &= n3.store().has(e.content_hash()).await?;
            }
            Ok(entries.len() == 3 && all)
        },
        "n3 catch-up",
    )
    .await?;
    println!(
        "n3 caught up with 3 entries and content after {:?}",
        t0.elapsed()
    );
    // Drain n3 events for a moment to show what a late joiner sees.
    let mut seen = Vec::new();
    while let Ok(Some(ev)) = timeout(Duration::from_millis(300), events3.next()).await {
        seen.push(
            format!("{:?}", ev?)
                .split(' ')
                .next()
                .unwrap_or("")
                .trim_end_matches('{')
                .to_string(),
        );
    }
    println!("n3 event kinds: {seen:?}");

    // Restart n2 and check persistence.
    let ns = doc2.id();
    drop(doc2);
    drop(events2);
    n2.shutdown().await?;
    println!("n2 shut down");
    let n2 = Node::spawn(&root.join("n2"), sk2, None).await?;
    let doc2 = n2
        .docs
        .open(ns)
        .await?
        .ok_or_else(|| anyhow!("doc not found after restart"))?;
    let entries: Vec<_> = doc2.get_many(Query::all()).await?.try_collect().await?;
    println!(
        "n2 after restart: {} entries, default author {}, sync peers {:?}",
        entries.len(),
        n2.docs.author_default().await?.fmt_short(),
        doc2.get_sync_peers().await?.map(|p| p.len())
    );
    assert_eq!(entries.len(), 3);
    for e in &entries {
        assert!(n2.store().has(e.content_hash()).await?, "content persisted");
    }
    // Does the doc sync again after restart without an explicit start_sync?
    doc1.set_bytes(author1, "after-restart", "x").await?;
    let mut events2 = doc2.subscribe().await?;
    let res = timeout(
        Duration::from_secs(3),
        wait_for_key(&mut events2, b"after-restart"),
    )
    .await;
    println!(
        "n2 receives new entry after restart without start_sync: {}",
        res.is_ok()
    );
    if res.is_err() {
        doc2.start_sync(ticket.nodes.clone()).await?;
        wait_for_key(&mut events2, b"after-restart").await?;
        println!("n2 receives new entry after start_sync: true");
    }
    let dir_size = |p: &Path| -> u64 {
        walkdir::WalkDir::new(p)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter_map(|e| e.metadata().ok())
            .filter(|m| m.is_file())
            .map(|m| m.len())
            .sum()
    };
    println!(
        "n2 dir sizes: blobs {} bytes, docs {} bytes",
        dir_size(&n2.dir.join("blobs")),
        dir_size(&n2.dir.join("docs"))
    );
    for entry in walkdir::WalkDir::new(&n2.dir).max_depth(2) {
        let entry = entry?;
        if entry.path() != n2.dir {
            println!("   {}", entry.path().strip_prefix(&n2.dir)?.display());
        }
    }

    n1.shutdown().await?;
    n2.shutdown().await?;
    n3.shutdown().await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// B. blob delta transfer
// ---------------------------------------------------------------------------

const MIN: usize = 16 << 10;
const AVG: usize = 64 << 10;
const MAX: usize = 256 << 10;

async fn import_chunked(store: &BlobStore, data: &[u8], tag: &str) -> Result<(Hash, usize)> {
    let mut hashes = Vec::new();
    let mut temp_tags = Vec::new();
    for chunk in StreamCDC::new(Cursor::new(data), MIN, AVG, MAX) {
        let chunk = chunk?;
        let tt = store.add_bytes(chunk.data).temp_tag().await?;
        hashes.push(tt.hash());
        temp_tags.push(tt);
    }
    let hs: HashSeq = hashes.iter().copied().collect();
    let n = hashes.len();
    let manifest = store
        .add_bytes_with_opts((hs.into_inner(), BlobFormat::HashSeq))
        .with_named_tag(tag)
        .await?;
    Ok((manifest.hash, n))
}

async fn assemble(store: &BlobStore, manifest: Hash) -> Result<Vec<u8>> {
    let bytes = store.get_bytes(manifest).await?;
    let hs = HashSeq::new(bytes).ok_or_else(|| anyhow!("bad hashseq"))?;
    let mut out = Vec::new();
    for h in hs.iter() {
        out.extend_from_slice(&store.get_bytes(h).await?);
    }
    Ok(out)
}

fn random_data(size: usize, mut seed: u64) -> Vec<u8> {
    let mut data = Vec::with_capacity(size);
    while data.len() < size {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        data.extend_from_slice(&seed.to_le_bytes());
    }
    data
}

async fn phase_b(root: &Path) -> Result<()> {
    println!("== B. blob delta transfer ==");
    let n1 = Node::spawn(&root.join("b1"), SecretKey::from_bytes(&[11u8; 32]), None).await?;
    let n2 = Node::spawn(&root.join("b2"), SecretKey::from_bytes(&[12u8; 32]), None).await?;
    let size = 10 << 20;
    let data = random_data(size, 0x9e37_79b9_7f4a_7c15);

    let t0 = Instant::now();
    let (m1, chunks1) = import_chunked(n1.store(), &data, "v1").await?;
    println!("import v1: {chunks1} chunks in {:?}", t0.elapsed());
    let dir_size = |p: &Path| -> u64 {
        walkdir::WalkDir::new(p)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter_map(|e| e.metadata().ok())
            .filter(|m| m.is_file())
            .map(|m| m.len())
            .sum()
    };
    let files = walkdir::WalkDir::new(n1.dir.join("blobs"))
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .count();
    println!(
        "n1 blob store after v1: {} bytes on disk for {} bytes of content ({} files)",
        dir_size(&n1.dir.join("blobs")),
        size,
        files
    );

    // Fetch via remote().fetch with exact stats.
    let t0 = Instant::now();
    let conn = n2.endpoint.connect(n1.addr(), BLOBS_ALPN).await?;
    let stats = n2
        .store()
        .remote()
        .fetch(conn, HashAndFormat::hash_seq(m1))
        .await?;
    println!(
        "n2 fetch v1: payload {} bytes, other {} bytes, {:?}",
        stats.payload_bytes_read,
        stats.other_bytes_read,
        t0.elapsed()
    );
    assert_eq!(assemble(n2.store(), m1).await?, data);

    // One-byte edit in the middle. Two-step fetch: root first, then only the
    // missing children (the missing set cannot be computed before the root is local).
    let mut edited = data.clone();
    edited[size / 2] ^= 0xff;
    let (m2, chunks2) = import_chunked(n1.store(), &edited, "v2").await?;
    let t0 = Instant::now();
    let conn = n2.endpoint.connect(n1.addr(), BLOBS_ALPN).await?;
    let root_stats = n2
        .store()
        .remote()
        .fetch(conn.clone(), HashAndFormat::raw(m2))
        .await?;
    let local = n2
        .store()
        .remote()
        .local(HashAndFormat::hash_seq(m2))
        .await?;
    println!(
        "n2 after root fetch of v2: root payload {} bytes; local complete={} local_bytes={} children={:?}",
        root_stats.payload_bytes_read, local.is_complete(), local.local_bytes(), local.children()
    );
    let missing = local.missing();
    let stats = n2.store().remote().execute_get(conn, missing).await?;
    println!(
        "n2 fetch v2 missing children ({chunks2} chunks total): payload {} bytes, other {} bytes, {:?}",
        stats.payload_bytes_read, stats.other_bytes_read, t0.elapsed()
    );
    assert!(stats.payload_bytes_read <= 3 * MAX as u64);
    assert_eq!(assemble(n2.store(), m2).await?, edited);

    // Same through the Downloader (multi-provider path): root, then hash seq.
    let mut edited2 = edited.clone();
    edited2[size / 4] ^= 0xff;
    let (m3, _) = import_chunked(n1.store(), &edited2, "v3").await?;
    let dl = n2.store().downloader(&n2.endpoint);
    let t0 = Instant::now();
    dl.download(m3, vec![n1.endpoint.id()]).await?;
    let local = n2
        .store()
        .remote()
        .local(HashAndFormat::hash_seq(m3))
        .await?;
    let before = local.local_bytes();
    println!(
        "n2 after downloader root fetch of v3: complete={} local_bytes={before} children={:?}",
        local.is_complete(),
        local.children()
    );
    let mut progress = dl
        .download(HashAndFormat::hash_seq(m3), vec![n1.endpoint.id()])
        .stream()
        .await?;
    let mut last = 0u64;
    let mut items = Vec::new();
    while let Some(item) = progress.next().await {
        match item {
            iroh_blobs::api::downloader::DownloadProgressItem::Progress(p) => last = p,
            other => items.push(
                format!("{other:?}")
                    .split(' ')
                    .next()
                    .unwrap_or("")
                    .trim_end_matches('{')
                    .to_string(),
            ),
        }
    }
    let local_after = n2
        .store()
        .remote()
        .local(HashAndFormat::hash_seq(m3))
        .await?;
    println!(
        "downloader v3: last progress {last}, items {items:?}, {:?}; local_bytes {} -> {} (downloaded {} bytes)",
        t0.elapsed(), before, local_after.local_bytes(), local_after.local_bytes() - before
    );
    assert!(local_after.local_bytes() - before <= 3 * MAX as u64);
    assert_eq!(assemble(n2.store(), m3).await?, edited2);

    // What does a plain hash-seq download do when the root is missing? (expected: everything)
    let mut edited3 = edited2.clone();
    edited3[size / 5] ^= 0xff;
    let (m4, _) = import_chunked(n1.store(), &edited3, "v4").await?;
    let conn = n2.endpoint.connect(n1.addr(), BLOBS_ALPN).await?;
    let stats = n2
        .store()
        .remote()
        .fetch(conn, HashAndFormat::hash_seq(m4))
        .await?;
    println!("one-step hash-seq fetch of v4 with root missing: payload {} bytes (full re-download expected)", stats.payload_bytes_read);

    // Tags protect: list tags on n1.
    let tags: Vec<_> = n1.store().tags().list().await?.try_collect().await?;
    println!(
        "n1 tags: {:?}",
        tags.iter()
            .map(|t| String::from_utf8_lossy(t.name.as_ref()).to_string())
            .collect::<Vec<_>>()
    );

    n1.shutdown().await?;
    n2.shutdown().await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// C. auth hook
// ---------------------------------------------------------------------------

mod auth {
    use super::*;
    use biscuit_auth::macros::authorizer;
    use biscuit_auth::{Biscuit, PublicKey};
    use iroh::endpoint::{
        AfterHandshakeOutcome, BeforeConnectOutcome, ConnectionError, EndpointHooks, Side,
    };
    use iroh::protocol::{AcceptError, ProtocolHandler};
    use tokio::sync::{mpsc, oneshot};

    pub const ALPN: &[u8] = b"vaultsync/auth/0";
    const ACCEPTED: u32 = 1;
    const DENIED: u32 = 403;
    const MAX_TOKEN: usize = 4096;
    const ADMISSION: Duration = Duration::from_secs(600);

    #[derive(Clone)]
    pub struct Config {
        pub token: Vec<u8>,
        pub root: PublicKey,
        pub vault: String,
    }

    #[derive(Debug, Default)]
    pub struct Admitted(Mutex<HashMap<EndpointId, Instant>>);

    impl Admitted {
        fn is_admitted(&self, id: &EndpointId) -> bool {
            self.0
                .lock()
                .unwrap()
                .get(id)
                .is_some_and(|t| t.elapsed() < ADMISSION)
        }
        fn admit(&self, id: EndpointId) {
            self.0.lock().unwrap().insert(id, Instant::now());
        }
    }

    type PreAuth = (EndpointAddr, oneshot::Sender<bool>);

    #[derive(Debug)]
    pub struct Hook {
        admitted: Arc<Admitted>,
        tx: mpsc::Sender<PreAuth>,
    }

    impl EndpointHooks for Hook {
        async fn before_connect<'a>(
            &'a self,
            remote: &'a EndpointAddr,
            alpn: &'a [u8],
        ) -> BeforeConnectOutcome {
            if alpn == ALPN {
                return BeforeConnectOutcome::Accept;
            }
            let (tx, rx) = oneshot::channel();
            if self.tx.send((remote.clone(), tx)).await.is_err() {
                return BeforeConnectOutcome::Reject;
            }
            match rx.await {
                Ok(true) => BeforeConnectOutcome::Accept,
                _ => BeforeConnectOutcome::Reject,
            }
        }

        async fn after_handshake<'a>(&'a self, conn: &'a Connection) -> AfterHandshakeOutcome {
            if conn.side() == Side::Client
                || conn.alpn() == ALPN
                || self.admitted.is_admitted(&conn.remote_id())
            {
                AfterHandshakeOutcome::Accept
            } else {
                AfterHandshakeOutcome::Reject {
                    error_code: DENIED.into(),
                    reason: b"not authenticated".to_vec(),
                }
            }
        }
    }

    pub struct Task {
        token: Vec<u8>,
        rx: mpsc::Receiver<PreAuth>,
    }

    impl Task {
        pub fn spawn(self, endpoint: Endpoint) {
            tokio::spawn(self.run(endpoint));
        }
        async fn run(mut self, endpoint: Endpoint) {
            let mut ok: HashMap<EndpointId, Instant> = HashMap::new();
            while let Some((remote, reply)) = self.rx.recv().await {
                if ok
                    .get(&remote.id)
                    .is_some_and(|t| t.elapsed() < ADMISSION - Duration::from_secs(30))
                {
                    reply.send(true).ok();
                    continue;
                }
                let res = Self::handshake(&endpoint, remote.clone(), &self.token).await;
                match &res {
                    Ok(()) => {
                        ok.insert(remote.id, Instant::now());
                    }
                    Err(e) => println!("   pre-auth to {} failed: {e:#}", remote.id.fmt_short()),
                }
                reply.send(res.is_ok()).ok();
            }
        }
        async fn handshake(endpoint: &Endpoint, remote: EndpointAddr, token: &[u8]) -> Result<()> {
            let conn = endpoint.connect(remote, ALPN).await?;
            let mut send = conn.open_uni().await?;
            send.write_all(token).await?;
            send.finish()?;
            match timeout(Duration::from_secs(10), conn.closed()).await? {
                ConnectionError::ApplicationClosed(c)
                    if c.error_code.into_inner() as u32 == ACCEPTED =>
                {
                    Ok(())
                }
                ConnectionError::ApplicationClosed(c)
                    if c.error_code.into_inner() as u32 == DENIED =>
                {
                    bail!("denied by remote")
                }
                other => bail!("unexpected close: {other}"),
            }
        }
    }

    #[derive(Debug, Clone)]
    pub struct Protocol {
        admitted: Arc<Admitted>,
        root: PublicKey,
        vault: String,
    }

    impl Protocol {
        fn verify(&self, token: &[u8], remote: EndpointId) -> Result<()> {
            let token = Biscuit::from(token, self.root)?;
            let mut authorizer = authorizer!(
                r#"
                endpoint({endpoint});
                time({now});
                check if vault({vault});
                allow if right("sync");
                "#,
                endpoint = remote.to_string(),
                now = std::time::SystemTime::now(),
                vault = self.vault.as_str(),
            )
            .build(&token)?;
            authorizer.authorize()?;
            Ok(())
        }
    }

    impl ProtocolHandler for Protocol {
        async fn accept(&self, conn: Connection) -> std::result::Result<(), AcceptError> {
            let remote = conn.remote_id();
            let mut recv = conn.accept_uni().await?;
            let token = match timeout(Duration::from_secs(10), recv.read_to_end(MAX_TOKEN)).await {
                Ok(Ok(t)) => t,
                Ok(Err(e)) => {
                    conn.close(DENIED.into(), b"bad token");
                    return Err(AcceptError::from_err(e));
                }
                Err(_) => {
                    conn.close(DENIED.into(), b"timeout");
                    return Ok(());
                }
            };
            match self.verify(&token, remote) {
                Ok(()) => {
                    self.admitted.admit(remote);
                    conn.close(ACCEPTED.into(), b"ok");
                }
                Err(e) => {
                    println!(
                        "   server rejected token from {}: {e:#}",
                        remote.fmt_short()
                    );
                    conn.close(DENIED.into(), b"rejected");
                }
            }
            Ok(())
        }
    }

    pub fn build(cfg: Config) -> (Hook, Task, Protocol) {
        let admitted = Arc::new(Admitted::default());
        let (tx, rx) = mpsc::channel(16);
        (
            Hook {
                admitted: admitted.clone(),
                tx,
            },
            Task {
                token: cfg.token,
                rx,
            },
            Protocol {
                admitted,
                root: cfg.root,
                vault: cfg.vault,
            },
        )
    }
}

async fn phase_c(root: &Path) -> Result<()> {
    use biscuit_auth::macros::{biscuit, block};
    use biscuit_auth::KeyPair;
    println!("== C. auth hook ==");
    let root_key = KeyPair::new();
    let vault = "vault-spike".to_string();
    let authority =
        biscuit!(r#"vault({vault}); right("sync");"#, vault = vault.as_str()).build(&root_key)?;
    let mint = |id: EndpointId, ttl: Duration| -> Result<Vec<u8>> {
        Ok(authority
            .append(block!(
                r#"check if endpoint($e), $e == {aud}; check if time($t), $t < {exp};"#,
                aud = id.to_string(),
                exp = std::time::SystemTime::now() + ttl,
            ))?
            .to_vec()?)
    };
    let sk_s = SecretKey::from_bytes(&[21u8; 32]);
    let sk_ok = SecretKey::from_bytes(&[22u8; 32]);
    let sk_none = SecretKey::from_bytes(&[23u8; 32]);
    let sk_bad = SecretKey::from_bytes(&[24u8; 32]);
    let sk_exp = SecretKey::from_bytes(&[25u8; 32]);
    let cfg = |token: Vec<u8>| auth::Config {
        token,
        root: root_key.public(),
        vault: vault.clone(),
    };

    let server = Node::spawn(
        &root.join("c-server"),
        sk_s.clone(),
        Some(cfg(mint(sk_s.public(), Duration::from_secs(3600))?)),
    )
    .await?;
    let author = server.docs.author_create().await?;
    let doc = server.docs.create().await?;
    doc.set_bytes(author, "k", "v").await?;
    let ticket = doc
        .share(ShareMode::Write, AddrInfoOptions::Addresses)
        .await?;

    // Good client.
    let good = Node::spawn(
        &root.join("c-good"),
        sk_ok.clone(),
        Some(cfg(mint(sk_ok.public(), Duration::from_secs(3600))?)),
    )
    .await?;
    let (doc_good, mut ev) = good.docs.import_and_subscribe(ticket.clone()).await?;
    let hash = wait_for_key(&mut ev, b"k").await?;
    assert_eq!(&good.store().get_bytes(hash).await?[..], b"v");
    println!("good client synced through the auth hook");
    // Reverse direction: the server must pre-auth to the good client too.
    let author_g = good.docs.author_create().await?;
    let mut ev_s = doc.subscribe().await?;
    doc_good.set_bytes(author_g, "k2", "v2").await?;
    let hash = wait_for_key(&mut ev_s, b"k2").await?;
    assert_eq!(&server.store().get_bytes(hash).await?[..], b"v2");
    println!("server received entry from good client (both directions gated)");

    // Client without hooks: direct connection attempts to each ALPN.
    let none = Node::spawn(&root.join("c-none"), sk_none.clone(), None).await?;
    for alpn in [DOCS_ALPN, BLOBS_ALPN, GOSSIP_ALPN] {
        let res = none.endpoint.connect(server.addr(), alpn).await;
        let outcome = match res {
            Ok(conn) => {
                // The server closes with 403 right after the handshake; opening a stream fails.
                let closed = timeout(Duration::from_secs(5), conn.closed()).await;
                format!("connected then closed: {:?}", closed.map(|c| c.to_string()))
            }
            Err(e) => format!("connect error: {e}"),
        };
        println!("no-auth -> {}: {outcome}", String::from_utf8_lossy(alpn));
    }
    let (doc_none, _ev) = none.docs.import_and_subscribe(ticket.clone()).await?;
    tokio::time::sleep(Duration::from_secs(3)).await;
    let got = doc_none.get_one(Query::all().key_exact("k")).await?;
    println!("no-auth client got entry k after 3 s: {}", got.is_some());
    assert!(got.is_none());

    // Client with a token for another endpoint.
    let bad = Node::spawn(
        &root.join("c-bad"),
        sk_bad.clone(),
        Some(cfg(mint(sk_none.public(), Duration::from_secs(3600))?)),
    )
    .await?;
    let (doc_bad, _ev) = bad.docs.import_and_subscribe(ticket.clone()).await?;
    tokio::time::sleep(Duration::from_secs(3)).await;
    let got = doc_bad.get_one(Query::all().key_exact("k")).await?;
    println!(
        "wrong-audience client got entry k after 3 s: {}",
        got.is_some()
    );
    assert!(got.is_none());

    // Client with an expired token.
    let exp = Node::spawn(
        &root.join("c-exp"),
        sk_exp.clone(),
        Some(cfg(mint(sk_exp.public(), Duration::from_secs(0))?)),
    )
    .await?;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let (doc_exp, _ev) = exp.docs.import_and_subscribe(ticket.clone()).await?;
    tokio::time::sleep(Duration::from_secs(3)).await;
    let got = doc_exp.get_one(Query::all().key_exact("k")).await?;
    println!(
        "expired-token client got entry k after 3 s: {}",
        got.is_some()
    );
    assert!(got.is_none());

    // The good client still works after all that.
    doc.set_bytes(author, "k3", "v3").await?;
    wait_for_key(&mut ev, b"k3").await?;
    println!("good client still syncing");

    server.shutdown().await?;
    good.shutdown().await?;
    none.shutdown().await?;
    bad.shutdown().await?;
    exp.shutdown().await?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let root = tempfile::tempdir()?;
    let which = std::env::args().nth(1).unwrap_or_else(|| "abc".into());
    if which.contains('a') {
        phase_a(root.path()).await?;
    }
    if which.contains('b') {
        phase_b(root.path()).await?;
    }
    if which.contains('c') {
        phase_c(root.path()).await?;
    }
    println!("OK");
    Ok(())
}
