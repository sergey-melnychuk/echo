//! Iroh endpoint and router, the sync protocol handler and the client
//! connection pool.
//!
//! The server side ([`SyncProtocol`]) serves `GetChunk`, `GetManifest`,
//! `GetHeads` and `GetVersion` over one bidirectional QUIC stream per request.
//! Every stream carries its own token, verified against the owner key
//! configured for the document (SEC-1) and bound to the connection's
//! authenticated `EndpointId` (SEC-2). Chunks are served only if a committed
//! manifest of the document references them (SEC-3). Frame lengths are
//! checked before allocation (SEC-7) and errors are coarse codes (SEC-10).

use crate::capabilities::{CapabilityToken, Permission};
use crate::clock::unix_now_secs;
use crate::crypto::short_hex;
use crate::gossip::SyncMessage;
use crate::manifest::FileManifest;
use crate::protocol::{
    self, ErrorCode, ProtocolError, Request, Response, ALPN, CHUNK_PAYLOAD_LIMIT, CONNECT_TIMEOUT,
    FRAME_READ_TIMEOUT, IDLE_TIMEOUT, MAX_CONNECTIONS, MAX_CONNECTIONS_PER_PEER, MAX_HEADS,
    MAX_STREAMS_PER_CONNECTION, REQUEST_FRAME_LIMIT, REQUEST_TIMEOUT, RESPONSE_FRAME_LIMIT,
};
use crate::storage::{Store, StoreError};
use crate::{Hash, VersionId};
use iroh::address_lookup::memory::MemoryLookup;
use iroh::endpoint::{presets, Connection, QuicTransportConfig, RecvStream, SendStream, VarInt};
use iroh::protocol::{AcceptError, ProtocolHandler, Router, RouterBuilder};
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayMode, SecretKey};
use parking_lot::{Mutex, RwLock};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::timeout;
use tracing::{debug, warn};

/// Application error code used when a stream or connection is refused.
const REFUSED_CODE: u32 = 1;

/// Transport failures. Codes returned by a peer surface as [`TransportError::Remote`].
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    /// Framing or encoding failed.
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    /// Binding or configuring the endpoint failed.
    #[error("endpoint error: {0}")]
    Endpoint(String),
    /// Connecting to a peer failed.
    #[error("connect failed: {0}")]
    Connect(String),
    /// Opening or using a stream failed.
    #[error("stream failed: {0}")]
    Stream(String),
    /// The request did not complete within [`REQUEST_TIMEOUT`].
    #[error("request timed out")]
    Timeout,
    /// The peer answered with an error code.
    #[error("peer returned {0}")]
    Remote(ErrorCode),
    /// The peer answered with a response of the wrong variant.
    #[error("unexpected response variant")]
    UnexpectedResponse,
    /// A chunk response exceeded [`CHUNK_PAYLOAD_LIMIT`].
    #[error("chunk payload of {0} bytes exceeds the limit")]
    ChunkTooLarge(usize),
}

// ---------------------------------------------------------------------------
// Endpoint
// ---------------------------------------------------------------------------

/// How to bind the iroh endpoint.
#[derive(Debug, Clone)]
pub struct EndpointOptions {
    /// This node's identity.
    pub secret_key: SecretKey,
    /// Use iroh's n0 preset (default relays and pkarr address lookup). Tests
    /// set `false`, which disables relays and uses only the in-memory
    /// address book.
    pub production: bool,
    /// Explicit IPv4 bind address. `None` binds all interfaces on a random port.
    pub bind_addr: Option<SocketAddrV4>,
}

impl EndpointOptions {
    /// Loopback only, relay disabled, random port: hermetic tests.
    pub fn loopback(secret_key: SecretKey) -> Self {
        EndpointOptions {
            secret_key,
            production: false,
            bind_addr: Some(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        }
    }

    /// Default relays, address lookup and all interfaces: real use.
    pub fn production(secret_key: SecretKey) -> Self {
        EndpointOptions {
            secret_key,
            production: true,
            bind_addr: None,
        }
    }
}

/// A bound endpoint plus the in-memory address book that peers learned from
/// invites or tests are entered into, so they can be dialed by ID.
#[derive(Debug, Clone)]
pub struct BoundEndpoint {
    /// The endpoint.
    pub endpoint: Endpoint,
    /// Address book consulted when dialing by `EndpointId`.
    pub addr_book: MemoryLookup,
}

impl BoundEndpoint {
    /// Make `addr` dialable by ID.
    pub fn add_addr(&self, addr: EndpointAddr) {
        self.addr_book.add_endpoint_info(addr);
    }
}

/// QUIC transport limits from section 6: concurrent bidirectional streams and
/// the idle timeout.
pub fn transport_config() -> QuicTransportConfig {
    let idle_ms = u32::try_from(IDLE_TIMEOUT.as_millis()).unwrap_or(u32::MAX);
    QuicTransportConfig::builder()
        .max_concurrent_bidi_streams(VarInt::from_u32(MAX_STREAMS_PER_CONNECTION))
        .max_idle_timeout(Some(VarInt::from_u32(idle_ms).into()))
        .build()
}

/// Bind an endpoint with the sync ALPN. The router later replaces the ALPN
/// list with every registered protocol.
pub async fn bind_endpoint(opts: EndpointOptions) -> Result<BoundEndpoint, TransportError> {
    let addr_book = MemoryLookup::new();
    let mut builder = if opts.production {
        Endpoint::builder(presets::N0)
    } else {
        Endpoint::builder(presets::Minimal).relay_mode(RelayMode::Disabled)
    };
    builder = builder
        .secret_key(opts.secret_key)
        .address_lookup(addr_book.clone())
        .transport_config(transport_config())
        .alpns(vec![ALPN.to_vec()]);
    if let Some(addr) = opts.bind_addr {
        builder = builder
            .clear_ip_transports()
            .bind_addr(addr)
            .map_err(|e| TransportError::Endpoint(e.to_string()))?;
    }
    let endpoint = builder
        .bind()
        .await
        .map_err(|e| TransportError::Endpoint(e.to_string()))?;
    Ok(BoundEndpoint {
        endpoint,
        addr_book,
    })
}

/// A router builder with the sync protocol registered. Callers add further
/// protocols (gossip, stage 6) and call `spawn()`.
pub fn router_builder(endpoint: Endpoint, sync: SyncProtocol) -> RouterBuilder {
    Router::builder(endpoint).accept(ALPN, sync)
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

/// Counters exposed so tests can assert how much was transferred and how
/// many requests were refused, without parsing logs.
#[derive(Debug, Default)]
pub struct ServerMetrics {
    /// Connections accepted into the handler loop.
    pub connections_accepted: AtomicU64,
    /// Connections closed for exceeding the total or per-peer limit.
    pub connections_refused: AtomicU64,
    /// Request frames rejected for exceeding the request limit (SEC-7).
    pub oversize_frames: AtomicU64,
    /// Requests that reached dispatch.
    pub requests: AtomicU64,
    /// `Chunk` responses.
    pub chunks_served: AtomicU64,
    /// `Manifest` responses.
    pub manifests_served: AtomicU64,
    /// `Heads` responses.
    pub heads_served: AtomicU64,
    /// `Version` responses.
    pub versions_served: AtomicU64,
    /// `Unauthorized` responses.
    pub unauthorized: AtomicU64,
    /// `Forbidden` responses.
    pub forbidden: AtomicU64,
    /// `NotFound` responses.
    pub not_found: AtomicU64,
    /// `BadRequest` responses.
    pub bad_request: AtomicU64,
    /// `Busy` responses.
    pub busy: AtomicU64,
    /// `Internal` responses.
    pub internal: AtomicU64,
}

impl ServerMetrics {
    fn record(&self, response: &Response) {
        let counter = match response {
            Response::Chunk(_) => &self.chunks_served,
            Response::Manifest(_) => &self.manifests_served,
            Response::Heads(_) => &self.heads_served,
            Response::Version(_) => &self.versions_served,
            Response::Error(code) => self.error_counter(*code),
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// The counter for one error code.
    pub fn error_counter(&self, code: ErrorCode) -> &AtomicU64 {
        match code {
            ErrorCode::Unauthorized => &self.unauthorized,
            ErrorCode::Forbidden => &self.forbidden,
            ErrorCode::NotFound => &self.not_found,
            ErrorCode::BadRequest => &self.bad_request,
            ErrorCode::Busy => &self.busy,
            ErrorCode::Internal => &self.internal,
        }
    }

    /// Convenience read of one counter.
    pub fn get(counter: &AtomicU64) -> u64 {
        counter.load(Ordering::Relaxed)
    }
}

#[derive(Default)]
struct ConnCounts {
    total: usize,
    per_peer: HashMap<EndpointId, usize>,
}

/// Decrements the connection counters when a connection ends.
struct ConnGuard {
    inner: Arc<Inner>,
    peer: EndpointId,
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        let mut c = self.inner.conns.lock();
        c.total = c.total.saturating_sub(1);
        if let Some(n) = c.per_peer.get_mut(&self.peer) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                c.per_peer.remove(&self.peer);
            }
        }
    }
}

/// The server side of the sync protocol. One instance serves every document
/// registered with [`SyncProtocol::add_document`]. Cloning shares state.
#[derive(Clone)]
pub struct SyncProtocol {
    inner: Arc<Inner>,
}

struct Inner {
    store: Arc<dyn Store>,
    /// Document ID to the owner public key that must have issued every token
    /// for it (SEC-1).
    docs: RwLock<HashMap<Hash, [u8; 32]>>,
    metrics: ServerMetrics,
    conns: Mutex<ConnCounts>,
}

impl std::fmt::Debug for SyncProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SyncProtocol")
            .field("docs", &self.inner.docs.read().len())
            .finish_non_exhaustive()
    }
}

impl SyncProtocol {
    /// A handler over `store` with no documents registered yet.
    pub fn new(store: Arc<dyn Store>) -> Self {
        SyncProtocol {
            inner: Arc::new(Inner {
                store,
                docs: RwLock::new(HashMap::new()),
                metrics: ServerMetrics::default(),
                conns: Mutex::new(ConnCounts::default()),
            }),
        }
    }

    /// Serve `doc_id`, trusting only tokens issued by `owner_key`.
    pub fn add_document(&self, doc_id: Hash, owner_key: [u8; 32]) {
        self.inner.docs.write().insert(doc_id, owner_key);
    }

    /// The owner key configured for a document, if any.
    pub fn owner_key(&self, doc_id: &Hash) -> Option<[u8; 32]> {
        self.inner.docs.read().get(doc_id).copied()
    }

    /// Counters for tests and `status`.
    pub fn metrics(&self) -> &ServerMetrics {
        &self.inner.metrics
    }

    /// The store this handler serves from.
    pub fn store(&self) -> &Arc<dyn Store> {
        &self.inner.store
    }
}

impl Inner {
    fn try_register(self: &Arc<Self>, peer: EndpointId) -> Option<ConnGuard> {
        let mut c = self.conns.lock();
        let per_peer = c.per_peer.get(&peer).copied().unwrap_or(0);
        if c.total >= MAX_CONNECTIONS || per_peer >= MAX_CONNECTIONS_PER_PEER {
            return None;
        }
        c.total += 1;
        c.per_peer.insert(peer, per_peer + 1);
        Some(ConnGuard {
            inner: Arc::clone(self),
            peer,
        })
    }

    /// Serve streams on `connection` until the peer closes it.
    async fn handle_connection(self: Arc<Self>, connection: Connection) {
        let peer = connection.remote_id();
        let Some(_guard) = self.try_register(peer) else {
            self.metrics
                .connections_refused
                .fetch_add(1, Ordering::Relaxed);
            debug!(peer = %peer.fmt_short(), "connection refused: limit reached");
            connection.close(VarInt::from_u32(REFUSED_CODE), b"busy");
            return;
        };
        self.metrics
            .connections_accepted
            .fetch_add(1, Ordering::Relaxed);
        let streams = Arc::new(Semaphore::new(MAX_STREAMS_PER_CONNECTION as usize));
        let peer_bytes = *peer.as_bytes();
        loop {
            let (send, recv) = match connection.accept_bi().await {
                Ok(s) => s,
                Err(e) => {
                    debug!(peer = %peer.fmt_short(), "connection ended: {e}");
                    break;
                }
            };
            let permit = Arc::clone(&streams).try_acquire_owned().ok();
            let this = Arc::clone(&self);
            tokio::spawn(async move {
                if timeout(
                    REQUEST_TIMEOUT,
                    this.handle_stream(peer_bytes, send, recv, permit),
                )
                .await
                .is_err()
                {
                    debug!("request timed out");
                }
            });
        }
    }

    async fn handle_stream(
        &self,
        peer: [u8; 32],
        mut send: SendStream,
        mut recv: RecvStream,
        permit: Option<OwnedSemaphorePermit>,
    ) {
        let frame = match timeout(
            FRAME_READ_TIMEOUT,
            protocol::read_frame(&mut recv, REQUEST_FRAME_LIMIT),
        )
        .await
        {
            Ok(Ok(frame)) => frame,
            Ok(Err(ProtocolError::FrameTooLarge { len, limit })) => {
                // SEC-7: reset without a response and without allocating.
                self.metrics.oversize_frames.fetch_add(1, Ordering::Relaxed);
                debug!(len, limit, "oversize request frame; resetting stream");
                let _ = recv.stop(VarInt::from_u32(REFUSED_CODE));
                let _ = send.reset(VarInt::from_u32(REFUSED_CODE));
                return;
            }
            Ok(Err(e)) => {
                debug!("request frame read failed: {e}");
                let _ = send.reset(VarInt::from_u32(REFUSED_CODE));
                return;
            }
            Err(_) => {
                debug!("request frame read timed out");
                let _ = send.reset(VarInt::from_u32(REFUSED_CODE));
                return;
            }
        };
        let response = if permit.is_none() {
            Response::Error(ErrorCode::Busy)
        } else {
            match protocol::decode::<Request>(&frame, REQUEST_FRAME_LIMIT) {
                Ok(req) => self.dispatch(req, &peer).await,
                Err(e) => {
                    debug!("request decode failed: {e}");
                    Response::Error(ErrorCode::BadRequest)
                }
            }
        };
        self.metrics.record(&response);
        let bytes = match protocol::encode(&response, RESPONSE_FRAME_LIMIT) {
            Ok(b) => b,
            Err(e) => {
                warn!("response encode failed: {e}");
                match protocol::encode(&Response::Error(ErrorCode::Internal), RESPONSE_FRAME_LIMIT)
                {
                    Ok(b) => b,
                    Err(_) => return,
                }
            }
        };
        if let Err(e) = protocol::write_frame(&mut send, &bytes, RESPONSE_FRAME_LIMIT).await {
            debug!("response write failed: {e}");
            return;
        }
        if send.finish().is_ok() {
            // Keep the stream (and its permit) until the peer has read it.
            let _ = send.stopped().await;
        }
    }

    /// Steps 3 to 5 of the per-stream behavior in section 6.
    async fn dispatch(&self, req: Request, peer: &[u8; 32]) -> Response {
        self.metrics.requests.fetch_add(1, Ordering::Relaxed);
        let doc_id = *req.doc_id();
        let Some(owner) = self.docs.read().get(&doc_id).copied() else {
            debug!(doc = %short_hex(&doc_id), "request for unknown document");
            return Response::Error(ErrorCode::Unauthorized);
        };
        if let Err(e) = req.token().verify(&owner, unix_now_secs()) {
            debug!(doc = %short_hex(&doc_id), kind = req.kind(), "token rejected: {e}");
            return Response::Error(ErrorCode::Unauthorized);
        }
        if let Err(e) = req.token().authorize(&doc_id, peer, Permission::Read) {
            debug!(doc = %short_hex(&doc_id), kind = req.kind(), "not authorized: {e}");
            return Response::Error(ErrorCode::Forbidden);
        }
        let store = Arc::clone(&self.store);
        let result = tokio::task::spawn_blocking(move || -> Result<Response, StoreError> {
            match req {
                Request::GetChunk { hash, .. } => {
                    if !store.doc_has_chunk(&doc_id, &hash)? {
                        return Ok(Response::Error(ErrorCode::NotFound));
                    }
                    Ok(match store.get_chunk(&hash)? {
                        Some(bytes) => Response::Chunk(bytes),
                        None => Response::Error(ErrorCode::NotFound),
                    })
                }
                Request::GetManifest { manifest_id, .. } => {
                    Ok(match store.get_manifest(&doc_id, &manifest_id)? {
                        Some(m) => Response::Manifest(m),
                        None => Response::Error(ErrorCode::NotFound),
                    })
                }
                Request::GetHeads { .. } => {
                    let mut heads = store.heads(&doc_id)?;
                    heads.truncate(MAX_HEADS);
                    Ok(Response::Heads(heads))
                }
                Request::GetVersion { version_id, .. } => {
                    Ok(match store.version(&doc_id, &version_id)? {
                        Some(v) => Response::Version(v),
                        None => Response::Error(ErrorCode::NotFound),
                    })
                }
            }
        })
        .await;
        match result {
            Ok(Ok(response)) => response,
            Ok(Err(e)) => {
                warn!("storage error while serving: {e}");
                Response::Error(ErrorCode::Internal)
            }
            Err(e) => {
                warn!("serving task failed: {e}");
                Response::Error(ErrorCode::Internal)
            }
        }
    }
}

impl ProtocolHandler for SyncProtocol {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        Arc::clone(&self.inner).handle_connection(connection).await;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/// One pooled connection per peer. Connections that closed (for example on
/// idle timeout) are replaced on the next use. Peers are dialed by ID, so
/// their addresses must be in the endpoint's address book.
pub struct ConnectionPool {
    endpoint: Endpoint,
    conns: Mutex<HashMap<EndpointId, Connection>>,
}

impl ConnectionPool {
    /// A pool dialing from `endpoint`.
    pub fn new(endpoint: Endpoint) -> Self {
        ConnectionPool {
            endpoint,
            conns: Mutex::new(HashMap::new()),
        }
    }

    /// The endpoint this pool dials from.
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// An open connection to `peer`, reusing the pooled one if it is alive.
    pub async fn connect(&self, peer: EndpointId) -> Result<Connection, TransportError> {
        if let Some(c) = self.conns.lock().get(&peer) {
            if c.close_reason().is_none() {
                return Ok(c.clone());
            }
        }
        let conn = match timeout(
            CONNECT_TIMEOUT,
            self.endpoint.connect(EndpointAddr::new(peer), ALPN),
        )
        .await
        {
            Ok(Ok(c)) => c,
            Ok(Err(e)) => return Err(TransportError::Connect(e.to_string())),
            Err(_) => return Err(TransportError::Connect("connect timed out".into())),
        };
        let mut guard = self.conns.lock();
        match guard.get(&peer) {
            Some(existing) if existing.close_reason().is_none() => {
                conn.close(VarInt::from_u32(0), b"duplicate");
                Ok(existing.clone())
            }
            _ => {
                guard.insert(peer, conn.clone());
                Ok(conn)
            }
        }
    }

    /// Drop the pooled connection to `peer`, closing it.
    pub fn evict(&self, peer: &EndpointId) {
        if let Some(c) = self.conns.lock().remove(peer) {
            c.close(VarInt::from_u32(0), b"evicted");
        }
    }

    /// Close every pooled connection.
    pub fn close_all(&self) {
        let conns: Vec<Connection> = self.conns.lock().drain().map(|(_, c)| c).collect();
        for c in conns {
            c.close(VarInt::from_u32(0), b"closing");
        }
    }
}

/// Send one request on a fresh stream and read the response, within
/// [`REQUEST_TIMEOUT`].
pub async fn request(conn: &Connection, req: &Request) -> Result<Response, TransportError> {
    let fut = async {
        let (mut send, mut recv) = conn
            .open_bi()
            .await
            .map_err(|e| TransportError::Stream(e.to_string()))?;
        let bytes = protocol::encode(req, REQUEST_FRAME_LIMIT)?;
        protocol::write_frame(&mut send, &bytes, REQUEST_FRAME_LIMIT).await?;
        send.finish()
            .map_err(|e| TransportError::Stream(e.to_string()))?;
        let frame = protocol::read_frame(&mut recv, RESPONSE_FRAME_LIMIT).await?;
        let response: Response = protocol::decode(&frame, RESPONSE_FRAME_LIMIT)?;
        Ok(response)
    };
    match timeout(REQUEST_TIMEOUT, fut).await {
        Ok(r) => r,
        Err(_) => Err(TransportError::Timeout),
    }
}

fn expect_ok(response: Response) -> Result<Response, TransportError> {
    match response {
        Response::Error(code) => Err(TransportError::Remote(code)),
        other => Ok(other),
    }
}

/// Fetch a chunk. The bytes are not yet verified against `hash`; the caller
/// (the fetcher, and `Store::put_chunk`) does that (SEC-8).
pub async fn get_chunk(
    conn: &Connection,
    token: &CapabilityToken,
    doc_id: Hash,
    hash: Hash,
) -> Result<Vec<u8>, TransportError> {
    let req = Request::GetChunk {
        token: token.clone(),
        doc_id,
        hash,
    };
    match expect_ok(request(conn, &req).await?)? {
        Response::Chunk(bytes) if bytes.len() > CHUNK_PAYLOAD_LIMIT => {
            Err(TransportError::ChunkTooLarge(bytes.len()))
        }
        Response::Chunk(bytes) => Ok(bytes),
        _ => Err(TransportError::UnexpectedResponse),
    }
}

/// Fetch a manifest. The caller recomputes its ID and validates it (SEC-8).
pub async fn get_manifest(
    conn: &Connection,
    token: &CapabilityToken,
    doc_id: Hash,
    manifest_id: Hash,
) -> Result<FileManifest, TransportError> {
    let req = Request::GetManifest {
        token: token.clone(),
        doc_id,
        manifest_id,
    };
    match expect_ok(request(conn, &req).await?)? {
        Response::Manifest(m) => Ok(m),
        _ => Err(TransportError::UnexpectedResponse),
    }
}

/// Fetch the latest signed `NewVersion` per file. Each entry must be
/// validated like a live announcement.
pub async fn get_heads(
    conn: &Connection,
    token: &CapabilityToken,
    doc_id: Hash,
) -> Result<Vec<SyncMessage>, TransportError> {
    let req = Request::GetHeads {
        token: token.clone(),
        doc_id,
    };
    match expect_ok(request(conn, &req).await?)? {
        Response::Heads(h) => Ok(h),
        _ => Err(TransportError::UnexpectedResponse),
    }
}

/// Fetch one stored signed `NewVersion`. Must be validated like a live
/// announcement.
pub async fn get_version(
    conn: &Connection,
    token: &CapabilityToken,
    doc_id: Hash,
    version_id: VersionId,
) -> Result<SyncMessage, TransportError> {
    let req = Request::GetVersion {
        token: token.clone(),
        doc_id,
        version_id,
    };
    match expect_ok(request(conn, &req).await?)? {
        Response::Version(v) => Ok(v),
        _ => Err(TransportError::UnexpectedResponse),
    }
}
