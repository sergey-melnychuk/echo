//! Admission (SPEC.md section 5.4): Biscuit capability tokens enforced by an
//! iroh endpoint hook, adapted from iroh's `auth-hook` example.
//!
//! Every node runs the same three parts:
//!
//! - [`AuthHook`]: `before_connect` pre-authenticates to a remote over the
//!   auth ALPN before any other connection to it is opened; `after_handshake`
//!   rejects incoming connections on every other ALPN unless the remote
//!   presented a valid token within the admission window (SEC-1).
//! - [`AuthTask`]: owns an `Endpoint` clone and performs the outgoing
//!   handshakes, one at a time per remote.
//! - [`AuthProtocol`]: accepts auth connections, reads one token of at most
//!   4 KiB within 10 s, at most 16 at a time (SEC-3), verifies it (SEC-2) and
//!   closes the connection with code 1 (accepted) or 403 (denied).
//!
//! Tokens are never logged (SEC-5).

use std::collections::{hash_map::Entry, HashMap};
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use anyhow::{anyhow, bail, Context, Result};
use biscuit_auth::builder::Algorithm;
use biscuit_auth::macros::{authorizer, biscuit, block};
use biscuit_auth::{Biscuit, KeyPair, PrivateKey, PublicKey};
use iroh::endpoint::{
    AfterHandshakeOutcome, BeforeConnectOutcome, Connection, ConnectionError, EndpointHooks, Side,
};
use iroh::protocol::{AcceptError, ProtocolHandler};
use iroh::{Endpoint, EndpointAddr, EndpointId};
use tokio::sync::{mpsc, oneshot, Semaphore};
use tokio::task::{JoinHandle, JoinSet};

pub const ALPN: &[u8] = b"vaultsync/auth/0";
/// SEC-3: the largest token accepted.
pub const MAX_TOKEN_BYTES: usize = 4096;
/// SEC-3: how long one handshake may take.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// SEC-3: incoming handshakes served at once; more are refused.
pub const MAX_IN_FLIGHT: usize = 16;
/// SEC-1: how long a verified token admits its endpoint.
pub const ADMISSION_TTL: Duration = Duration::from_secs(600);
/// How long the outgoing side skips the handshake to a remote it just
/// authenticated to. Short on purpose: a remote that restarts forgets whom
/// it admitted, and a stale cache would make every connection to it fail
/// with 403 until the cache expired (NOTES.md, stage 5).
pub const OUTGOING_CACHE_TTL: Duration = Duration::from_secs(3);

const CLOSE_ACCEPTED: u32 = 1;
const CLOSE_DENIED: u32 = 403;

/// What a node needs to admit peers and to be admitted.
#[derive(Clone)]
pub struct AuthConfig {
    /// This device's own token, presented to every remote.
    pub token: Vec<u8>,
    /// The vault's Biscuit root public key.
    pub root: PublicKey,
    /// The vault id the token must name.
    pub vault_id: String,
    pub handshake_timeout: Duration,
    pub max_in_flight: usize,
    pub admission_ttl: Duration,
}

impl AuthConfig {
    pub fn new(token: Vec<u8>, root: PublicKey, vault_id: String) -> Self {
        Self {
            token,
            root,
            vault_id,
            handshake_timeout: HANDSHAKE_TIMEOUT,
            max_in_flight: MAX_IN_FLIGHT,
            admission_ttl: ADMISSION_TTL,
        }
    }
}

impl fmt::Debug for AuthConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthConfig")
            .field("token", &format_args!("<{} bytes>", self.token.len()))
            .field("root", &public_to_hex(&self.root))
            .field("vault_id", &self.vault_id)
            .finish_non_exhaustive()
    }
}

// --- keys and tokens -------------------------------------------------------

pub fn generate_root() -> KeyPair {
    KeyPair::new()
}

pub fn root_to_bytes(root: &KeyPair) -> Vec<u8> {
    root.private().to_bytes().to_vec()
}

pub fn root_from_bytes(bytes: &[u8]) -> Result<KeyPair> {
    let private =
        PrivateKey::from_bytes(bytes, Algorithm::Ed25519).context("Biscuit root private key")?;
    Ok(KeyPair::from(&private))
}

pub fn public_to_hex(key: &PublicKey) -> String {
    key.to_bytes_hex()
}

pub fn public_from_hex(hex: &str) -> Result<PublicKey> {
    PublicKey::from_bytes_hex(hex.trim(), Algorithm::Ed25519)
        .map_err(|err| anyhow!("Biscuit root public key: {err}"))
}

/// The authority block: this vault, the right to sync.
pub fn mint_authority(root: &KeyPair, vault_id: &str) -> Result<Biscuit> {
    biscuit!(
        r#"
        vault({vault_id});
        right("sync");
        "#,
        vault_id = vault_id,
    )
    .build(root)
    .map_err(|err| anyhow!("minting the authority token: {err}"))
}

/// Attenuate `token` with an expiry and, when given, an audience. Checks
/// accumulate, so a token that already has an audience cannot be re-bound
/// to another endpoint (NOTES.md, stage 0).
pub fn attenuate(
    token: &Biscuit,
    audience: Option<&EndpointId>,
    expires: SystemTime,
) -> Result<Biscuit> {
    let block = match audience {
        Some(id) => block!(
            r#"
            check if endpoint($e), $e == {audience};
            check if time($t), $t < {expires};
            "#,
            audience = id.to_string(),
            expires = expires,
        ),
        None => block!(r#"check if time($t), $t < {expires};"#, expires = expires,),
    };
    token
        .append(block)
        .map_err(|err| anyhow!("attenuating the token: {err}"))
}

/// Parse and verify the signature chain of a token under `root`.
pub fn parse_token(bytes: &[u8], root: &PublicKey) -> Result<Biscuit> {
    Biscuit::from(bytes, *root).map_err(|err| anyhow!("token does not verify: {err}"))
}

/// SEC-2: the receiver's side of a token.
#[derive(Debug, Clone)]
pub struct Verifier {
    root: PublicKey,
    vault_id: String,
}

impl Verifier {
    pub fn new(root: PublicKey, vault_id: String) -> Self {
        Self { root, vault_id }
    }

    /// Accept `token` from `remote` at `now`: it must verify under the root
    /// key, name this vault, carry the sync right in its authority block, and
    /// pass every check (audience, expiry).
    pub fn verify(&self, token: &[u8], remote: &EndpointId, now: SystemTime) -> Result<()> {
        if token.len() > MAX_TOKEN_BYTES {
            bail!("token of {} bytes exceeds {MAX_TOKEN_BYTES}", token.len());
        }
        let token = parse_token(token, &self.root)?;
        let mut authorizer = authorizer!(
            r#"
            endpoint({endpoint});
            time({now});
            check if vault({vault_id});
            allow if right("sync");
            "#,
            endpoint = remote.to_string(),
            now = now,
            vault_id = self.vault_id.as_str(),
        )
        .build(&token)
        .map_err(|err| anyhow!("building the authorizer: {err}"))?;
        authorizer
            .authorize()
            .map_err(|err| anyhow!("token refused: {err}"))?;
        Ok(())
    }
}

// --- admitted set ------------------------------------------------------------

/// Remotes that presented a valid token, with the time they did.
#[derive(Debug, Default)]
struct Admitted {
    remotes: Mutex<HashMap<EndpointId, Instant>>,
}

impl Admitted {
    fn is_admitted(&self, id: &EndpointId, ttl: Duration) -> bool {
        self.remotes
            .lock()
            .expect("admitted")
            .get(id)
            .is_some_and(|since| since.elapsed() < ttl)
    }

    fn admit(&self, id: EndpointId) {
        self.remotes
            .lock()
            .expect("admitted")
            .insert(id, Instant::now());
    }
}

// --- hook ----------------------------------------------------------------------

/// Messages from the hook to the outgoing task.
enum ToTask {
    /// Pre-authenticate to this remote and report whether to proceed.
    PreAuth(EndpointAddr, oneshot::Sender<bool>),
    /// A connection to this remote was closed with 403: it no longer
    /// remembers us (it restarted, or our admission lapsed). Forget the
    /// cached handshake so the next connection authenticates again.
    Forget(EndpointId),
}

/// Mount on the endpoint builder.
#[derive(Debug)]
pub struct AuthHook {
    admitted: Arc<Admitted>,
    ttl: Duration,
    tx: mpsc::Sender<ToTask>,
}

impl EndpointHooks for AuthHook {
    async fn before_connect<'a>(
        &'a self,
        remote: &'a EndpointAddr,
        alpn: &'a [u8],
    ) -> BeforeConnectOutcome {
        if alpn == ALPN {
            return BeforeConnectOutcome::Accept;
        }
        let (reply_tx, reply_rx) = oneshot::channel();
        if self
            .tx
            .send(ToTask::PreAuth(remote.clone(), reply_tx))
            .await
            .is_err()
        {
            return BeforeConnectOutcome::Reject;
        }
        match reply_rx.await {
            Ok(true) => BeforeConnectOutcome::Accept,
            _ => {
                tracing::debug!(
                    "not connecting to {}: pre-authentication failed",
                    remote.id.fmt_short()
                );
                BeforeConnectOutcome::Reject
            }
        }
    }

    async fn after_handshake<'a>(&'a self, conn: &'a Connection) -> AfterHandshakeOutcome {
        if conn.side() == Side::Client {
            // A connection we opened: the remote's gate decides. Watch how it
            // ends, so a 403 invalidates our cached handshake for that remote.
            if conn.alpn() != ALPN {
                let remote = conn.remote_id();
                let closed = conn.weak_handle().closed();
                let tx = self.tx.clone();
                tokio::spawn(async move {
                    if let Some(closed) = closed.await {
                        if let ConnectionError::ApplicationClosed(close) = &closed.reason {
                            if close.error_code.into_inner() as u32 == CLOSE_DENIED {
                                let _ = tx.send(ToTask::Forget(remote)).await;
                            }
                        }
                    }
                });
            }
            return AfterHandshakeOutcome::Accept;
        }
        // The auth ALPN itself is always open (it carries the token).
        if conn.alpn() == ALPN || self.admitted.is_admitted(&conn.remote_id(), self.ttl) {
            AfterHandshakeOutcome::Accept
        } else {
            tracing::info!(
                "rejecting {} on {}: not authenticated",
                conn.remote_id().fmt_short(),
                String::from_utf8_lossy(conn.alpn())
            );
            AfterHandshakeOutcome::Reject {
                error_code: CLOSE_DENIED.into(),
                reason: b"not authenticated".to_vec(),
            }
        }
    }
}

// --- outgoing task -------------------------------------------------------------

/// Performs the outgoing pre-authentication handshakes. Spawn it with the
/// bound endpoint.
pub struct AuthTask {
    token: Vec<u8>,
    timeout: Duration,
    rx: mpsc::Receiver<ToTask>,
}

impl fmt::Debug for AuthTask {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuthTask")
    }
}

impl AuthTask {
    pub fn spawn(self, endpoint: Endpoint) -> JoinHandle<()> {
        tokio::spawn(self.run(endpoint))
    }

    async fn run(mut self, endpoint: Endpoint) {
        // Remotes we authenticated to, and when; coalesces the burst of
        // connections the protocols open together.
        let mut allowed: HashMap<EndpointId, Instant> = HashMap::new();
        let mut pending: HashMap<EndpointId, Vec<oneshot::Sender<bool>>> = HashMap::new();
        let mut handshakes: JoinSet<(EndpointId, Result<()>)> = JoinSet::new();
        loop {
            tokio::select! {
                request = self.rx.recv() => {
                    let (remote, reply) = match request {
                        Some(ToTask::PreAuth(remote, reply)) => (remote, reply),
                        Some(ToTask::Forget(id)) => {
                            if allowed.remove(&id).is_some() {
                                tracing::info!(
                                    "{} no longer admits us; authenticating again next time",
                                    id.fmt_short()
                                );
                            }
                            continue;
                        }
                        None => break,
                    };
                    if allowed
                        .get(&remote.id)
                        .is_some_and(|since| since.elapsed() < OUTGOING_CACHE_TTL)
                    {
                        reply.send(true).ok();
                        continue;
                    }
                    match pending.entry(remote.id) {
                        Entry::Occupied(mut waiting) => waiting.get_mut().push(reply),
                        Entry::Vacant(slot) => {
                            slot.insert(vec![reply]);
                            let endpoint = endpoint.clone();
                            let token = self.token.clone();
                            let timeout = self.timeout;
                            handshakes.spawn(async move {
                                let id = remote.id;
                                (id, handshake(&endpoint, remote, &token, timeout).await)
                            });
                        }
                    }
                }
                Some(finished) = handshakes.join_next(), if !handshakes.is_empty() => {
                    let (id, result) = match finished {
                        Ok(pair) => pair,
                        Err(err) => {
                            tracing::warn!("handshake task failed: {err}");
                            continue;
                        }
                    };
                    let ok = match &result {
                        Ok(()) => {
                            allowed.insert(id, Instant::now());
                            true
                        }
                        Err(err) => {
                            tracing::info!("pre-authentication to {} failed: {err:#}", id.fmt_short());
                            false
                        }
                    };
                    for reply in pending.remove(&id).into_iter().flatten() {
                        reply.send(ok).ok();
                    }
                }
            }
        }
    }
}

/// One outgoing handshake: send the token on a uni stream, wait for the close.
async fn handshake(
    endpoint: &Endpoint,
    remote: EndpointAddr,
    token: &[u8],
    timeout: Duration,
) -> Result<()> {
    let attempt = async {
        let conn = endpoint
            .connect(remote, ALPN)
            .await
            .context("connecting for authentication")?;
        let mut send = conn.open_uni().await.context("opening the auth stream")?;
        send.write_all(token).await.context("sending the token")?;
        send.finish().context("finishing the auth stream")?;
        match conn.closed().await {
            ConnectionError::ApplicationClosed(close)
                if close.error_code.into_inner() as u32 == CLOSE_ACCEPTED =>
            {
                Ok(())
            }
            ConnectionError::ApplicationClosed(close)
                if close.error_code.into_inner() as u32 == CLOSE_DENIED =>
            {
                bail!("denied by the remote")
            }
            other => bail!("unexpected close: {other}"),
        }
    };
    tokio::time::timeout(timeout, attempt)
        .await
        .map_err(|_| anyhow!("authentication handshake timed out"))?
}

// --- incoming protocol -------------------------------------------------------

/// Mount on the router under [`ALPN`].
#[derive(Debug, Clone)]
pub struct AuthProtocol {
    admitted: Arc<Admitted>,
    verifier: Arc<Verifier>,
    in_flight: Arc<Semaphore>,
    timeout: Duration,
}

impl ProtocolHandler for AuthProtocol {
    async fn accept(&self, conn: Connection) -> std::result::Result<(), AcceptError> {
        let remote = conn.remote_id();
        let Ok(_permit) = self.in_flight.try_acquire() else {
            tracing::warn!(
                "refusing authentication from {}: too many handshakes in flight",
                remote.fmt_short()
            );
            conn.close(CLOSE_DENIED.into(), b"busy");
            return Ok(());
        };
        let read = async {
            let mut recv = conn.accept_uni().await?;
            recv.read_to_end(MAX_TOKEN_BYTES)
                .await
                .map_err(AcceptError::from_err)
        };
        let token = match tokio::time::timeout(self.timeout, read).await {
            Ok(Ok(token)) => token,
            Ok(Err(err)) => {
                tracing::info!(
                    "authentication from {} failed to read a token: {err}",
                    remote.fmt_short()
                );
                conn.close(CLOSE_DENIED.into(), b"bad token");
                return Ok(());
            }
            Err(_) => {
                tracing::info!("authentication from {} timed out", remote.fmt_short());
                conn.close(CLOSE_DENIED.into(), b"timeout");
                return Ok(());
            }
        };
        match self.verifier.verify(&token, &remote, SystemTime::now()) {
            Ok(()) => {
                tracing::info!("admitted {}", remote.fmt_short());
                self.admitted.admit(remote);
                conn.close(CLOSE_ACCEPTED.into(), b"accepted");
            }
            Err(err) => {
                tracing::info!("refused {}: {err:#}", remote.fmt_short());
                conn.close(CLOSE_DENIED.into(), b"rejected");
            }
        }
        Ok(())
    }
}

/// Build the three parts from one config.
pub fn build(config: AuthConfig) -> (AuthHook, AuthTask, AuthProtocol) {
    let admitted = Arc::new(Admitted::default());
    let (tx, rx) = mpsc::channel(64);
    let hook = AuthHook {
        admitted: admitted.clone(),
        ttl: config.admission_ttl,
        tx,
    };
    let task = AuthTask {
        token: config.token,
        timeout: config.handshake_timeout,
        rx,
    };
    let protocol = AuthProtocol {
        admitted,
        verifier: Arc::new(Verifier::new(config.root, config.vault_id)),
        in_flight: Arc::new(Semaphore::new(config.max_in_flight)),
        timeout: config.handshake_timeout,
    };
    (hook, task, protocol)
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::SecretKey;

    fn id(tag: u8) -> EndpointId {
        SecretKey::from_bytes(&[tag; 32]).public()
    }

    fn later(secs: u64) -> SystemTime {
        SystemTime::now() + Duration::from_secs(secs)
    }

    #[test]
    fn bound_token_is_accepted_only_by_its_audience_vault_and_time() {
        let root = generate_root();
        let verifier = Verifier::new(root.public(), "vault-1".into());
        let authority = mint_authority(&root, "vault-1").unwrap();
        let token = attenuate(&authority, Some(&id(1)), later(3600))
            .unwrap()
            .to_vec()
            .unwrap();
        assert!(token.len() < 1024, "{} bytes", token.len());
        let now = SystemTime::now();
        verifier.verify(&token, &id(1), now).unwrap();
        assert!(
            verifier.verify(&token, &id(2), now).is_err(),
            "other endpoint"
        );
        assert!(
            verifier.verify(&token, &id(1), later(3601)).is_err(),
            "expired"
        );
        let other_vault = Verifier::new(root.public(), "vault-2".into());
        assert!(
            other_vault.verify(&token, &id(1), now).is_err(),
            "other vault"
        );
        let other_root = Verifier::new(generate_root().public(), "vault-1".into());
        assert!(
            other_root.verify(&token, &id(1), now).is_err(),
            "other root key"
        );
        assert!(
            verifier.verify(&[1, 2, 3], &id(1), now).is_err(),
            "garbage token"
        );
    }

    #[test]
    fn root_key_round_trips_through_bytes_and_hex() {
        let root = generate_root();
        let again = root_from_bytes(&root_to_bytes(&root)).unwrap();
        assert_eq!(again.public(), root.public());
        let public = public_from_hex(&public_to_hex(&root.public())).unwrap();
        assert_eq!(public, root.public());
        assert!(public_from_hex("zz").is_err());
    }

    #[test]
    fn bearer_token_delegates_by_narrowing_and_bound_tokens_do_not() {
        let root = generate_root();
        let verifier = Verifier::new(root.public(), "v".into());
        let authority = mint_authority(&root, "v").unwrap();
        let bearer = attenuate(&authority, None, later(3600)).unwrap();
        let now = SystemTime::now();
        // A bearer token admits any endpoint until it expires.
        let bytes = bearer.to_vec().unwrap();
        verifier.verify(&bytes, &id(1), now).unwrap();
        verifier.verify(&bytes, &id(7), now).unwrap();
        // Narrowed by the holder to one device and a shorter life.
        let delegated = parse_token(&bytes, &root.public()).unwrap();
        let narrowed = attenuate(&delegated, Some(&id(7)), later(60))
            .unwrap()
            .to_vec()
            .unwrap();
        verifier.verify(&narrowed, &id(7), now).unwrap();
        assert!(verifier.verify(&narrowed, &id(1), now).is_err());
        assert!(verifier.verify(&narrowed, &id(7), later(61)).is_err());
        // A bound token cannot be re-bound: both checks must hold.
        let bound = attenuate(&authority, Some(&id(1)), later(3600)).unwrap();
        let rebound = attenuate(&bound, Some(&id(2)), later(60))
            .unwrap()
            .to_vec()
            .unwrap();
        assert!(verifier.verify(&rebound, &id(1), now).is_err());
        assert!(verifier.verify(&rebound, &id(2), now).is_err());
    }

    #[test]
    fn widened_tokens_are_refused() {
        let root = generate_root();
        let now = SystemTime::now();
        // Facts added in an attenuation block are scoped to that block.
        let authority = mint_authority(&root, "v").unwrap();
        let bound = attenuate(&authority, Some(&id(1)), later(3600)).unwrap();
        let widened = bound
            .append(block!(r#"vault("other"); right("sync"); right("admin");"#))
            .unwrap()
            .to_vec()
            .unwrap();
        let other = Verifier::new(root.public(), "other".into());
        assert!(other.verify(&widened, &id(1), now).is_err());
        // The right must come from the authority block.
        let no_right = biscuit!(r#"vault("v");"#).build(&root).unwrap();
        let claimed = no_right
            .append(block!(r#"right("sync");"#))
            .unwrap()
            .to_vec()
            .unwrap();
        let verifier = Verifier::new(root.public(), "v".into());
        assert!(verifier.verify(&claimed, &id(1), now).is_err());
        // Oversized tokens are refused before parsing.
        let mut big = authority.clone();
        for i in 0..40 {
            big = attenuate(&big, None, later(3600 + i)).unwrap();
        }
        let big = big.to_vec().unwrap();
        assert!(big.len() > MAX_TOKEN_BYTES, "{} bytes", big.len());
        assert!(verifier.verify(&big, &id(1), now).is_err());
    }
}
