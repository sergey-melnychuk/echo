//! Stage 4 gate tests: SEC-1 (unauthenticated endpoints cannot open docs,
//! blobs or gossip connections), SEC-2 (expired, wrong-audience, wrong-root
//! and wrong-vault tokens are refused), delegation by narrowing, refusal of
//! widened tokens, SEC-3 (oversized tokens and stalled handshakes), SEC-6.

mod common;

use std::time::{Duration, Instant, SystemTime};

use anyhow::{bail, Result};
use biscuit_auth::macros::block;
use common::{init_tracing, wait_for_file, Peer, DEADLINE};
use iroh::endpoint::ConnectionError;
use iroh::{Endpoint, EndpointAddr, SecretKey};
use iroh_docs::api::protocol::ShareMode;
use iroh_docs::engine::LiveEvent;
use iroh_docs::store::Query;
use n0_future::StreamExt;
use vaultsync::auth::{self, AuthConfig};
use vaultsync::config::{self, Layout};
use vaultsync::node::{NetOptions, Node};
use vaultsync::vault::Vault;

const HOUR: Duration = Duration::from_secs(3600);

/// A node for `dir` with the given admission config (or none).
async fn bare_node(dir: &std::path::Path, auth: Option<AuthConfig>) -> Result<Node> {
    let layout = Layout::new(dir);
    layout.create_dirs()?;
    let key = config::load_or_create_secret_key(&layout.endpoint_key())?;
    Node::spawn(&layout, key, &NetOptions::loopback(), auth).await
}

fn endpoint_key(dir: &std::path::Path) -> Result<SecretKey> {
    let layout = Layout::new(dir);
    std::fs::create_dir_all(layout.dot())?;
    config::load_or_create_secret_key(&layout.endpoint_key())
}

/// The owner's root key pair, from its vault directory.
fn owner_root(peer: &Peer) -> Result<biscuit_auth::KeyPair> {
    let bytes = config::load_bytes_private(&Layout::new(&peer.dir).root_key())?
        .ok_or_else(|| anyhow::anyhow!("no root key"))?;
    auth::root_from_bytes(&bytes)
}

/// Connect on `alpn` and report how the connection ended: `None` if the
/// connect itself was refused (the local hook denied it), otherwise the
/// application close code the remote used.
async fn probe(endpoint: &Endpoint, remote: EndpointAddr, alpn: &[u8]) -> Result<Option<u32>> {
    let conn =
        match tokio::time::timeout(Duration::from_secs(10), endpoint.connect(remote, alpn)).await {
            Err(_) => bail!("connect timed out"),
            Ok(Err(_)) => return Ok(None),
            Ok(Ok(conn)) => conn,
        };
    match tokio::time::timeout(Duration::from_secs(10), conn.closed()).await {
        Ok(ConnectionError::ApplicationClosed(close)) => {
            Ok(Some(close.error_code.into_inner() as u32))
        }
        Ok(other) => bail!("unexpected close: {other}"),
        Err(_) => bail!("the connection stayed open"),
    }
}

#[tokio::test]
async fn unauthenticated_and_badly_authenticated_endpoints_are_refused() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let a = Peer::init(&tmp.path().join("a")).await?;
    // Positive control: a bound write invite for B.
    let b_dir = tmp.path().join("b");
    let b_key = endpoint_key(&b_dir)?;
    let invite = a
        .vault
        .invite(ShareMode::Write, Some(b_key.public()), HOUR)?;
    let b = Peer::join(&b_dir, &invite).await?;
    a.write("f.txt", "shared\n")?;
    wait_for_file(&b, "f.txt", Some("shared\n")).await?;
    let a_addr = a.vault.node().addr();
    let vault_id = a.vault.id().to_string();
    let root = owner_root(&a)?;

    // SEC-1: no hooks, no token. Every protocol ALPN is closed with 403.
    let none = bare_node(&tmp.path().join("none"), None).await?;
    for alpn in [iroh_docs::ALPN, iroh_blobs::ALPN, iroh_gossip::ALPN] {
        assert_eq!(
            probe(none.endpoint(), a_addr.clone(), alpn).await?,
            Some(403)
        );
    }
    // Importing the ticket gets nowhere: the sync attempt fails.
    let ticket = invite.doc_ticket()?;
    let (doc, mut events) = none.docs().import_and_subscribe(ticket.clone()).await?;
    let deadline = Instant::now() + DEADLINE;
    loop {
        match tokio::time::timeout(Duration::from_millis(500), events.next()).await {
            Ok(Some(Ok(LiveEvent::SyncFinished(event)))) if event.result.is_err() => break,
            Ok(Some(Ok(LiveEvent::InsertRemote { .. }))) => bail!("an entry got through"),
            _ => {}
        }
        if Instant::now() > deadline {
            bail!("no failed sync was observed");
        }
    }
    assert!(doc.get_one(Query::all()).await?.is_none());
    none.shutdown().await?;

    // SEC-2: tokens that must be refused, each presented by its own node.
    let authority = auth::mint_authority(&root, &vault_id)?;
    let now = SystemTime::now();
    let cases: Vec<(&str, Vec<u8>, biscuit_auth::PublicKey, String)> = vec![
        (
            "wrong audience",
            auth::attenuate(&authority, Some(&b_key.public()), now + HOUR)?.to_vec()?,
            root.public(),
            vault_id.clone(),
        ),
        (
            "expired",
            auth::attenuate(&authority, None, now - Duration::from_secs(1))?.to_vec()?,
            root.public(),
            vault_id.clone(),
        ),
        (
            "other root key",
            {
                let other = auth::generate_root();
                auth::attenuate(&auth::mint_authority(&other, &vault_id)?, None, now + HOUR)?
                    .to_vec()?
            },
            root.public(),
            vault_id.clone(),
        ),
        (
            "other vault",
            auth::attenuate(
                &auth::mint_authority(&root, "another-vault")?,
                None,
                now + HOUR,
            )?
            .to_vec()?,
            root.public(),
            vault_id.clone(),
        ),
    ];
    for (name, token, root_key, vault) in cases {
        let dir = tmp.path().join(format!("bad-{}", name.replace(' ', "-")));
        let node = bare_node(&dir, Some(AuthConfig::new(token, root_key, vault))).await?;
        // The local hook pre-authenticates first; A denies, so the connect
        // never happens.
        let outcome = probe(node.endpoint(), a_addr.clone(), iroh_docs::ALPN).await?;
        assert_eq!(outcome, None, "{name}: expected the connect to be refused");
        node.shutdown().await?;
    }

    // The admitted member keeps working throughout.
    a.write("g.txt", "still shared\n")?;
    wait_for_file(&b, "g.txt", Some("still shared\n")).await?;

    // Joining with an invite for another device is refused up front.
    let for_b_again = a
        .vault
        .invite(ShareMode::Write, Some(b_key.public()), HOUR)?;
    assert!(
        Vault::join(&tmp.path().join("z"), &for_b_again, &NetOptions::loopback())
            .await
            .is_err()
    );

    a.stop().await?;
    b.stop().await?;
    Ok(())
}

#[tokio::test]
async fn delegation_narrows_and_widening_fails() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let a = Peer::init(&tmp.path().join("a")).await?;
    // A bearer write invite: B may pass it on.
    let bearer = a.vault.invite(ShareMode::Write, None, HOUR)?;
    assert!(bearer.delegatable);
    let b = Peer::join(&tmp.path().join("b"), &bearer).await?;
    assert!(b.vault.config().token_delegatable);
    a.write("f.txt", "one\n")?;
    wait_for_file(&b, "f.txt", Some("one\n")).await?;

    // B delegates a read-only, bound, short-lived token to C.
    let c_dir = tmp.path().join("c");
    let c_key = endpoint_key(&c_dir)?;
    let for_c = b.vault.invite(
        ShareMode::Read,
        Some(c_key.public()),
        Duration::from_secs(600),
    )?;
    assert!(!for_c.delegatable);
    // C's invite still works while B is offline: nothing in it depends on B.
    let c = Peer::join(&c_dir, &for_c).await?;
    wait_for_file(&c, "f.txt", Some("one\n")).await?;
    // SEC-6: C reads but cannot publish, neither through the vault nor docs.
    assert!(!c.vault.can_write());
    assert!(c.vault.set("x", "y").await.is_err());
    c.write("f.txt", "edited on a read-only device\n")?;
    a.write("f.txt", "two\n")?;
    wait_for_file(&c, "f.txt", Some("two\n")).await?;
    wait_for_file(&b, "f.txt", Some("two\n")).await?;
    // C cannot delegate: its token is bound.
    assert!(c.vault.invite(ShareMode::Read, None, HOUR).is_err());
    // Someone else holding C's token is refused (bound to C).
    let stranger = bare_node(
        &tmp.path().join("stranger"),
        Some(AuthConfig::new(
            for_c.token_bytes()?,
            for_c.root_key()?,
            a.vault.id().to_string(),
        )),
    )
    .await?;
    assert_eq!(
        probe(stranger.endpoint(), a.vault.node().addr(), iroh_docs::ALPN).await?,
        None
    );
    stranger.shutdown().await?;

    // Widening: B's bearer token for vault A, with a block claiming vault D
    // and extra rights, is refused by vault D.
    let d = Peer::init(&tmp.path().join("d")).await?;
    let widened = auth::parse_token(&bearer.token_bytes()?, &bearer.root_key()?)?
        .append(block!(
            r#"vault({other}); right("sync"); right("admin");"#,
            other = d.vault.id().to_string(),
        ))?
        .to_vec()?;
    // Presented to D, whose root key differs: refused by the signature.
    let widener = bare_node(
        &tmp.path().join("widener"),
        Some(AuthConfig::new(
            widened.clone(),
            bearer.root_key()?,
            d.vault.id().to_string(),
        )),
    )
    .await?;
    assert_eq!(
        probe(widener.endpoint(), d.vault.node().addr(), iroh_docs::ALPN).await?,
        None
    );
    widener.shutdown().await?;
    // And at the verifier level under A's own root key, for vault D's id.
    let verifier = auth::Verifier::new(bearer.root_key()?, d.vault.id().to_string());
    assert!(verifier
        .verify(&widened, &c_key.public(), SystemTime::now())
        .is_err());

    a.stop().await?;
    b.stop().await?;
    c.stop().await?;
    d.stop().await?;
    Ok(())
}

#[tokio::test]
async fn oversized_tokens_and_stalled_handshakes_do_not_disturb_other_peers() -> Result<()> {
    init_tracing();
    let tmp = tempfile::tempdir()?;
    // The owner serves handshakes with a short timeout and one at a time.
    let mut net = NetOptions::loopback();
    net.handshake_timeout = Some(Duration::from_millis(500));
    net.max_in_flight = Some(1);
    let a_vault = Vault::init(&tmp.path().join("a"), &net).await?;
    let a = Peer::from_vault(&tmp.path().join("a"), a_vault).await?;
    let bearer = a.vault.invite(ShareMode::Write, None, HOUR)?;
    let b = Peer::join(&tmp.path().join("b"), &bearer).await?;
    a.write("f.txt", "one\n")?;
    wait_for_file(&b, "f.txt", Some("one\n")).await?;
    let a_addr = a.vault.node().addr();

    // A stalled handshake: connect on the auth ALPN, send nothing. The
    // server gives up after its timeout and closes with 403.
    let staller = bare_node(&tmp.path().join("staller"), None).await?;
    let started = std::time::Instant::now();
    let conn = staller
        .endpoint()
        .connect(a_addr.clone(), auth::ALPN)
        .await?;
    let _send = conn.open_uni().await?;
    match tokio::time::timeout(Duration::from_secs(10), conn.closed()).await? {
        ConnectionError::ApplicationClosed(close) => {
            assert_eq!(close.error_code.into_inner(), 403);
        }
        other => bail!("unexpected close: {other}"),
    }
    assert!(started.elapsed() < Duration::from_secs(5));
    staller.shutdown().await?;

    // An oversized token (well over 4 KiB) is refused before verification.
    let root = owner_root(&a)?;
    let mut big = auth::mint_authority(&root, &a.vault.id().to_string())?;
    for i in 0..60 {
        big = auth::attenuate(
            &big,
            None,
            SystemTime::now() + HOUR + Duration::from_secs(i),
        )?;
    }
    let big = big.to_vec()?;
    assert!(big.len() > auth::MAX_TOKEN_BYTES);
    let bloated = bare_node(
        &tmp.path().join("bloated"),
        Some(AuthConfig::new(
            big,
            root.public(),
            a.vault.id().to_string(),
        )),
    )
    .await?;
    assert_eq!(
        probe(bloated.endpoint(), a_addr.clone(), iroh_docs::ALPN).await?,
        None
    );
    bloated.shutdown().await?;

    // Meanwhile the admitted member is unaffected, and a new one can join.
    a.write("g.txt", "two\n")?;
    wait_for_file(&b, "g.txt", Some("two\n")).await?;
    let c = Peer::join(&tmp.path().join("c"), &bearer).await?;
    wait_for_file(&c, "g.txt", Some("two\n")).await?;

    a.stop().await?;
    b.stop().await?;
    c.stop().await?;
    Ok(())
}

#[tokio::test]
async fn owner_token_is_reminted_and_members_need_a_fresh_invite() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let net = NetOptions::loopback();
    let a_dir = tmp.path().join("a");
    let a = Vault::init(&a_dir, &net).await?;
    // A member joins with a token that lives four seconds.
    let b_dir = tmp.path().join("b");
    let b_key = endpoint_key(&b_dir)?;
    let ttl = Duration::from_secs(4);
    let minted_at = Instant::now();
    let short = a.invite(ShareMode::Write, Some(b_key.public()), ttl)?;
    let b = Vault::join(&b_dir, &short, &net).await?;
    b.shutdown().await?;
    a.shutdown().await?;

    // The owner's own token file is corrupted; `open` mints a new one.
    std::fs::write(Layout::new(&a_dir).token(), "garbage")?;
    let a = Vault::open(&a_dir, &net).await?;
    assert!(config::load_bytes_private(&Layout::new(&a_dir).token())?
        .map(|t| t.len() > 100)
        .unwrap_or(false));
    a.shutdown().await?;

    // Once the member's token has expired, its vault cannot be opened.
    tokio::time::sleep_until((minted_at + ttl + Duration::from_millis(300)).into()).await;
    let err = match Vault::open(&b_dir, &net).await {
        Ok(_) => bail!("expired token accepted"),
        Err(err) => format!("{err:#}"),
    };
    assert!(err.contains("expired"), "{err}");
    Ok(())
}
