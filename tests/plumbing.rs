//! Stage 1 gate tests: two nodes sync arbitrary entries, a third joins later
//! and catches up, state survives a restart. Loopback only, no fixed sleeps.

use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{bail, Result};
use iroh_docs::api::protocol::ShareMode;
use iroh_docs::store::Query;
use iroh_docs::DocTicket;
use vaultsync::node::NetOptions;
use vaultsync::vault::Vault;

const DEADLINE: Duration = Duration::from_secs(30);

async fn wait_for_entry(vault: &Vault, key: &str, value: &[u8]) -> Result<()> {
    let deadline = Instant::now() + DEADLINE;
    loop {
        for entry in vault.entries(Query::all().key_exact(key)).await? {
            let hash = entry.content_hash();
            if vault.has_content(hash).await? && vault.content(hash).await? == value {
                return Ok(());
            }
        }
        if Instant::now() > deadline {
            bail!(
                "timeout waiting for {key} on {}",
                vault.endpoint_id().fmt_short()
            );
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

async fn joined(dir: &Path, ticket: &DocTicket, net: &NetOptions) -> Result<Vault> {
    // Round-trip the ticket through its string form, as the CLI does.
    let ticket: DocTicket = ticket.to_string().parse()?;
    let vault = Vault::join(dir, ticket, net).await?;
    vault.start_sync().await?;
    Ok(vault)
}

#[tokio::test]
async fn two_nodes_sync_entries_both_ways() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let net = NetOptions::loopback();
    let a = Vault::init(&tmp.path().join("a"), &net).await?;
    assert!(a.can_write());
    let ticket = a.ticket(ShareMode::Write, &[]).await?;
    let b = joined(&tmp.path().join("b"), &ticket, &net).await?;
    assert!(b.can_write());
    assert_eq!(b.id(), a.id());
    assert_ne!(b.endpoint_id(), a.endpoint_id());

    a.set("k1", "v1").await?;
    wait_for_entry(&b, "k1", b"v1").await?;
    b.set("k2", "v2").await?;
    wait_for_entry(&a, "k2", b"v2").await?;

    // A burst of entries, including a larger value.
    let big = vec![0xabu8; 300 * 1024];
    a.set("big", big.clone()).await?;
    for i in 0..40 {
        a.set(format!("bulk/{i}"), format!("value {i}")).await?;
    }
    wait_for_entry(&b, "big", &big).await?;
    for i in 0..40 {
        wait_for_entry(&b, &format!("bulk/{i}"), format!("value {i}").as_bytes()).await?;
    }

    // Both devices wrote k-entries under their own authors.
    let on_b = b.entries(Query::all()).await?;
    let authors: std::collections::HashSet<_> = on_b.iter().map(|e| e.author()).collect();
    assert_eq!(authors.len(), 2);

    a.shutdown().await?;
    b.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn late_joiner_catches_up() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let net = NetOptions::loopback();
    let a = Vault::init(&tmp.path().join("a"), &net).await?;
    let ticket = a.ticket(ShareMode::Write, &[]).await?;
    let b = joined(&tmp.path().join("b"), &ticket, &net).await?;
    for i in 0..5 {
        a.set(format!("a/{i}"), format!("from a {i}")).await?;
        b.set(format!("b/{i}"), format!("from b {i}")).await?;
    }
    wait_for_entry(&a, "b/4", b"from b 4").await?;
    wait_for_entry(&b, "a/4", b"from a 4").await?;

    // C only knows A's address from the ticket, and must end up with
    // everything, including B's entries.
    let c = joined(&tmp.path().join("c"), &ticket, &net).await?;
    for i in 0..5 {
        wait_for_entry(&c, &format!("a/{i}"), format!("from a {i}").as_bytes()).await?;
        wait_for_entry(&c, &format!("b/{i}"), format!("from b {i}").as_bytes()).await?;
    }
    // And later writes from C reach both.
    c.set("c/0", "from c").await?;
    wait_for_entry(&a, "c/0", b"from c").await?;
    wait_for_entry(&b, "c/0", b"from c").await?;

    a.shutdown().await?;
    b.shutdown().await?;
    c.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn state_survives_restart() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let net = NetOptions::loopback();
    let a = Vault::init(&tmp.path().join("a"), &net).await?;
    let ticket = a.ticket(ShareMode::Write, &[]).await?;
    let b_dir = tmp.path().join("b");
    let b = joined(&b_dir, &ticket, &net).await?;
    a.set("k1", "v1").await?;
    wait_for_entry(&b, "k1", b"v1").await?;
    let b_id = b.endpoint_id();
    let b_author = b.author();
    b.shutdown().await?;

    // Written while B is down.
    a.set("k2", "v2").await?;

    let b = Vault::open(&b_dir, &net).await?;
    assert_eq!(b.endpoint_id(), b_id, "endpoint key persisted");
    assert_eq!(b.author(), b_author, "author persisted");
    assert_eq!(b.id(), a.id());
    // Entries and content are there before any network activity.
    wait_for_entry(&b, "k1", b"v1").await?;
    assert!(b.entries(Query::all().key_exact("k2")).await?.is_empty());
    // Peers were remembered from the ticket, so sync resumes.
    assert_eq!(b.peers()?.len(), 1);
    b.start_sync().await?;
    wait_for_entry(&b, "k2", b"v2").await?;
    b.set("k3", "v3").await?;
    wait_for_entry(&a, "k3", b"v3").await?;

    a.shutdown().await?;
    b.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn read_ticket_holder_cannot_publish() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let net = NetOptions::loopback();
    let a = Vault::init(&tmp.path().join("a"), &net).await?;
    let ticket = a.ticket(ShareMode::Read, &[]).await?;
    let b = joined(&tmp.path().join("b"), &ticket, &net).await?;
    assert!(!b.can_write());
    a.set("k1", "v1").await?;
    wait_for_entry(&b, "k1", b"v1").await?;
    assert!(b.set("k2", "v2").await.is_err());
    assert!(b.ticket(ShareMode::Write, &[]).await.is_err());
    let read_again = b.ticket(ShareMode::Read, &[]).await?;
    assert_eq!(read_again.capability.id(), a.id());
    a.shutdown().await?;
    b.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn second_open_of_a_vault_fails_fast() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let net = NetOptions::loopback();
    let dir = tmp.path().join("a");
    let a = Vault::init(&dir, &net).await?;
    let started = Instant::now();
    let err = match Vault::open(&dir, &net).await {
        Ok(_) => bail!("second open succeeded"),
        Err(err) => err,
    };
    assert!(started.elapsed() < Duration::from_secs(5), "must not block");
    assert!(format!("{err:#}").contains("in use"), "{err:#}");
    a.shutdown().await?;
    // The lock is released with the node.
    let a = Vault::open(&dir, &net).await?;
    a.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn init_and_open_refuse_the_wrong_state() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let net = NetOptions::loopback();
    let dir = tmp.path().join("a");
    assert!(Vault::open(&dir, &net).await.is_err());
    let a = Vault::init(&dir, &net).await?;
    a.shutdown().await?;
    assert!(Vault::init(&dir, &net).await.is_err());
    let a = Vault::open(&dir, &net).await?;
    assert!(a.can_write());
    a.shutdown().await?;
    Ok(())
}
