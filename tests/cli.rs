//! Stage 1 CLI tests for the commands that do not block: `init`, `whoami`,
//! `invite`, `status`. `run` and `join` are exercised through the library in
//! `tests/plumbing.rs`.

use std::time::Duration;

use anyhow::Result;
use echo::cli::{execute, make_invite, Cli, Command, ConflictAction};
use echo::config::{self, Layout};
use echo::node::NetOptions;
use echo::vault::Vault;
use iroh_docs::api::protocol::ShareMode;
use iroh_docs::Capability;

const HOUR: Duration = Duration::from_secs(3600);

fn cli(command: Command) -> Cli {
    Cli {
        loopback: true,
        bind: None,
        command,
    }
}

#[tokio::test]
async fn init_whoami_invite_status() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let dir = tmp.path().join("a");
    execute(cli(Command::Init { dir: dir.clone() })).await?;
    let layout = Layout::new(&dir);
    assert!(layout.is_initialized());
    let key = config::load_secret_key(&layout.endpoint_key())?;

    // whoami on a fresh directory creates only the endpoint key.
    let fresh = tmp.path().join("fresh");
    execute(cli(Command::Whoami { dir: fresh.clone() })).await?;
    let fresh_layout = Layout::new(&fresh);
    assert!(fresh_layout.endpoint_key().is_file());
    assert!(!fresh_layout.is_initialized());

    // Without a recorded address the invite carries the id only.
    let invite = make_invite(&layout, ShareMode::Write, None, HOUR, &[])?;
    let ticket = invite.doc_ticket()?;
    assert_eq!(ticket.nodes.len(), 1);
    assert_eq!(ticket.nodes[0].id, key.public());
    assert!(ticket.nodes[0].addrs.is_empty());
    assert!(matches!(ticket.capability, Capability::Write(_)));
    assert!(invite.delegatable);
    let fresh_key = config::load_secret_key(&fresh_layout.endpoint_key())?;
    let read = make_invite(
        &layout,
        ShareMode::Read,
        Some(fresh_key.public()),
        HOUR,
        &["127.0.0.1:4711".parse()?],
    )?;
    let read_ticket = read.doc_ticket()?;
    assert!(matches!(read_ticket.capability, Capability::Read(_)));
    assert_eq!(read_ticket.nodes[0].addrs.len(), 1);
    assert!(!read.delegatable);
    // The invite string round-trips.
    let parsed: echo::invite::Invite = invite.to_string().parse()?;
    assert_eq!(parsed, invite);

    // After a node ran, the invite carries the recorded address.
    let vault = Vault::open(&dir, &NetOptions::loopback()).await?;
    vault.save_own_addr()?;
    let bound = vault.node().addr();
    vault.shutdown().await?;
    let ticket = make_invite(&layout, ShareMode::Write, None, HOUR, &[])?.doc_ticket()?;
    assert_eq!(ticket.nodes[0].addrs, bound.addrs);
    assert!(!ticket.nodes[0].addrs.is_empty());

    execute(cli(Command::Invite {
        dir: dir.clone(),
        write: true,
        read: false,
        audience: Some(fresh_key.public().to_string()),
        ttl: "12h".into(),
        addr: vec![],
    }))
    .await?;
    assert!(execute(cli(Command::Invite {
        dir: dir.clone(),
        write: false,
        read: false,
        audience: None,
        ttl: "1h".into(),
        addr: vec![],
    }))
    .await
    .is_err());
    assert!(execute(cli(Command::Invite {
        dir: dir.clone(),
        write: true,
        read: false,
        audience: Some("not-an-id".into()),
        ttl: "1h".into(),
        addr: vec![],
    }))
    .await
    .is_err());
    execute(cli(Command::Status { dir: dir.clone() })).await?;
    execute(cli(Command::Conflict {
        dir: dir.clone(),
        action: ConflictAction::List,
    }))
    .await?;
    // Exporting a path without losing versions is fine and prints nothing.
    execute(cli(Command::Conflict {
        dir: dir.clone(),
        action: ConflictAction::Export {
            path: "nothing.txt".into(),
        },
    }))
    .await?;
    assert!(execute(cli(Command::Status { dir: fresh })).await.is_err());
    assert!(execute(cli(Command::Init { dir })).await.is_err());
    Ok(())
}

#[tokio::test]
async fn read_only_member_cannot_make_write_invites() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let net = NetOptions::loopback();
    let a = Vault::init(&tmp.path().join("a"), &net).await?;
    let b_dir = tmp.path().join("b");
    // A bound read invite for B.
    let b_key = config::load_or_create_secret_key(&Layout::new(&b_dir).endpoint_key())?;
    let invite = a.invite(ShareMode::Read, Some(b_key.public()), HOUR)?;
    let b = Vault::join(&b_dir, &invite, &net).await?;
    b.shutdown().await?;
    a.shutdown().await?;
    let layout = Layout::new(&b_dir);
    // Read-only, and bound: neither a write invite nor a delegation.
    assert!(make_invite(&layout, ShareMode::Write, None, HOUR, &[]).is_err());
    assert!(make_invite(&layout, ShareMode::Read, None, HOUR, &[]).is_err());
    // The owner can always invite.
    assert!(make_invite(
        &Layout::new(tmp.path().join("a")),
        ShareMode::Read,
        None,
        HOUR,
        &[]
    )
    .is_ok());
    Ok(())
}
