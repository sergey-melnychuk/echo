//! Stage 1 CLI tests for the commands that do not block: `init`, `whoami`,
//! `invite`, `status`. `run` and `join` are exercised through the library in
//! `tests/plumbing.rs`.

use anyhow::Result;
use iroh_docs::api::protocol::ShareMode;
use iroh_docs::Capability;
use vaultsync::cli::{execute, make_invite, Cli, Command, ConflictAction};
use vaultsync::config::{self, Layout};
use vaultsync::node::NetOptions;
use vaultsync::vault::Vault;

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
    let ticket = make_invite(&layout, ShareMode::Write, &[])?;
    assert_eq!(ticket.nodes.len(), 1);
    assert_eq!(ticket.nodes[0].id, key.public());
    assert!(ticket.nodes[0].addrs.is_empty());
    assert!(matches!(ticket.capability, Capability::Write(_)));
    let read = make_invite(&layout, ShareMode::Read, &["127.0.0.1:4711".parse()?])?;
    assert!(matches!(read.capability, Capability::Read(_)));
    assert_eq!(read.nodes[0].addrs.len(), 1);
    // The ticket string round-trips.
    let parsed: iroh_docs::DocTicket = ticket.to_string().parse()?;
    assert_eq!(parsed.capability.id(), ticket.capability.id());

    // After a node ran, the invite carries the recorded address.
    let vault = Vault::open(&dir, &NetOptions::loopback()).await?;
    vault.save_own_addr()?;
    let bound = vault.node().addr();
    vault.shutdown().await?;
    let ticket = make_invite(&layout, ShareMode::Write, &[])?;
    assert_eq!(ticket.nodes[0].addrs, bound.addrs);
    assert!(!ticket.nodes[0].addrs.is_empty());

    execute(cli(Command::Invite {
        dir: dir.clone(),
        write: true,
        read: false,
        addr: vec![],
    }))
    .await?;
    assert!(execute(cli(Command::Invite {
        dir: dir.clone(),
        write: false,
        read: false,
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
    let ticket = a.ticket(ShareMode::Read, &[]).await?;
    let b_dir = tmp.path().join("b");
    let b = Vault::join(&b_dir, ticket, &net).await?;
    b.shutdown().await?;
    a.shutdown().await?;
    let layout = Layout::new(&b_dir);
    assert!(make_invite(&layout, ShareMode::Write, &[]).is_err());
    assert!(make_invite(&layout, ShareMode::Read, &[]).is_ok());
    Ok(())
}
