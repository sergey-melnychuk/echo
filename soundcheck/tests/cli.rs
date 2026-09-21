//! Stage 9: argument parsing, init → invite → join, and the `run` wiring.

use clap::Parser;
use p2p_sync_poc::cli::{
    init, invite, join, load_config, load_owner_key, parse_duration, start, status, whoami, Cli,
    CliError, Command, Invite,
};
use std::path::PathBuf;
use std::time::{Duration, Instant};

#[test]
fn parses_every_command() {
    let cli = Cli::try_parse_from(["p2p", "init", "/tmp/x"]).unwrap();
    assert_eq!(
        cli.command,
        Command::Init {
            dir: PathBuf::from("/tmp/x")
        }
    );
    let cli = Cli::try_parse_from(["p2p", "whoami", "d"]).unwrap();
    assert!(matches!(cli.command, Command::Whoami { .. }));
    let cli = Cli::try_parse_from([
        "p2p",
        "invite",
        "d",
        "--audience",
        "ab",
        "--read",
        "--write",
        "--ttl",
        "2h",
        "--addr",
        "127.0.0.1:5000",
    ])
    .unwrap();
    match cli.command {
        Command::Invite {
            audience,
            read,
            write,
            ttl,
            addrs,
            ..
        } => {
            assert_eq!(audience, "ab");
            assert!(read && write);
            assert_eq!(ttl, "2h");
            assert_eq!(addrs, vec!["127.0.0.1:5000".parse().unwrap()]);
        }
        other => panic!("{other:?}"),
    }
    // Default ttl and no permissions flags parse (the command itself rejects them).
    let cli = Cli::try_parse_from(["p2p", "invite", "d", "--audience", "ab"]).unwrap();
    assert!(
        matches!(cli.command, Command::Invite { ttl, read: false, write: false, .. } if ttl == "24h")
    );
    let cli = Cli::try_parse_from(["p2p", "join", "d", "deadbeef"]).unwrap();
    assert!(matches!(cli.command, Command::Join { invite, .. } if invite == "deadbeef"));
    let cli = Cli::try_parse_from(["p2p", "run", "d", "--loopback", "--port", "4242"]).unwrap();
    assert!(matches!(
        cli.command,
        Command::Run {
            loopback: true,
            port: Some(4242),
            ..
        }
    ));
    let cli = Cli::try_parse_from(["p2p", "status", "d"]).unwrap();
    assert!(matches!(cli.command, Command::Status { .. }));
    assert!(Cli::try_parse_from(["p2p", "invite", "d"]).is_err());
    assert!(Cli::try_parse_from(["p2p", "bogus"]).is_err());
    assert!(Cli::try_parse_from(["p2p"]).is_err());
}

#[test]
fn init_invite_join_round_trip() {
    let owner_dir = tempfile::tempdir().unwrap();
    let joiner_dir = tempfile::tempdir().unwrap();
    let owner_root = owner_dir.path().join("doc");
    let joiner_root = joiner_dir.path().join("doc");

    let out = init(&owner_root).unwrap();
    assert!(matches!(
        init(&owner_root),
        Err(CliError::AlreadyInitialized(_))
    ));
    assert!(owner_root.join(".p2p-sync/config.toml").exists());
    assert!(owner_root.join(".p2p-sync/node.key").exists());
    assert!(owner_root.join(".p2p-sync/owner.key").exists());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for f in ["config.toml", "node.key", "owner.key"] {
            let mode = std::fs::metadata(owner_root.join(".p2p-sync").join(f))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "{f}");
        }
    }
    let owner_cfg = load_config(&owner_root).unwrap();
    assert_eq!(owner_cfg.doc_id, out.doc_id);
    assert_eq!(owner_cfg.owner_key, out.owner_key);
    assert!(owner_cfg.token.claims.can_write);
    assert_eq!(owner_cfg.token.claims.audience, *out.node_id.as_bytes());
    assert_eq!(whoami(&owner_root).unwrap(), out.node_id);
    assert!(load_owner_key(&owner_root).unwrap().is_some());

    // The joiner learns its node id first and sends it to the owner.
    let joiner_id = whoami(&joiner_root).unwrap();
    assert_eq!(
        whoami(&joiner_root).unwrap(),
        joiner_id,
        "node key is stable"
    );
    assert!(load_owner_key(&joiner_root).unwrap().is_none());
    assert!(matches!(
        invite(
            &joiner_root,
            out.node_id,
            true,
            false,
            Duration::from_secs(60),
            &[]
        ),
        Err(CliError::NotInitialized(_)) | Err(CliError::NotOwner(_))
    ));
    assert!(matches!(
        invite(
            &owner_root,
            joiner_id,
            false,
            false,
            Duration::from_secs(60),
            &[]
        ),
        Err(CliError::NoPermission)
    ));

    let ttl = parse_duration("12h").unwrap();
    let inv = invite(
        &owner_root,
        joiner_id,
        true,
        true,
        ttl,
        &["127.0.0.1:11204".parse().unwrap()],
    )
    .unwrap();
    let text = inv.encode().unwrap();
    let decoded = Invite::decode(&text).unwrap();
    assert_eq!(decoded, inv);
    assert!(Invite::decode("zz").is_err());
    assert!(Invite::decode(&text[..text.len() - 8]).is_err());
    assert_eq!(inv.bootstrap.len(), 1);
    assert_eq!(inv.bootstrap[0].id, out.node_id);
    assert_eq!(inv.bootstrap[0].ip_addrs().count(), 1);

    let loaded = join(&joiner_root, &decoded).unwrap();
    assert_eq!(loaded.doc_id, out.doc_id);
    assert_eq!(loaded.owner_key, out.owner_key);
    assert_eq!(loaded.salt, owner_cfg.salt);
    assert_eq!(loaded.token.claims.audience, *joiner_id.as_bytes());
    assert!(loaded.token.claims.can_read && loaded.token.claims.can_write);
    let reloaded = load_config(&joiner_root).unwrap();
    assert_eq!(reloaded.token, loaded.token);
    assert_eq!(reloaded.bootstrap, loaded.bootstrap);
    // status works on a fresh (empty) joined directory.
    let (heads, rejected) = status(&joiner_root).unwrap();
    assert!(heads.is_empty());
    assert!(rejected.is_empty());
}

/// SEC-2 at join time: an invite bound to one node is refused by another.
#[test]
fn invite_for_another_node_is_refused() {
    let owner_dir = tempfile::tempdir().unwrap();
    let a_dir = tempfile::tempdir().unwrap();
    let b_dir = tempfile::tempdir().unwrap();
    init(owner_dir.path()).unwrap();
    let a_id = whoami(a_dir.path()).unwrap();
    let inv = invite(
        owner_dir.path(),
        a_id,
        true,
        false,
        Duration::from_secs(600),
        &[],
    )
    .unwrap();
    let err = join(b_dir.path(), &inv).unwrap_err();
    assert!(
        matches!(err, CliError::InviteNotForThisNode { .. }),
        "{err:?}"
    );
    assert!(!b_dir.path().join(".p2p-sync/config.toml").exists());
    // The right node accepts it.
    join(a_dir.path(), &inv).unwrap();
    assert!(a_dir.path().join(".p2p-sync/config.toml").exists());

    // A tampered invite (wrong owner key) is refused too.
    let mut forged = inv.clone();
    forged.owner_key[0] ^= 1;
    let c_dir = tempfile::tempdir().unwrap();
    let c_id = whoami(c_dir.path()).unwrap();
    let mut for_c = invite(
        owner_dir.path(),
        c_id,
        true,
        false,
        Duration::from_secs(600),
        &[],
    )
    .unwrap();
    for_c.owner_key[0] ^= 1;
    assert!(matches!(
        join(c_dir.path(), &for_c),
        Err(CliError::InvalidInvite(_))
    ));
}

async fn wait_for_file(path: &std::path::Path, expected: &[u8]) {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Ok(bytes) = std::fs::read(path) {
            if bytes == expected {
                return;
            }
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {}",
            path.display()
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// The `run` wiring end to end on loopback: an owner with an existing file,
/// a joiner that catches up, and a joiner edit that reaches the owner.
#[tokio::test]
async fn run_wiring_syncs_both_ways_on_loopback() {
    let owner_tmp = tempfile::tempdir().unwrap();
    let joiner_tmp = tempfile::tempdir().unwrap();
    let owner_root = owner_tmp.path().join("doc");
    let joiner_root = joiner_tmp.path().join("doc");
    init(&owner_root).unwrap();
    let hello = b"hello from the owner".to_vec();
    std::fs::create_dir_all(owner_root.join("notes")).unwrap();
    std::fs::write(owner_root.join("notes/hello.txt"), &hello).unwrap();

    let owner = start(&owner_root, true, None).await.unwrap();
    let owner_addr = owner.addr();
    let addrs: Vec<std::net::SocketAddr> = owner_addr.ip_addrs().copied().collect();
    assert!(!addrs.is_empty());

    let joiner_id = whoami(&joiner_root).unwrap();
    let inv = invite(
        &owner_root,
        joiner_id,
        true,
        true,
        Duration::from_secs(3600),
        &addrs,
    )
    .unwrap();
    join(
        &joiner_root,
        &Invite::decode(&inv.encode().unwrap()).unwrap(),
    )
    .unwrap();
    let joiner = start(&joiner_root, true, None).await.unwrap();

    wait_for_file(&joiner_root.join("notes/hello.txt"), &hello).await;

    let reply = b"hello back from the joiner".to_vec();
    std::fs::write(joiner_root.join("reply.txt"), &reply).unwrap();
    wait_for_file(&owner_root.join("reply.txt"), &reply).await;

    // While a node runs, the store is locked and status says so.
    assert!(matches!(status(&owner_root), Err(CliError::StoreBusy(_))));
    joiner.shutdown().await;
    owner.shutdown().await;
    let (heads, _) = status(&owner_root).unwrap();
    assert_eq!(heads.len(), 2);
    let (heads, _) = status(&joiner_root).unwrap();
    assert_eq!(heads.len(), 2);
    assert!(heads.iter().all(|h| h.written));
}
