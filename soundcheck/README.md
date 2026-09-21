# p2p-sync-poc

A Rust proof of concept that syncs a directory between peers with no central
server: content-defined chunking (FastCDC), BLAKE3-addressed chunks,
capability tokens bound to one peer, QUIC transport and gossip signaling over
[iroh](https://iroh.computer) 1.x. `SPEC.md` is the design; `NOTES.md` records
where the implementation had to differ from it and why; `STATUS.md` tracks
progress.

## Build and test

```sh
./scripts/gate.sh          # fmt --check, check, clippy -D warnings, test
cargo test --test e2e      # the three-node end-to-end suite only
```

Requires Rust 1.91 or newer (set by iroh). Every test runs on loopback with
relays disabled; nothing touches the network outside the machine.

## Using the CLI

Everything the tool owns lives under `<dir>/.p2p-sync/`: keys, config, the
chunk store, temporary files and copies of rejected versions. The rest of
`<dir>` is the synced tree.

### 1. The owner creates a document

```sh
p2p-sync-poc init ~/shared
p2p-sync-poc run ~/shared
```

`init` generates the document ID, the topic salt, the owner signing key and
this machine's node key. `run` starts the node and prints its node ID and
direct addresses; leave it running. Files already in `~/shared` are published
on the first run, and every later change is picked up by the file watcher
after it has been quiet for half a second.

### 2. A new peer asks to be invited

On the peer's machine:

```sh
p2p-sync-poc whoami ~/shared-copy
```

This prints the peer's node ID. Send it to the owner. Tokens are bound to
one node ID, so an invite copied by anyone else is useless (SEC-2).

### 3. The owner issues an invite

```sh
p2p-sync-poc invite ~/shared --audience <peer node id> --read --write --ttl 12h
```

Add `--addr <ip:port>` (the direct address printed by `run`) when peers must
dial without relays or discovery, for example on one LAN. `--read` alone gives
a read-only member: it can fetch and re-serve, but its announcements of new
versions are ignored by everyone. The command prints one long hex string:
the invite. Send it to the peer over a channel you trust; it contains the
topic salt and the token.

### 4. The peer joins and runs

```sh
p2p-sync-poc join ~/shared-copy <invite>
p2p-sync-poc run ~/shared-copy
```

`join` refuses an invite meant for another node. `run` catches up from the
peers named in the invite, then follows the gossip topic.

### 5. Status

```sh
p2p-sync-poc status ~/shared-copy
```

Prints each file's head version, author, clock and whether it is on disk,
and lists the copies kept under `.p2p-sync/rejected/`. Stop `run` first: the
store is locked while a node is running.

### Local testing without relays

`run --loopback` binds to 127.0.0.1 with relays disabled. Use `invite --addr`
with the address printed by the owner's `run`.

## Conflicts

Every version names its parent. Two edits of the same file from the same
parent are a fork; every node keeps the one with the smaller
(`hlc`, `author`) and rejects the other, whatever order they arrive in. The
losing node's bytes are kept under `.p2p-sync/rejected/<file>.<version>`, its
file on disk becomes the winner's content, and its next save is a normal
child of the winner. An unpublished local edit displaced by an incoming
version is kept there too, as `<file>.unpublished.<hash>`.

## Limits of the proof of concept

No deletions or renames, no chunk garbage collection, no token revocation
before expiry, files up to 256 MiB held in memory while chunking, and one
owner key per document. See `SPEC.md` section 14.
