# vaultsync

A proof of concept that keeps a folder in sync between devices with no
central server, built on [iroh](https://iroh.computer) 1.x, iroh-docs,
iroh-blobs and Automerge.

- Text files merge character by character; concurrent edits are combined.
- Other files are split into content-defined chunks, so an edit transfers
  only the chunks that changed. Concurrent edits get one deterministic
  winner everywhere; the losing version is kept and flagged.
- Peers are admitted with signed, expiring Biscuit tokens, optionally bound
  to one device, enforced before any sync protocol runs.

`SPEC.md` is the design, `NOTES.md` records every place the implementation
had to differ from it and why, with measured numbers.

## Build and test

```sh
./scripts/gate.sh          # fmt --check, check, clippy -D warnings, test
cargo test --test e2e      # the three-node scenarios only
```

Rust 1.91 or newer. Every test runs on loopback; nothing leaves the machine.

## Using the CLI

Everything the tool owns lives under `<dir>/.vault/`: keys, tokens, config,
the blob and docs stores, temporary files, and copies of losing versions.
The rest of `<dir>` is the synced folder. Do not put your own files under
`.vault/`.

### The owner creates a vault

```sh
vaultsync init ~/shared
vaultsync run ~/shared
```

`run` prints the vault id, this device's id and its addresses, syncs the
folder and keeps going until Ctrl-C. Files already in the folder are
published on the first run.

### A new device asks for an invite

On the new device:

```sh
vaultsync whoami ~/shared-copy
```

Send the printed endpoint id to the owner. On the owner's machine (while
`run` is active or not):

```sh
vaultsync invite ~/shared --write --audience <endpoint id> --ttl 7d
```

This prints one long string: the invite. It carries a docs ticket, a token
bound to that device that expires after the time to live, and the vault's
root public key. Send it over a channel you trust. `--read` instead of
`--write` admits a device that can read but never publish. Without
`--audience` the invite is a bearer secret: it admits whoever holds it until
it expires, and its holder can `invite` others by narrowing it.

### The new device joins

```sh
vaultsync join ~/shared-copy '<invite>'
```

`join` stores the invite, verifies that it admits this device, and then
behaves like `run`. Later starts use `run`.

### Quick demo on one machine

Two vaults on loopback, no relays, no discovery:

```sh
./scripts/gate.sh
cargo run -- --loopback init /tmp/v1
cargo run -- --loopback --bind 127.0.0.1:47001 run /tmp/v1     # leave running
cargo run -- whoami /tmp/v2
cargo run -- invite /tmp/v1 --write --audience <id from whoami> --ttl 1d
cargo run -- --loopback join /tmp/v2 '<invite>'
```

Drop a file into `/tmp/v1` and it appears in `/tmp/v2` within a second.

### Status and conflicts

```sh
vaultsync status ~/shared
vaultsync conflict list ~/shared
vaultsync conflict export ~/shared path/to/file.bin   # node stopped
```

When two devices change the same non-text file while apart, every device
shows the same winner, `status` flags the path, the losing author finds a
copy under `.vault/conflicts/`, and any other device can export one. The
next change to the file, on any device, clears the flag.

## Networking

By default the endpoint uses n0's public relays and address lookup, so
devices find each other by id; this was verified between two processes on
one machine (NOTES.md, "Real-network trial"), not yet between machines
behind different NATs. `--loopback` restricts everything to 127.0.0.1 with
no relays (tests, demos on one machine); `--bind <ip:port>` pins the UDP
port so invites keep working across restarts on a LAN. `invite --addr
<ip:port>` adds direct addresses for devices that cannot use address lookup.

## Security model in one paragraph

Transport encryption, peer identity and content integrity come from iroh.
Admission is a Biscuit token verified by an endpoint hook before any sync
protocol runs: the token must be signed by the vault's root key, name the
vault, be unexpired and, unless it was issued as a bearer, be bound to the
connecting endpoint. What the tokens do not do: a member with a write
invite holds the namespace secret and cannot be revoked before its token
expires, content is not encrypted at rest, and endpoint ids and addresses
are visible to whatever relay and discovery service is used. SPEC.md
section 7 and NOTES.md have the details.

## Limits and known gaps

- A proof of concept: iroh-blobs 0.103 describes itself as not production
  quality, and Automerge is pinned at 0.12.0.
- Developed and tested on macOS only. The file watcher notes in NOTES.md are
  about FSEvents; Linux (inotify) and Windows report renames and directory
  removals differently. The engine reconciles known files after every event
  batch to be independent of that, but it has not been run there.
- One vault per process. `status` and `conflict export` need the stores,
  so they fail while `run` holds them (invites do not).
- A member holding a write invite has the namespace secret and cannot be
  revoked before its token expires.
- Re-saving a conflicted file with identical bytes does not resolve the
  conflict; a content change does.

## Repository notes

- `examples/` holds the stage 0 spike programs: throwaway code that confirmed
  the crate APIs and produced the numbers in NOTES.md. They are kept for
  reference and are not usage examples.
- `scripts/gate.sh` runs the four gates every commit must pass; the GitHub
  workflow runs the same script on Linux and macOS.

## License

Licensed under either of the Apache License, Version 2.0 (`LICENSE-APACHE`)
or the MIT license (`LICENSE-MIT`), at your option.
