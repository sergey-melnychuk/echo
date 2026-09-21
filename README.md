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

By default the endpoint uses n0's relays and address lookup, so devices find
each other by id. `--loopback` restricts everything to 127.0.0.1 with no
relays (tests, demos on one machine); `--bind <ip:port>` pins the UDP port
so invites keep working across restarts on a LAN. `invite --addr <ip:port>`
adds direct addresses for devices that cannot use address lookup.

## Limits and known gaps

- A proof of concept: iroh-blobs 0.103 describes itself as not production
  quality, and Automerge is pinned at 0.12.0.
- One vault per process. `status` and `conflict export` need the stores,
  so they fail while `run` holds them (invites do not).
- A member holding a write invite has the namespace secret and cannot be
  revoked before its token expires.
- Re-saving a conflicted file with identical bytes does not resolve the
  conflict; a content change does.
