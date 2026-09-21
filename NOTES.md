# Implementation notes

Findings from the stage 0 spike, API names confirmed against the pinned crate
sources, measured numbers, and every place where the implementation differs
from `SPEC.md`. One entry per item, newest last.

## Stage 0: versions and toolchain

Checked against crates.io on 2026-09-21. Every dependency resolves to the
newest stable release on that date.

| Crate | SPEC.md says | Used | Note |
| --- | --- | --- | --- |
| `iroh` | 1.2.0 | 1.2.0 | |
| `iroh-blobs` | 0.103.0 | 0.103.0 | `default-features = false, features = ["fs-store"]`: the default `rpc` feature pulls in `noq` and is not needed in-process |
| `iroh-docs` | 0.101.0 | 0.101.0 | `default-features = false, features = ["fs-store"]`: the defaults pull in `rpc` and `redb-v2-migration` (a second `redb` 3.x) for stores written by iroh-docs 0.94 to 0.98, which we never have |
| `iroh-gossip` | 0.101.0 | 0.101.0 | We do call it directly after all: `Gossip::builder().spawn(endpoint)` must be constructed and passed to `Docs::spawn` and mounted on the router |
| `automerge` | 0.12.0 | =0.12.0 | |
| `biscuit-auth` | 6.0.0 | 6.0.0 | |
| `fastcdc` | 3.1.0 | 5.0.0 | 3.1 was not the last release; 5.0.0 shipped 2026-08-22. `v2020::StreamCDC::new(reader, min, avg, max)` takes `usize` sizes and yields `ChunkData { hash, offset, length, data }` |
| `notify` | 8.2.0 | 8.2.0 | 9.0.0-rc.5 exists; release candidates are not used |
| `notify-debouncer-full` | 0.6.0 | 0.7.0 | 0.7.0 shipped 2026-01-23; 0.8.0-rc.2 exists and requires notify 9 rc. `new_debouncer(timeout, tick_rate, handler)` and `Debouncer::watch(path, RecursiveMode)` |
| `n0-future` | not listed | 0.3 | Added: `iroh-docs` and `iroh-blobs` return `impl Stream`; `n0_future::{StreamExt, TryStreamExt}` (re-exports of futures-lite and futures-util) give `next` and `try_collect`. Already in the dependency tree through iroh |

`rust-version` in the manifests: iroh, iroh-blobs and iroh-docs 1.91,
automerge 1.90, notify-debouncer-full 1.85, notify 1.77. The maximum, 1.91,
is recorded in `Cargo.toml`. The toolchain used here is 1.98.1.

`cargo build` warns that `proc-macro-error2` 2.0.1 (a transitive dependency)
contains code a future Rust will reject. Nothing to do on our side.

## Stage 0: confirmed API (section 12 checklist)

### iroh 1.2

- `Endpoint::builder(preset)` with `presets::{Empty, Minimal, N0, N0DisableRelay}`.
  `Minimal` sets only the TLS crypto provider; `N0` adds pkarr publishing,
  pkarr and DNS address lookup and the production relays.
- Hermetic test endpoint: `Endpoint::builder(presets::Minimal).secret_key(sk).relay_mode(RelayMode::Disabled).clear_ip_transports().bind_addr("127.0.0.1:0")?.bind().await?`.
  `endpoint.addr()` then contains the loopback socket address immediately; no
  `online()` wait (which needs a relay) and no address lookup service. iroh
  remembers the address of every remote that connected to it, so dialing back
  by `EndpointId` works for peers learned this way (the docs engine and the
  blobs downloader rely on it). Peers that were never seen need an
  `EndpointAddr` with addresses, or an address lookup (`MemoryLookup` exists
  for tests, `N0` for production).
- `Router::builder(endpoint).accept(ALPN, handler).spawn()`; `router.shutdown().await`
  calls `ProtocolHandler::shutdown` on every handler. `BlobsProtocol::shutdown`
  shuts the blob store down, so calling `store.shutdown()` afterwards fails
  with "Sender closed". Shut down the router, then `endpoint.close().await`.
- `ProtocolHandler::accept(&self, conn: Connection) -> Result<(), AcceptError>`;
  `AcceptError::from_err(std_error)` and `AcceptError::from_boxed(anyhow_error.into())`.
- `EndpointHooks` (in `iroh::endpoint`): `before_connect(&self, &EndpointAddr, &[u8]) -> BeforeConnectOutcome::{Accept, Reject}`
  runs before any packet is sent for an outgoing connection;
  `after_handshake(&self, &Connection) -> AfterHandshakeOutcome::{Accept, Reject { error_code, reason }}`
  runs for incoming **and** outgoing connections. `Connection::side()` is
  `Side::Server` for incoming connections, which is how the gate ignores the
  connections we opened ourselves. `Connection::alpn()`, `remote_id()`,
  `close(code, reason)`, `closed().await -> ConnectionError`,
  `ConnectionError::ApplicationClosed(c)` with `c.error_code.into_inner()`.
  `Builder::hooks(h)` may be called several times; hooks run in order.
- Key types come from `iroh` root: `SecretKey::{generate, from_bytes, to_bytes, public}`,
  `EndpointId = PublicKey` with `Display`/`FromStr` (hex), `fmt_short()`,
  `EndpointAddr::{new(id), from_parts, with_ip_addr, addrs, id}`.

### iroh-blobs 0.103

- `FsStore::load(dir)` creates `dir/blobs.db`, `dir/data/`, `dir/temp/` (and
  the parent directory). `MemStore::new()` for tests. Both `Deref` to
  `iroh_blobs::api::Store`, which `Deref`s to `Blobs` (`add_bytes`, `get_bytes`,
  `has`, `status`, `export`, `reader`, `list`) and exposes `tags()`, `remote()`,
  `downloader(&endpoint)`.
- `BlobsProtocol::new(&store, None)`; ALPN `/iroh-bytes/4`.
- Adding: `store.add_bytes(bytes).temp_tag().await` (GC protection while the
  `TempTag` lives), `.await`/`.with_tag()` (auto-named persistent tag),
  `.with_named_tag(name)` (named persistent tag). A `HashSeq` blob:
  `hashes.iter().copied().collect::<HashSeq>()` then
  `store.add_bytes_with_opts((hs.into_inner(), BlobFormat::HashSeq)).with_named_tag(name)`.
  Reading it back: `HashSeq::new(store.get_bytes(hash).await?)` and `hs.iter()`.
- Tags: `store.tags().{set, get, list, delete, create}`; a named tag on a
  HashSeq protects the root and all children from GC. GC itself is configured
  at store construction (`FsStore::load_with_opts` with `Options { gc: Some(GcConfig {..}) }`)
  and is not enabled in the PoC. Docs content would need
  `Docs::persistent(..).protect_handler(..)` if it were.
- Downloading: `store.remote().fetch(conn, HashAndFormat)` returns
  `Stats { payload_bytes_read, other_bytes_read, .. }` and skips ranges already
  present locally; `store.remote().local(HashAndFormat).await? -> LocalInfo`
  with `is_complete()`, `local_bytes()`, `children()`, `missing() -> GetRequest`;
  `store.remote().execute_get(conn, GetRequest)`. Multi-provider:
  `store.downloader(&endpoint).download(request, providers)` where `providers`
  is any `Vec<EndpointId>`/`Option<EndpointId>`/`Shuffled`; it also computes
  the missing set first. Progress via `.stream().await?` yields
  `DownloadProgressItem::{Progress(bytes), TryProvider, ProviderFailed, PartComplete, ..}`.
- **Delta transfer needs two steps.** Downloading `HashAndFormat::hash_seq(m)`
  while the root `m` is not local downloads every child (the missing set
  cannot be computed without the root): measured 10,489,856 payload bytes for
  a one-byte edit. Fetching the root as a raw blob first
  (`HashAndFormat::raw(m)`, 4,096 bytes for 128 hashes) and then
  `local(hash_seq(m)).missing()` downloads only the changed chunks.
  `SPEC.md` section 4 ("Requesting the HashSeq from a peer downloads the
  sequence and every child that is not already present locally") holds only
  after the root is present.

### iroh-docs 0.101

- `Docs::persistent(dir).spawn(endpoint, blobs_store, gossip).await?`
  (`Docs::memory()` for tests). It creates `dir/docs.redb` and
  `dir/default-author` but **not** `dir` itself. `Docs` implements
  `ProtocolHandler`; ALPN `/iroh-sync/1`. `Docs` derefs to `DocsApi`.
- Authors: `docs.author_create()`, `author_default()`, `author_export(id) -> Option<Author>`,
  `author_import(Author)`; `Author::{from_bytes, to_bytes, id}`. The default
  author persists across restarts.
- Replicas: `docs.create() -> Doc`, `docs.open(NamespaceId) -> Option<Doc>`,
  `docs.import(DocTicket) -> Doc` (starts syncing with the ticket's peers),
  `docs.import_and_subscribe(ticket) -> (Doc, events)` (subscribes first so no
  event is missed), `docs.import_namespace(Capability)` (no sync).
- Sharing: `doc.share(ShareMode::{Read, Write}, AddrInfoOptions::{Id, Addresses, Relay, RelayAndAddresses}) -> DocTicket`;
  `DocTicket { capability, nodes }` with `Display`/`FromStr` (128 characters
  for one loopback address). `Capability::{Write(NamespaceSecret), Read(NamespaceId)}`.
- Writing: `doc.set_bytes(author, key, value) -> Hash`, `doc.del(author, prefix)`.
- Reading: `doc.get_many(Query::all().key_exact(k)) -> Stream<Result<Entry>>`,
  `doc.get_one(query)`, `doc.get_exact(author, key, include_empty)`;
  `Entry::{key, author, content_hash, content_len, timestamp}`. Content is
  read through the blob store: `blobs.get_bytes(entry.content_hash())`. There
  is no `content_bytes` helper.
- Live events: `doc.subscribe() -> Stream<Result<LiveEvent>>` with
  `InsertLocal { entry }`, `InsertRemote { from, entry, content_status }`,
  `ContentReady { hash }`, `PendingContentReady`, `NeighborUp(id)`,
  `NeighborDown(id)`, `SyncFinished(SyncEvent)`. `content_status` is often
  already `Complete` when `InsertRemote` arrives; otherwise wait for
  `ContentReady` with the same hash. Remote content is downloaded
  automatically (default `DownloadPolicy::EverythingExcept([])`).
- After a restart a replica does not resume syncing on its own:
  `doc.start_sync(Vec<EndpointAddr>)` is required. `doc.get_sync_peers()`
  returns the ids (not addresses) of peers that were passed to `start_sync`,
  so the engine keeps its own `EndpointAddr` list.
- Neighbors learn each other through gossip: a late joiner that only knew the
  creator's address received `NeighborUp` for the other member as well.

### automerge 0.12

- `AutoCommit::new().with_actor(ActorId::from([u8; 32]))`, `AutoCommit::load(&bytes)?.with_actor(..)`,
  `save() -> Vec<u8>`, `merge(&mut other) -> Vec<ChangeHash>`, `get_heads()`,
  `commit()`, `pending_ops()`. Trait methods need `use automerge::{ReadDoc, transaction::Transactable}`.
- `get_all(ROOT, key) -> Vec<(Value, ObjId)>` returns every concurrent value.
  `ObjId` (the crate's `ExId`) is `Id(counter: u64, actor: ActorId, actor_index: usize)`
  and the `(counter, actor)` pair is identical on every replica, so the
  earliest-wins rule from SPEC.md section 5.1 is implementable as
  `min_by_key(|(_, id)| (counter, actor))`. Automerge's own `get` picks the
  **largest** `(counter, actor)`, so the rule is needed.
- Text: `put_object(ROOT, "text", ObjType::Text)`, `update_text(&obj, s)`,
  `text(&obj)`. Concurrent edits merge character by character
  (`"hello world\n"` edited to `"hello brave world\n"` and to
  `"hello world!\nsecond line\n"` merges to `"hello brave world!\nsecond line\n"`).
  `update_text` with identical content creates no op.
- **`put` of an identical scalar creates no op** when the register has a
  single value. A concurrent edit that leaves `kind = "blob"` unchanged is
  therefore invisible next to a concurrent `kind = "deleted"`: `get_all("kind")`
  shows only `deleted`, and CRD-6 cannot be evaluated on the schema in SPEC.md
  section 4. `put` on a register that currently holds several concurrent
  values always creates an op and collapses them, even with an identical
  value, which is exactly CRD-5.
- Snapshot sizes: a blob-mode document after 7 commits is 544 bytes; a text
  document with a merged three-line text is 329 bytes.

### biscuit-auth 6

- `KeyPair::new()`, `root.public().to_bytes_hex()`,
  `PublicKey::from_bytes_hex(&hex, Algorithm::Ed25519)`,
  `root.private().to_bytes()`, `PrivateKey::from_bytes(&bytes, Algorithm::Ed25519)`,
  `KeyPair::from(&private)`. `Algorithm` is `biscuit_auth::builder::Algorithm`.
- Macros `biscuit!`, `block!`, `authorizer!` from `biscuit_auth::macros`;
  parameters are written `{name}` in the Datalog text and bound with
  `name = value` (`&str`, `String`, `i64`, `bool`, `Vec<u8>`, `SystemTime`).
  `biscuit!(..).build(&root)?`, `token.append(block!(..))?`, `token.to_vec()?`,
  `Biscuit::from(&bytes, root_public_key)?` verifies the whole chain,
  `authorizer!(..).build(&token)?.authorize()?`.
- The spec's Datalog works as written: authority `vault("<ns>"); right("sync");`,
  attenuation `check if endpoint($e), $e == "<id>"; check if time($t), $t < <exp>;`,
  authorizer `endpoint("<id>"); time(<now>); check if vault("<ns>"); allow if right("sync");`.
  Wrong endpoint, expiry, other vault and other root key are all refused with
  distinct errors. Facts added in an attenuation block are scoped to that
  block and never satisfy the authorizer's policy, so a token cannot be
  widened by appending `right("sync")` or another `vault(..)`.
- Sizes: authority block 192 bytes; owner-attenuated invite (audience plus
  expiry) 413 bytes, 552 characters in base64; 21 blocks 3,255 bytes. The 4 KiB
  limit from SEC-3 leaves room for several delegation hops.
- **Checks accumulate, so an audience-bound token cannot be delegated to a
  different endpoint.** Block 1 `endpoint == alice` plus block 2
  `endpoint == bob` is satisfiable by nobody. Delegation only works from a
  token that carries no audience check yet (a bearer token with an expiry),
  which each hop narrows. See "design consequences" below.

### Auth hook against the real protocols

Adapted from `iroh/examples/auth-hook.rs` (iroh 1.2 checkout): one hook
struct implementing both `before_connect` (pre-authenticate to the remote over
the auth ALPN, through a task that owns an `Endpoint` clone because the hook is
built before the endpoint exists) and `after_handshake` (reject
`Side::Server` connections whose remote did not authenticate in the last 10
minutes), plus a `ProtocolHandler` that reads one token (`read_to_end(4096)`
with a 10 s timeout), verifies it with Biscuit and closes the connection with
code 1 (accepted) or 403 (denied). Measured:

- A client without hooks connecting to the docs, blobs and gossip ALPNs sees
  "closed by peer: not authenticated (code 403)" for each, and after importing
  the ticket has no entry after 3 s.
- Tokens for another endpoint and expired tokens are refused with the Biscuit
  check error; the admitted client keeps syncing throughout.
- Both directions are gated: the owner also pre-authenticates to the member
  before it can fetch the member's content, so every node holds its own token.
- Docs, gossip and the blobs downloader open connections concurrently, and
  each triggers a pre-auth handshake to the same remote; stage 4 de-duplicates
  in-flight handshakes per remote as the example does.

## Stage 0: measured numbers

Debug builds, loopback, macOS, 2026-09-21.

| Measurement | Value |
| --- | --- |
| Docs entry plus content, two nodes | 17 ms from `import_and_subscribe` to `ContentReady` |
| Late joiner, three entries with content | 62 ms |
| FastCDC 10 MiB, min 16 KiB, avg 64 KiB, max 256 KiB (normalization level 1) | 128 chunks, mean 80 KiB, smallest 17 KiB, largest 247 KiB |
| Chunks changed by a one-byte overwrite, or a one-byte insert | 1 |
| FastCDC 10 MiB at 8/32/128 KiB | 268 chunks, mean 38 KiB |
| Import 10 MiB as 128 chunks plus HashSeq into `FsStore` | 185 ms |
| `FsStore` on disk after that import | 11,542,528 bytes for 10,485,760 bytes of content, 129 files in `data/`; the difference (1,056,768 bytes) is the `blobs.db` size of an empty store, so the per-blob file overhead is nil and outboards live in redb |
| Full fetch of 10 MiB | payload 10,489,856 bytes (content plus 4,096-byte manifest), other 38,664 bytes (about 300 bytes per blob), 1.12 s |
| One-byte edit, two-step fetch | root 4,096 bytes, then 165,549 payload bytes (one chunk), 23 ms |
| One-byte edit through the `Downloader` after fetching the root | 52,042 bytes (one chunk), 39 ms |
| One-byte edit, one-step `hash_seq` fetch with the root missing | 10,489,856 bytes (full re-download) |
| Docs ticket with one loopback address | 128 characters |
| Empty `docs.redb` and `blobs.db` | 1,056,832 and 1,056,768 bytes |

Success criterion 2 (at most 3 new chunks) is met with margin: a one-byte
edit costs one chunk, because the maximum chunk size caps the blast radius.

## Stage 0: decision gate

Delta transfer works (with the two-step fetch) and the hook gates every ALPN.
The spec continues, with these design consequences.

## Stage 0: design consequences (deviations from SPEC.md)

1. **File document schema (section 4, 5.1, 6).** One register, `version`,
   holds a string that changes on every write:
   `deleted`, `text:<blake3 hex of the text>` or `blob:<manifest hex>:<size>`.
   The `text` object stays as specified and is never removed, so a text
   version that wins a mixed conflict, or a switch back to text mode, keeps
   its content. `visible` evaluates the winner rule over `get_all(ROOT, "version")`:
   drop `deleted` values when any other value exists (CRD-6); if every
   remaining value is `text:*` the visible content is the merged `text`
   object and nothing is flagged (CRD-2); otherwise the earliest
   `(counter, actor)` wins and the rest are losers (CRD-3, CRD-4). Reason:
   automerge drops identical `put`s, so separate `kind`/`manifest`/`size`
   registers cannot show a concurrent edit next to a concurrent delete.
   `apply_local` compares the parsed fields with the current winner; when the
   register is not in conflict and nothing changed it returns `false`, when it
   is in conflict it always writes (CRD-5).
2. **Blob export is two-step (section 5.2).** `export_blob_file` fetches the
   manifest as a raw blob first, then `remote().local(hash_seq).missing()` and
   the `Downloader` for the missing children. Otherwise the whole file is
   transferred again.
3. **Delegation (section 5.4, stage 4).** `invite --audience <id>` yields a
   token bound to that endpoint, which cannot be delegated. `invite --delegatable`
   yields a bearer token with only the expiry check; its holder must guard it
   like a password and can narrow it with `delegate --audience <id> --ttl ..`.
   SEC-2's "bound to the authenticated remote endpoint ID" applies to bound
   tokens only; a bearer token is bound by its expiry alone. The stage 4 gate
   test for delegation uses a delegatable parent token.
4. **Peers after restart (section 5.3).** The engine stores the
   `EndpointAddr`s it learns (ticket, `NeighborUp` plus `endpoint.remote_info`)
   under `.vault/` and calls `start_sync` with them at startup, because docs
   does not resume and remembers ids only.
5. **Gossip is constructed by us (section 2).** `Gossip::builder().spawn(endpoint)`
   is passed to `Docs::spawn` and mounted on the router; we still never publish
   or subscribe on it.
6. **Dependencies (section 3).** `n0-future` added; `fastcdc` 5.0 and
   `notify-debouncer-full` 0.7; `iroh-blobs` and `iroh-docs` with default
   features off plus `fs-store`.

The spike programs are kept under `examples/` for reference and reruns
(`cargo run --example spike_automerge`, `spike_biscuit`, `spike_fastcdc`
(use `--release`), and `spike_net [a|b|c]` for docs sync, delta transfer and
the auth hook). They are throwaway by design: no tests depend on them, and the
real modules are written from the API notes above, not by moving spike code.

## Stage 1: vault plumbing

- Module layout: `config.rs` (the `.vault/` layout, `config.json`, key files,
  `peers.json`), `node.rs` (endpoint plus blobs, gossip and docs on a router),
  `vault.rs` (one replica, one author, one node) and `cli.rs`. The crate is a
  library plus a thin `main.rs`, so `tests/` drive the same code as the binary.
- `.vault/` holds `config.json` (vault id, write flag), `endpoint.key` (hex
  iroh secret key, 0600), `vault.key` (the docs capability as
  `<kind byte><32 bytes>` in hex, 0600), `peers.json` (known `EndpointAddr`s),
  `addr.json` (this node's addresses, written by `run`), `blobs/`, `docs/`,
  `conflicts/`, `tmp/` and later `state.json`. All private files go through a
  temporary file and a rename.
- The namespace secret is stored in `vault.key` as well as inside
  `docs.redb`, because `invite` must work while `run` holds the redb files
  (redb takes an exclusive lock). `invite` therefore never opens the stores:
  it builds the `DocTicket` from `vault.key`, `endpoint.key`, `addr.json` and
  `--addr`. The only way to get the secret out of docs at `init` is
  `doc.share(ShareMode::Write, AddrInfoOptions::Id).capability`.
- `status` reports what it can from the files, then tries to open the stores
  for the entry count and says so when they are locked by a running node.
- `join` imports the capability with `import_namespace` (no sync) and stores
  the ticket's peers; syncing starts with `start_sync(peers)` in `run`, which
  `join` continues into, as the spec's command table says. On every
  `NeighborUp` the running node records the peer's current addresses
  (`endpoint.remote_info`) in `peers.json`, so the next start can call
  `start_sync` with real addresses; the ticket's peers seed the list.
- Every device uses the docs default author (`author_default`), which docs
  persists in `docs/default-author`.
- Network selection: `--loopback` (tests, demos: `presets::Minimal`, relays
  disabled, bound to `127.0.0.1:0`) versus the default `presets::N0`;
  `--bind <ip:port>` pins the UDP port so `--addr`-free invites stay valid
  across restarts.
- Read-only members: `Vault::set` refuses to publish and `invite --write`
  refuses on a read capability (SEC-6 groundwork; enforcement by the docs
  ticket itself is inherited).
- Gate tests (`tests/plumbing.rs`, 5 tests, about 1 s): both-way sync of
  entries including a 300 KiB value, late joiner catching up with two peers'
  entries and writing back, restart with entries and content intact and sync
  resuming from `peers.json`, read ticket holder cannot publish, and
  `init`/`open` refusing the wrong state. `tests/cli.rs` covers `init`,
  `whoami`, `invite` and `status`.
- `.vault/lock` is an advisory file lock (`std::fs::File::try_lock`, stable
  since Rust 1.89) taken by every process that opens the stores and held for
  the node's lifetime. Without it a second opener (`status` while `run` was
  active) blocked inside the redb open instead of failing, and the smoke test
  hung. With it, `status`, a second `run` or `Vault::open` fail immediately
  with "is in use by another process".
- With `RUST_LOG=info`, iroh-docs logs `sync failed ... Failed to close
  connection ... closed stream` once when two peers start syncing at the same
  moment: each side opens a sync connection to the other, one direction wins
  and the loser's connection is closed. The accept direction reports
  `sync finished` in the same millisecond and entries flow. Benign; left as is.
- Smoke test of the binary over loopback (`init`, `whoami`, `run --bind`,
  `invite` while `run` is active, `join`, `status`, Ctrl-C on both): both
  nodes see each other as neighbors and exit within a second of SIGINT.

## Stage 2: text files

- **Contract change (SPEC.md section 5.3, publishing step 2).** A local edit is
  not applied on top of the merge of every known version. `state.json` keeps,
  per path, the hash of the bytes on disk and the document heads those bytes
  came from. Publishing forks the merged document at those heads, applies the
  whole-file edit there (`update_text` diff) and merges the fork back. Applied
  on the merge directly, a save made against an older version reverted remote
  changes that had already reached the docs store but were not yet on disk:
  in the CRD-1 test, B's edit of line 3 turned A's fresh line 1 back to the
  old text. With the fork the result is the three-way merge. If the base heads
  are unknown to the document (should not happen) the engine falls back to
  applying on the merge and logs it.
- After publishing, the engine materializes the merged visible content, so a
  file whose local edit was combined with remote changes is rewritten with
  the merge at once; the apply flow does the same after publishing the local
  edit first (CRD-1 step 3).
- Every file document starts from a deterministic genesis change (fixed
  actor, time 0, one `put_object` creating the `text` object). Two devices
  that create the same path independently therefore share one text object
  and both initial texts survive the merge; without it Automerge would keep
  two concurrent text objects and show only one.
- `apply_local` semantics: with a single `version` value and identical
  visible content it is a no-op (echo suppression, also across restarts);
  with several concurrent values it always writes, which collapses the
  register (CRD-5). Concurrent text edits leave two `version` values that
  are not a conflict; the next echo or edit collapses them.
- Non-text files (over 1 MiB, containing NUL, or invalid UTF-8) are skipped
  with a log line until stage 3; a blob version arriving from a peer is
  skipped the same way.
- Watcher behavior on macOS (FSEvents through notify 8 and
  notify-debouncer-full 0.7, measured with `examples/spike_watcher.rs`):
  paths are reported canonical (`/private/var/...` for a `/var/...` root), so
  the engine canonicalizes the vault root once; `remove_dir_all` is reported
  as one event for the directory itself, without its contents; a rename
  reports only the destination path, for files and for directories alike.
  The watcher therefore forwards the paths of each debounce window as one
  batch, and the engine, after handling the batch (a directory: publish every
  file inside; a missing path: publish a deletion), reconciles: every key in
  `state.json` whose file is gone is published as deleted. That covers
  renames, moved directories and removed trees in one rule. Files inside
  `.vault/` never map to a key (`paths::key_from_path`).
- **Check and write share one read of the disk.** An apply first compared the
  file with `state.json` (CRD-1 step 3) and later re-read the file to write
  it. The directory-removal test hit the gap: the test removed the file
  between the two reads, the apply saw a missing file on its second read and
  recreated it from the remote document, and the deletion was never
  published. `materialize` now takes the hash the caller expects on disk,
  reads once, and returns `Outcome::LocalChange` instead of writing when the
  disk holds something else; the apply flow then publishes the local change
  and retries (at most three rounds). The remaining window is between that
  single read and the rename of the temporary file, microseconds, and is
  documented rather than closed: there is no portable compare-and-swap for
  files.
- `Engine::scan` runs after the watcher is attached: publish files whose
  hash differs from `state.json`, publish deletions for state entries with no
  file, then apply every key in the vault. Debug builds handle the three-node
  test files in well under a second.
- Read-only devices never publish (SEC-6); a local edit on such a device is
  overwritten by the next apply with a warning.
- Property test (`filedoc::tests::replicas_converge`, 200 cases): three
  replicas, random text, blob and delete writes and random pairwise syncs,
  then a full exchange; heads and visible state agree everywhere.
- Gate tests in `tests/textsync.rs` (5 tests, about 2 s): both-way sync with
  a pre-existing file, edits, delete, recreate and directory removal;
  offline catch-up with a partitioned concurrent edit merging line by line;
  CRD-1 through both the apply and the publish flow; hostile keys
  (`../evil.txt`, `/abs.txt`, `.vault/config.json`, `x/../../y.txt`,
  backslashes, `.` components) ignored with `.vault/config.json` intact; a
  read ticket holder materializes but never publishes.
- **Startup race with content downloads.** One run in fourteen of the text
  sync suite timed out at the 30 s deadline. A joiner's engine subscribes to
  live events after `start_sync` has begun; an entry whose insert event
  arrived before the subscription and whose content was still downloading
  when the startup scan ran was skipped by `load_merged`, and the
  `ContentReady` that followed found no key waiting for that hash, so the
  file was never written. `load_merged` now records `hash -> key` in the
  pending map whenever it skips a snapshot (re-checking availability after
  registering, to close the gap), and `PendingContentReady` applies every
  pending key as a safety net.

## Stage 3: blob files

- **Echo suppression is hash based, and identical content never resolves a
  conflict (CRD-5 narrowed).** After the engine materializes a file, the
  watcher reports the write back. With the register in conflict,
  `apply_local` treats any write as a resolving write, so the echo of the
  winner's own materialization on the winner's author resolved the conflict
  in its favor a moment after it appeared, and the flag and the loser's copy
  never became visible on the other peers. `publish_locked` now skips
  ingestion entirely when the bytes on disk hash to what `state.json`
  recorded: that is the engine's own write coming back. The consequence is
  that a user re-saving a conflicted file with byte-identical content does
  not resolve the conflict; a content change (or a future explicit resolve
  command) does. SPEC.md CRD-5 says "the next write"; here it means the next
  write that changes the bytes.
- `chunker.rs`: `import_blob_file` runs `StreamCDC` on a blocking thread and
  hands chunks (at most 256 KiB each) over a channel of depth 4 to the async
  side, which adds them with temporary tags; the `HashSeq` manifest gets a
  persistent tag `manifest/<hex>` and protects its children. Memory stays
  bounded by a few chunks regardless of file size. `export_blob_file` is the
  two-step fetch from stage 0 (manifest as a raw blob, then the missing
  children through the `Downloader` with every known peer as provider) and
  streams the chunks into a temporary file that is renamed into place.
- Text detection reads files up to 1 MiB in full; larger files are hashed in
  a streaming pass and are blobs regardless of content (a 1.2 MiB UTF-8 file
  is a blob, as SPEC.md section 4 says). The blob import is a second pass
  over the file; if the file changes between the two passes the next watcher
  event republishes it.
- `state.json` entries carry the manifest of a materialized or published blob
  version. A blob whose disk hash and manifest are both recorded is
  recognized without chunking again; a remote blob version whose manifest
  equals the recorded one is not re-exported.
- Conflicts: `conflicts.json` under `.vault/` lists every path whose merged
  document has losing versions (kind, 8 hex digits of the manifest or text
  hash, 8 hex digits of the actor); the engine updates it on every
  materialize, and `status` and `conflict list` read it without opening the
  stores. The loser's author gets `.vault/conflicts/<key>.<8 hex>` written
  automatically (CRD-4); other peers run `vaultsync conflict export <dir>
  <path>`, which needs the stores and therefore a stopped node, or the
  library's `Engine::export_conflicts`, which fetches the loser's chunks from
  peers. A losing text version is exported as the merged text, because the
  losing edits live inside the shared text object.
- A blob whose chunks cannot be fetched (no peer known, or the only provider
  offline) fails the apply with a logged error and is retried on the next
  `NeighborUp` or `PendingContentReady`.
- Gate tests in `tests/blobsync.rs` (3 tests, about 16 s in a debug build):
  a 10 MiB random file present before start transfers byte-identical (over
  40 chunk-sized blobs), a one-byte edit brings at most 3 new chunk-sized
  blobs (measured through the receiving blob store's inventory), and B's
  edit flows back; a partitioned concurrent binary edit ends with the same
  winner on both peers (a tie on the Lamport counter, decided by actor id),
  the loser's author holding a copy, `conflicts.json` flagging the path on
  both, on-demand export on the other peer fetching the loser's chunks, and a
  new write clearing the flag everywhere; a text file becoming binary and
  back, an over-1 MiB text file as a blob, and blob deletions.

## Stage 4: admission

- `auth.rs` adapts iroh's `auth-hook` example: one `AuthHook` implements both
  hook methods (`before_connect` pre-authenticates through a channel to the
  `AuthTask`, which owns the bound endpoint and de-duplicates in-flight
  handshakes per remote; `after_handshake` rejects `Side::Server`
  connections on any ALPN but the auth ALPN unless the remote was admitted
  within the last 10 minutes), plus `AuthProtocol` (a `Semaphore` of 16
  permits taken with `try_acquire`, so the 17th handshake is refused at once
  rather than queued; `read_to_end(4096)` under a 10 s timeout; close code 1
  or 403). The example's `n0-error`/`n0-future` helpers were replaced by
  `anyhow` and `tokio`; no new dependency. Tokens are never logged; the
  `AuthConfig` `Debug` impl prints only the token length (SEC-5).
- **The vault namespace is generated by us at `init`, not by
  `docs.create()`.** The owner's own token must name the vault id before the
  node binds with the hook, and docs creates the id only after the node
  exists. `NamespaceSecret::from_bytes(SecretKey::generate().to_bytes())`
  uses iroh's CSPRNG (no `rand` dependency) and `import_namespace` creates
  the replica.
- Every device holds a token, the owner included: `init` mints the owner a
  token bound to its own endpoint for 365 days and `open` re-mints it from
  the root key when it no longer verifies (expired, corrupt, missing). A
  member whose token expired cannot `open` and is told to ask for a new
  invite. The client side of `join` verifies that the invite would admit
  this device before storing anything, so a wrong-audience or expired invite
  fails with an explanation rather than with silent peers.
- Invite format: `vaultsync1.` plus base64url of JSON `{ticket, token, root,
  delegatable}`. About 1 KB for a bound write invite with one address. The
  `invite` command works for the owner (mints from `root.key`) and for a
  member whose token is delegatable (narrows its own token); without
  `--audience` it prints a bearer invite and says so on stderr. `--ttl`
  takes seconds or `s`/`m`/`h`/`d`/`w` (default `7d`). There is no separate
  `delegate` command; a member's `invite` is the delegation.
- `Config` gains `root_public_key` and `token_delegatable`; `.vault/` gains
  `root.key` (owner only) and `token`, both 0600. A vault without
  `root_public_key` (none can be created any more) runs without admission
  and logs a warning.
- Tests use bearer invites for convenience (`Peer::write_invite`), so every
  existing suite now runs with admission on; the auth suite adds bound
  invites and `whoami`-first joins.
- Gate tests in `tests/auth.rs` (4 tests, about 3 s): SEC-1 (a hookless node
  is closed with 403 on the docs, blobs and gossip ALPNs and its sync
  attempt fails), SEC-2 (wrong audience, expired, other root key, other
  vault: the presenting node's own hook is denied and never connects; the
  admitted member keeps syncing; a wrong-audience invite is refused by
  `join`), delegation (bearer invite to B, B narrows to a bound read-only
  10-minute invite for C, C reads and cannot publish or delegate, C's token
  presented by a stranger is refused, a widened token is refused by the
  other vault and by the verifier), SEC-3 (a stalled auth connection is
  closed with 403 after the server's timeout, a 5 KB token is refused,
  members are unaffected and a new one joins), and owner re-minting plus
  member expiry.
- Incoming docs syncs for a namespace are rejected (`AbortReason::NotFound`)
  until `start_sync` has opened it, and `doc.share(..)` calls
  `start_sync(doc_id, [])` internally. Stage 1's `init` obtained the
  namespace secret through `share`, which silently opened the owner's
  replica for sync; stage 4 generates the namespace itself and no longer
  calls `share`, so the owner must call `start_sync` like every other node
  (`run` always did; the plumbing tests now do too).
- Binary smoke over loopback: `init`, `whoami` on the new device, `run`,
  `invite --write --audience <id> --ttl 1h` (1,277 characters), a stranger's
  `join` with the same invite refused with the audience check in the error,
  the invited device syncing a file within 400 ms, its bound token refusing
  to delegate, and both processes exiting within 100 ms of Ctrl-C.

## Stage 5: hardening and end to end

- **Docs downloads an entry's content only from the peer that sent the
  entry.** In the three-node partition test, C received B's entry through a
  sync whose connection then flapped, docs gave up on the download, no
  `ContentReady` came, and C waited forever. `load_merged` now fetches a
  missing snapshot itself through the blobs downloader with every known peer
  as provider (5 s timeout), registers the key for retry on the next peer
  event, and `InsertRemote` triggers an apply even while the content status
  is not yet complete.
- **The outgoing pre-authentication cache broke reconnection after a
  restart.** The `auth-hook` example remembers remotes it authenticated to
  and skips the handshake; with a 9-minute memory, a peer that restarted
  (empty admitted set) closed every cached connection with 403 until the
  memory expired, and blob downloads from it failed with "Unable to
  download". The cache now lasts 3 s (enough to coalesce the connections the
  protocols open together), and the hook watches every outgoing connection
  through a `WeakConnectionHandle`: a close with code 403 tells the task to
  forget that remote, so the next connection authenticates again. The
  receiving side keeps the 10-minute admission from the spec.
- Resource limits: `Limits { max_file_bytes (1 GiB), max_entries (100,000) }`,
  overridable per vault in `config.json` (`max_file_bytes`, `max_entries`).
  An oversized file is never published (logged once per attempt); a new path
  beyond the cap is not published, existing paths still update, and remote
  content still materializes. The path count is refreshed by each scan.
- Crash safety: files reach the folder only through `.vault/tmp/` and a
  rename, so a kill leaves either the old file or the new one, never a
  partial one. `Engine::new` removes leftovers from `.vault/tmp/`, and an
  unreadable `state.json` is set aside as `state.json.corrupt` (every file
  then looks new and is re-published only if it differs from the vault). A
  crash between a publish and the state update is repaired by the next scan:
  the file hashes differently from the state, is re-ingested, and
  `apply_local` finds nothing new.
- Gate tests in `tests/e2e.rs` (6 tests): criteria 1 and 2 with three nodes
  (10 MiB to B and C, one-byte edit costs each 1 to 3 chunk-sized blobs),
  criterion 4 for text and binary on three nodes (same winner on all three,
  loser copy at its author, on-demand export at the bystander, flag cleared
  everywhere by C's write), criterion 5 (C offline while A deletes, B edits
  and adds, A replaces a blob; C converges on restart), criterion 3 with a
  fourth hookless node closed with 403 by all three members on every ALPN and
  an expired invite refused by `join`, a real `vaultsync join` process killed
  with SIGKILL while materializing a 10 MiB file (restart converges, no
  partial file, no temp leftovers, no spurious version), and the limits.
  Measured under the full parallel suite in a debug build: 10 MiB to both
  peers in about 7 s, the one-byte edit in about 6 s, C's catch-up in under
  a second; the partitioned test alone finishes in 2.3 s.

## Open questions from SPEC.md section 10

1. Automerge text merging applies to every file that is valid UTF-8, has no
   NUL and is at most 1 MiB; no extension allow-list was added.
2. Conflict copies are automatic for the loser's author and on demand for
   other peers (`conflict export`, or `Engine::export_conflicts`), as
   specified.
3. Read versus write stays with docs tickets; Biscuit decides admission,
   audience, expiry and delegation only.

## Measured size of the custom code

SPEC.md section 2 estimated the custom code and asked for measurements.
Lines excluding unit tests, at the end of stage 5:

| Piece (SPEC.md) | Estimate | Measured | Files |
| --- | --- | --- | --- |
| Auth (Biscuit plus hooks) | 250 | 632 | `auth.rs` 515, `invite.rs` 117 |
| File documents and winner rule | 300 | 384 | `filedoc.rs` 310, `paths.rs` 74 |
| Chunker, manifest, assembler | 200 | 199 | `chunker.rs` |
| Sync engine, watcher, state file | 500 | 1,196 | `engine.rs` 1,131, `watcher.rs` 65 |
| CLI, config, invite, node, vault | 250 | 1,328 | `cli.rs` 302, `config.rs` 348, `node.rs` 217, `vault.rs` 432, `lib.rs`, `main.rs` |

About 3,700 lines of non-test code against an estimate of 1,500; the engine
(three-way merge against the on-disk base, conflict copies, retries, limits)
and the vault and config plumbing (keys, tokens, peers, invites, lock) carry
most of the difference. Tests: 1,840 lines in `tests/` plus unit tests in
the modules; 50 tests, the whole suite in about 44 s in a debug build. The
stage 0 spike programs under `examples/` are another 1,440 lines.
