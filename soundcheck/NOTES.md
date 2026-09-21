# Implementation notes

Deviations from `SPEC.md`, API differences found against the pinned crates,
and decisions the spec left open. One entry per item, newest last.

## Stage 1

- `Cargo.toml` sets `rust-version = "1.76"`, copied from iroh 0.28.1's
  manifest as section 4 instructs.

## Stage 3

- `FileManifest::validate` rejects two cases beyond the section 5 list, both
  in the spirit of SEC-9: a `file_name` whose first component is `.p2p-sync`
  (a remote manifest could otherwise overwrite `config.toml` or `node.key`),
  and any `:` in the name (the simplest robust "no drive prefix" rule; it also
  keeps names portable to Windows).
- `manifest::confined_path` implements the "resolved path is inside the
  document directory" check from section 8 step 5. It canonicalizes the
  deepest existing ancestor of the target so a symlink inside the document
  cannot redirect a write outside it.

## Stage 4

- `protocol::encode` / `protocol::decode` and the limit constants were written
  in this stage rather than stage 5, because `RedbStore` serializes manifests,
  versions and heads through them (section 6: never mix in plain
  `bincode::serialize`). The wire messages themselves arrive in stage 5.
- `gossip::SyncMessage` is defined in this stage as a plain data type with
  accessors, because `Store::version` and `Store::heads` return it. Signing,
  validation and the topic subscription follow in stage 6.
- `Store::mark_written` returns `HeadMoved` when the head is no longer the id
  passed, so a stale writer cannot mark a newer head as written by mistake.
- `commit_version` and `switch_branch` also run `FileManifest::validate` and
  check `manifest.id() == version.manifest_id` and the document ID, so an
  inconsistent commit is refused before anything is written.
- `redb` composite keys use tuples (`([u8; 32], [u8; 32])`, `([u8; 32], &str)`),
  which redb 2.6 supports directly, so no 64-byte concatenated key was needed.

## Dependency modernization (before stage 5)

- Decision (user, 2026-09-21): target current stable crates instead of the
  first draft's 2024 pins. Resolved set: iroh 1.2.0, iroh-gossip 0.101.0,
  fastcdc 5.0, ed25519-dalek 3.0, rand 0.10, bincode 2.0 (`serde` feature),
  redb 4.3, notify 8.2, thiserror 2.0, tokio 1.47+, clap 4.5+, proptest 1.7+,
  tempfile 3.20+. `rust-version` is 1.91, copied from iroh 1.2.0.
- Why not iroh 0.28: besides being two years old, iroh-net 0.28.2 carries a
  crate-level `#![deprecated]` (the crate was renamed to `iroh`), which fails
  the `-D warnings` gate. Pinning iroh-net 0.28.1 was tried and worked, but
  the user chose the current release instead.
- `bincode` 3.0.0 on crates.io is an empty crate (zero-line `lib.rs`), so
  "current" bincode is 2.0.1. The codec now uses
  `bincode::config::standard().with_little_endian().with_variable_int_encoding().with_limit::<CODEC_LIMIT>()`
  and `bincode::serde::{encode_to_vec, decode_from_slice}`. bincode 2 has no
  `reject_trailing_bytes`; `protocol::decode` compares the bytes consumed with
  the input length instead. The limit is a const generic, so one ceiling
  (`CODEC_LIMIT` = the response limit, 2 MiB) is compiled in and the
  per-direction limits are checked around it.
- `rand` 0.10 has no `OsRng`; `rand::rng()` (thread-local CSPRNG, reseeded
  from the OS) is used for keys, document IDs and salts. `rand::Rng` is the
  core trait with `fill_bytes`.
- `redb` 4 implements `Key` for `&[u8; N]`, not `[u8; N]`, so table keys are
  `&[u8; 32]` and tuples of references. Behavior is unchanged.
- iroh 1.x API notes are in SPEC.md section 4 ("iroh calls to verify").
  The handler trait is `accept(&self, Connection)`, so `SyncProtocol` keeps
  its state in an inner `Arc` and is `Clone`; `Router::builder(..).accept(ALPN, handler)`
  takes the handler by value. `EndpointId`/`EndpointAddr` replace
  `NodeId`/`NodeAddr`; the spec keeps saying `NodeId` for the concept.
- Dialing peers by ID needs an address lookup in iroh 1.x. `bind_endpoint`
  registers a `MemoryLookup` address book (`BoundEndpoint::addr_book`) that
  tests and the CLI fill from exchanged `EndpointAddr`s or invites.

## Stage 5

- `GetHeads` and `GetVersion` are served from this stage rather than stage 7:
  the dispatch is one match arm each and they share every check with
  `GetChunk` and `GetManifest`. Stage 7 adds their clients' use (catch-up and
  ancestor walking), not the server side.
- iroh 1.2's `ProtocolHandler::accept` returns `Result<(), AcceptError>`, so
  `anyhow` is not needed in `transport.rs` after all; it stays reserved for
  `main.rs`.
- `Response` carries a narrow `#[allow(clippy::large_enum_variant)]` with a
  comment: `Version(SyncMessage)` is a few hundred bytes next to a one-byte
  `Error`, a response lives only until it is encoded, and boxing would change
  the section 6 contract.
- On an oversize request frame the server calls `RecvStream::stop` and
  `SendStream::reset` (SEC-7). The client may then see either a reset error
  or an empty finished stream depending on timing, and the test accepts both.
- Integration test helpers live in `tests/common/mod.rs` with a commented
  `#![allow(dead_code)]`: each test binary uses a different subset. Helpers
  outside `#[test]` functions must use `expect`, because
  `allow-unwrap-in-tests` covers only test functions and `cfg(test)` modules.
- Test nodes bind with `presets::Minimal`, `RelayMode::Disabled`,
  `clear_ip_transports()` and `bind_addr(127.0.0.1:0)`, and exchange
  `EndpointAddr`s through the `MemoryLookup` address book. The full stage 5
  network suite runs in well under a second.

## Stage 6

- `bytes = "1"` was added to `Cargo.toml` (not in the section 4 table):
  iroh-gossip 0.101 broadcasts and delivers `bytes::Bytes` and does not
  re-export the type. It was already in the dependency tree.
- iroh 1.2 has its own `iroh::Signature` type, distinct from
  `ed25519_dalek::Signature` even though both are 64 bytes. The wire types
  keep the dalek type (section 5 and 7 contracts); `gossip::sign_with_endpoint_key`
  and `gossip::verify_with_endpoint_id` convert through `to_bytes`/`from_bytes`.
- `validate_message` takes `doc_id`, `owner_key`, `now_secs`, `physical_now_ms`
  and the topic's `LruSet<DedupKey>` as parameters, so tests control time and
  the sync engine (stage 7) can share one de-duplication set per topic.
- The de-duplication set is a true LRU (a hit refreshes the key), built from
  a `HashMap` plus a `BTreeMap` keyed by insertion sequence; no extra crate.
- The subscription wrapper (`GossipNode`, `TopicSubscription`) returns raw
  announcements (`bytes` plus `delivered_from`); validation is a separate step
  because it needs the caller's clock and de-duplication state.
- iroh-gossip 0.101 has no `Joined` event; `TopicSubscription::joined` wraps
  `GossipReceiver::joined`. `subscribe` returns immediately and dials the
  bootstrap IDs through the endpoint's address lookup, so tests enter peer
  addresses with `TestNode::know` first.
- The gossip actor's default maximum message size (4 KiB) is left alone; the
  1 KiB limit from section 7 is enforced on our payloads by `validate_message`
  and `SyncMessage::encode`.

## Stage 7

- **Contract change (SPEC sections 8 and 9 updated in this commit):**
  `Store::record_version` was added. The convergence proptest found that a
  node which bootstraps on a non-root version (a late joiner hearing the
  current head first) cannot later find the fork point for a concurrent
  branch, because its local chain has unknown ancestors; the branch was
  dropped and nodes diverged. Now, before bootstrapping on a version whose
  parent is unknown, the engine fetches the ancestors with `GetVersion`
  (at most 64), validates them and stores the signed messages with
  `record_version` (no content, no head change). If they cannot be fetched
  the bootstrap proceeds without ancestry, as section 8 originally allowed.
- `decide` is the pure case table over the store and `commit_decision` its
  storage side, so the proptest runs with `MemStore` and no network. The
  engine composes them with manifest and chunk fetching, preservation of
  displaced bytes, atomic writes and announcements.
- A remote version's file name lives in its manifest, so the manifest is
  fetched (from the local store if committed, else from providers, with its
  ID recomputed and `validate` run) before the per-file lock is taken.
- Gap filling releases the per-file lock before recursing, and the async
  recursion is boxed (`Box::pin`), which the compiler requires.
- `publish_from(file, bytes, base)` passes the caller's base head straight to
  the store's compare-and-set, so the CON-1/CON-2 test exercises the real
  `HeadMoved` path rather than a pre-check.
- The fetcher uses up to 32 worker tasks in a `JoinSet` pulling from a shared
  queue, with a per-provider semaphore of 16; a fatal error aborts the set.
  Provider health (3 consecutive failures → skipped for 60 s) is shared
  across manifests of the same engine.
- `ConnectionPool::connect` is wrapped in a 10 s `CONNECT_TIMEOUT`
  (added to `protocol.rs`). In practice iroh fails a dial to a peer with no
  address in well under a second, which `connect_to_unknown_peer_fails_promptly`
  asserts, so retries against a dead provider stay fast.
- Announcements leave the engine through an `mpsc` outbox; `spawn_gossip_driver`
  bridges the outbox and a `TopicSubscription`. Tests read the outbox
  directly to assert that a rejected publish broadcast nothing.
- The `tests/sync.rs` suite takes about 13 s, dominated by the dead-provider
  backoff and the 70-version chain fixture.

## Stage 8

- Echo suppression is content based only: the watcher calls
  `SyncEngine::publish_file`, which chunks the file and returns `Unchanged`
  when the manifest equals the head's. `take_recent_write` exists on the
  engine but the watcher does not use it: a time-window skip would swallow a
  real edit made within the window after an engine write. The cost is one
  chunking pass per engine write.
- macOS FSEvents reports canonical paths (`/private/var/...`) while callers
  may pass a symlinked document directory (`/var/...`), so `classify` strips
  either prefix. Paths become `/`-separated relative names and are checked
  with `validate_file_name`; directories, `.p2p-sync/**` and invalid names
  are reported as `WatcherEvent::Skipped` so tests can observe them without
  waiting.
- notify 8's callback runs on its own thread; it forwards into a tokio
  unbounded channel and the debounce loop runs on the runtime with one
  deadline per path (500 ms, reset on every event).
- The "edit during remote apply" test relies on the apply finishing before the
  500 ms debounce fires (it takes tens of milliseconds on loopback). If it
  did not, the watcher would publish the edit first and the remote version
  would then win the fork (CON-6), so the asserted outcome (winner on disk,
  edit kept under `rejected/`) holds either way.
- `tests/watcher.rs` takes about 4 s because each test waits out several
  debounce windows to prove that nothing else is published.

## Stage 9

- `src/cli.rs` is a library module not listed in section 10: it holds the
  command implementations so `tests/cli.rs` can drive `init`, `invite`,
  `join`, `start` and `status` directly. `main.rs` only parses arguments,
  sets up `tracing` and calls `cli::execute`.
- `toml = "1"` was added (not in section 4) for `config.toml`. Bootstrap
  peers are stored as plain strings (`id`, `addrs`, `relays`) rather than
  serde-derived `EndpointAddr`s so the file stays readable.
- Key files (`node.key`, `owner.key`) hold the 32-byte secret as hex text;
  they and `config.toml` are written with mode 0600 on Unix.
- The invite is the hex encoding of a bincode `Invite` (document ID, owner
  key, salt, token, bootstrap `EndpointAddr`s). `invite --addr` adds direct
  socket addresses of the inviting node so peers without relays or address
  lookup (loopback, LAN) can dial it; with the production `N0` preset the ID
  alone is enough. `join` refuses an invite whose token audience is not this
  node (SEC-2) or whose token does not verify against the invite's owner key.
- `run` publishes files that already exist in the directory and have no head
  or differ from it before starting the watcher, so a directory populated
  before the first `run` is shared. This is not in the spec's stage 9 table.
- redb's default `ExclusiveWriter` mode locks the whole file while `run` is
  active, so `status` opens the store read-only (`RedbStore::open_read_only`)
  and reports `StoreBusy` while a node runs instead of a raw backend error.
  The concurrent `SingleWriter` mode is behind redb's `experimental-multiprocess`
  feature and was not enabled. Known providers live only in the running
  engine, so `status` says so rather than printing them.
- `tests/cli.rs` includes a full `start` → `start` loopback sync in both
  directions, which exercises the `run` wiring without the blocking ctrl-c wait.

## Stage 10

- `spawn_gossip_driver_gated` adds an on/off `watch` switch to the gossip
  driver: offline, it holds outgoing announcements and drops incoming ones,
  which is how the end-to-end test partitions A and B for success criterion
  4. `spawn_gossip_driver` is the always-online case. After reconnecting,
  the test calls `catch_up` explicitly on both sides, as the periodic task
  would after at most 5 minutes.
- Criterion 2 is asserted through `SyncEvent::Applied { fetched_chunks }`
  on B and C for the second version's ID (at most 3 chunks); criterion 1
  through byte-identical files and the first version's fetch count (over
  300 chunks for 10 MiB).
- The read-only-for-write part of criterion 3 is tested end to end: a member
  with a read token joins the topic and announces a `NewVersion`; no node
  stores it or changes a head, while the same token still reads chunks.
- The "wrong document" token in criterion 3 must be issued by the real owner
  for another document ID; a token from another issuer fails earlier as
  `Unauthorized` (SEC-1), which is correct but tests SEC-1, not SEC-3.
- The three-node suite runs in about 5 s on loopback in a debug build,
  including the 10 MiB transfer to two peers.
