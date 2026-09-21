# Current state and resume point

Snapshot: 2026-09-21, after the `stage 10: end-to-end and adversarial tests`
commit. All ten stages of SPEC.md section 12 are implemented. Every commit on `master` passes `scripts/gate.sh` (fmt, check, clippy
`-D warnings`, test).

## Where we are

| Stage (SPEC.md section 12) | State | Commit |
| --- | --- | --- |
| 1 Project skeleton | done | `stage 1: project skeleton` |
| 2 Capabilities and hashing | done | `stage 2: capabilities and hashing` |
| 3 Chunker and manifest | done | `stage 3: chunker and manifest` |
| 4 Storage | done | `stage 4: storage` |
| (deps) current crate versions | done | `deps: move to current stable crate versions` |
| 5 Protocol and authorized serving | done | `stage 5: protocol and authorized serving` |
| 6 Gossip signaling | done | `stage 6: gossip signaling` |
| 7 Sync engine and parallel fetcher | done | `stage 7: sync engine and parallel fetcher` |
| 8 File watcher | done | `stage 8: file watcher` |
| 9 CLI | done | `stage 9: CLI` |
| 10 End-to-end and adversarial tests | done | `stage 10: end-to-end and adversarial tests` |

Test count at this point: 67 unit tests in `src/`, 7 integration tests in
`tests/transport.rs`, 3 in `tests/gossip.rs`, 18 in `tests/sync.rs`, 5 in
`tests/watcher.rs`, 4 in `tests/cli.rs`, 5 in `tests/e2e.rs`. The whole gate takes about two minutes on a warm target
dir (`tests/sync.rs` is about 13 s, `tests/watcher.rs` about 4 s).

Decisions already made (do not re-litigate):

- Dependencies are the current stable releases (iroh 1.2.0, iroh-gossip
  0.101.0, bincode 2, redb 4, rand 0.10, ed25519-dalek 3, fastcdc 5,
  notify 8, thiserror 2). SPEC.md section 4 and NOTES.md record why.
- One commit per stage, named `stage N: <title>`; gates run before each.
- `NodeId` in the spec means iroh 1.x `EndpointId`.

## Module state

| File | State |
| --- | --- |
| `src/lib.rs` | modules, `Hash`, `VersionId` |
| `src/crypto.rs` | complete |
| `src/capabilities.rs` | complete |
| `src/clock.rs` | complete (`Hlc`, `HlcClock`, `physical_now_ms`, `unix_now_secs`) |
| `src/chunker.rs` | complete |
| `src/manifest.rs` | complete (`validate`, `validate_file_name`, `confined_path`) |
| `src/protocol.rs` | complete (messages, limits, `encode`/`decode`, `read_frame`/`write_frame`) |
| `src/storage.rs` | complete (`Store` incl. `record_version`, `MemStore`, `RedbStore`) |
| `src/transport.rs` | complete for stages 5 and 7 server side: `bind_endpoint` → `BoundEndpoint { endpoint, addr_book }`, `router_builder`, `SyncProtocol` (serves all four requests), `ConnectionPool`, `get_chunk`/`get_manifest`/`get_heads`/`get_version` |
| `src/gossip.rs` | complete: `SyncMessage` with `new_version`/`have` constructors, `signing_payload`, `verify_signature`, `validate_message` (six checks), `LruSet<DedupKey>`, `GossipNode` (spawn, `alpn`, `handler`, `subscribe`, `shutdown`), `TopicSubscription` (`joined`, `neighbors`, `broadcast`, `next_announcement` → `RawAnnouncement`) |
| `src/sync.rs` | complete: `DocContext`, `VersionInfo`, `decide`/`commit_decision`, `ParallelFetcher` (`fetch_missing` → `FetchReport`), `SyncEngine` (`publish_local_change`, `publish_from`, `publish_file`, `apply_remote`, `handle_announcement`, `catch_up`, `catch_up_any`, `repair_unwritten_heads`, `validate_frame`, `heads`, `rejections`, `take_recent_write`, events), `spawn_gossip_driver`, `spawn_catch_up_task` |
| `src/watcher.rs` | complete: `FileWatcher::spawn(engine)`, `subscribe` → `WatcherEvent`, `stop`; `DEBOUNCE` 500 ms |
| `src/cli.rs` | complete: `Cli`/`Command` (clap), `Config`/`Loaded`/`Invite`, `init`, `whoami`, `invite`, `join`, `start` → `Running`, `status`, `execute` |
| `src/main.rs` | parses args, sets up tracing, calls `cli::execute` |
| `tests/common/mod.rs` | `TestNode` (`spawn`/`spawn_with(store)`, router serving sync + gossip ALPNs, `Arc<dyn Store>`, `Arc<ConnectionPool>`, `gossip`, `secret()`, `know()`), `Doc` (owner key, token issuing), `Harness` (node + `SyncEngine` + outbox + events + temp doc dir), `payload`, `version_by`, `seed`, `vid`, `past_hlc`, `with_timeout`, `test_data` |
| `tests/transport.rs` | stage 5 tests |
| `tests/gossip.rs` | stage 6 tests |
| `tests/sync.rs` | stage 7 tests, with a `Misbehaving` store wrapper for corrupt and substituted data |
| `tests/watcher.rs` | stage 8 tests |
| `tests/cli.rs` | stage 9 tests, including a two-node `start` sync |
| `tests/e2e.rs` | stage 10: success criteria 1 to 4, late joiner, provider stopped mid-transfer |
| `README.md` | CLI flow and how to run the gates |

## Resume here: the spec is implemented

Every stage is done and every gate passes. Natural follow-ups, none started:

- **Spec follow-ups.** Section 14's future work: streaming chunking, token
  delegation and revocation, deletions and renames, garbage collection,
  paginated `GetHeads`, per-peer rate limits, merge tooling.
- **`status` while running.** redb's `SingleWriter` concurrency mode (behind
  its `experimental-multiprocess` feature) would let `status` read the store
  while `run` holds it; today `status` reports `StoreBusy`.
- **Real-network trial.** Everything is tested on loopback with relays
  disabled. Running two machines through the `N0` preset (relays plus pkarr
  address lookup) has not been tried; `invite --addr` exists for LANs.
- **Release build timing.** All timings in this file are debug builds.

## Gotchas learned so far

- `cargo fmt` reformats files right after they are written; anchor-based
  patch scripts must run before `fmt` or match the formatted text.
- clippy `unwrap_used` is denied crate-wide; `allow-unwrap-in-tests` covers
  `#[test]` functions and `cfg(test)` modules only, so helpers in
  `tests/common/mod.rs` use `expect`.
- redb 4 `Key` is implemented for `&[u8; N]`, not `[u8; N]`.
- bincode 3.0.0 on crates.io is an empty placeholder; the crate uses 2.0.1.
- `RedbStore::put_chunk` costs about 5 ms per chunk in a debug build
  (`Durability::Immediate`); tests use `MemStore`.

## Useful commands

```sh
./scripts/gate.sh                       # the four gates, in order
cargo test --test transport             # stage 5 network tests only
cargo test --lib storage                # one module's unit tests
RUST_LOG=debug cargo test --test transport -- --nocapture
```
