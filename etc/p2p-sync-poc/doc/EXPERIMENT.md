# Geo-distributed iroh experiment

Date: 2026-09-27. Supersedes both earlier drafts of this guide. API calls are grounded against the real `iroh` 1.2.0 / `iroh-docs` 0.101.0 / `iroh-blobs` 0.103.0 source, downloaded directly from static.crates.io and read line by line — not from docs.rs search snippets, which were serving stale, inconsistent cached versions across different queries. The earlier `// CHECK` spots have since been settled against a real compiler; see section 5.

This is the stage-0 spike referenced in `doc/SPEC2.md`: before committing engineering time to the full sync engine, confirm that the transport layer it depends on (NAT traversal, relay fallback, multi-path, iroh-docs catch-up) actually behaves as the docs claim, on real networks, not just in loopback tests.

## 0. What changed since the last draft

- `Endpoint::conn_type()` does not exist in 1.2.0 — it never got renamed on the same type, the whole mechanism moved. Connection path visibility now lives on `Connection`, not `Endpoint`: `conn.paths()`, `conn.paths_stream()`, `conn.path_events()`. A connection can hold multiple simultaneously open paths at once, each independently `is_ip()`/`is_relay()`/`is_selected()`, with its own `rtt()` — richer than the old four-variant enum, and better suited to watching migration and multi-path directly.
- Construction takes a `Preset` argument (`Endpoint::builder(presets::N0)`), not a method chain (`.discovery_n0()` doesn't exist either).
- Transport is `noq` (n0's own QUIC implementation), confirmed in the real `Cargo.toml`, not just described in unreleased-branch prose.
- `EndpointId` is a type alias for `PublicKey`; it converts directly into `EndpointAddr`, so sharing the bare ID string as text is enough for discovery to resolve the rest.
- `iroh-docs` already ships `Doc::import_file`/`export_file`, driving `iroh-blobs` internally — no need to hand-roll chunking for this experiment.
- This draft folds the code and the ops guide into one project layout (section 2), and restores a "collecting results" step that a prior rewrite accidentally dropped (section 10).
- Coordination runs from your laptop over plain ssh (`ops/harness.sh`), replacing the Telegram relay. Telegram bots can't see each other's messages, so its automatic `/registered` discovery couldn't have worked, and the relay accepted commands from anyone who messaged the bot. Telegram stays only for send-only progress posts (section 9.2).

## 1. What this answers

1. What fraction of connections between real-world NAT types end up with an `ip` path vs a `relay` path?
2. Does a connection ever hold more than one open path at once, and does `is_selected()` favor direct over relay when both are available?
3. Does a network change (wifi → cellular) produce a new path on the same `Connection`, visible via `paths_stream()`, or does the connection close and a fresh one get dialed?
4. How long does iroh-docs catch-up take for a peer that was offline, and does `import_file`/`export_file` transfer time scale with how much changed rather than total history?

Out of scope: the Biscuit auth hook and the conflict rules from `doc/SPEC2.md` — neither needs geography, both stay on loopback in that spec's own stage 0/4.

## 2. Project layout

```
p2p-sync-poc/
├── README.md              — orientation: how everything here fits together
├── Cargo.toml              — the probe binary's manifest
├── src/
│   ├── main.rs              — connection watcher (scenarios 1-3, 5)
│   └── docs.rs               — docs+blobs module (scenarios 4, 6)
├── ops/
│   ├── harness.sh             — runs everything from your laptop over ssh
│   ├── harness.hosts           — optional: nodes that aren't droplets (home, cell)
│   └── run_scenario.sh          — per-scenario dispatch, runs on each node
├── doc/
│   ├── SPEC.md               — from-scratch custom protocol design (fallback reference)
│   ├── SPEC2.md               — the recommended design: reuse iroh-docs/blobs/automerge
│   └── EXPERIMENT.md            — this file
└── results/
    └── README.md               — convention for where pulled logs and summaries land
```

Each node gets a flat `~/exp` directory: `probe`, `run_scenario.sh`, and the `peers.txt` / `ticket.txt` the harness writes there. `probe.log`, `probe.pid` and `probe-data/` appear once a scenario runs. The harness keeps its own state in `ops/.harness/`: its `known_hosts`, the collected ids, and the directories of nodes that run on the laptop itself.

## 3. Topology

All-public-IP topologies teach you nothing about NAT — there's nothing to punch through. The useful signal comes from mixing public anchors with real NAT'd nodes.

| Node | Role |
| --- | --- |
| `anchor-us` | Cheap VPS, US — public IP |
| `anchor-asia` | Cheap VPS, Singapore or Tokyo — public IP, cross-continent baseline |
| `home` | Your laptop, Warsaw home wifi — residential NAT |
| `cell` | Laptop tethered to a phone, or a phone directly — CGNAT |

Provisioning: cheapest VPS tier at any provider, Ubuntu 24.04, default firewall — don't pre-open ports, the point is testing hole-punching and relay fallback as they'd actually behave for a real user.

## 4. Prerequisites

Nothing needs installing on the nodes: the harness copies the probe over. It's built against glibc 2.31, so it runs on Ubuntu 20.04 and anything newer, including the droplets' 24.04.

On your laptop:

```sh
brew install doctl zig jq
cargo install cargo-zigbuild
rustup target add x86_64-unknown-linux-gnu
doctl auth init                                              # paste a DigitalOcean API token
doctl compute ssh-key import harness --public-key-file ~/.ssh/id_ed25519.pub
```

Use a different key with `HARNESS_KEY=~/.ssh/<key>` (the private key's path; its `.pub` is what DigitalOcean gets).

## 5. The probe

`src/main.rs` runs the watch protocol (scenarios 1-3, 5). `src/docs.rs` adds blobs, gossip and docs to the same endpoint and `Router` (scenarios 4, 6), and is only switched on by `--share <file>` (the sharing side) or `--join <ticket>` (the receiving side). Everything compiles against the real crates, and the earlier `// CHECK` spots are settled.

Everything a node needs to keep across restarts lives in `probe-data/`:

| File | What it's for |
| --- | --- |
| `secret.key` | The endpoint key. It keeps the node id stable, so `peers.txt` entries and doc tickets survive a restart. Scenario 6 depends on this. |
| `doc_id.txt` | The sharing node's doc. Later `--share` runs import into the same doc, so the ticket stays the same. |
| `ticket.txt` | The doc's read ticket. It holds no namespace secret, so it's safe to post in the group. |
| `blobs/`, `docs/` | The blob and doc stores. |
| `out/` | Each synced file, exported on the receiving side once its content is ready. |

The docs log lines:

| Kind | Meaning |
| --- | --- |
| `import_done` | Import finished on the sharing side (key, hash, size, time taken). |
| `docs_event` | A doc sync event. `InsertRemote` carries key, hash, size and content status; `ContentReady` fires once the blob is downloaded and verified. |
| `export_done` | The file was written to `probe-data/out/`. |
| `doc_ticket` | The ticket to hand to the receiving nodes. |

Build once, locally, on whichever machine has the toolchain from section 4:

```sh
cargo build --release
```

`cargo check` first if you just want to confirm it compiles without a full build.

## 6. Setting up the nodes

```sh
./ops/harness.sh build       # Linux build for the droplets, native build for the laptop
./ops/harness.sh up          # create anchor-us (nyc3) and anchor-asia (sgp1), wait for ssh
./ops/harness.sh push        # copy the right build + run_scenario.sh to every node
./ops/harness.sh discover    # collect every node's endpoint id, write peers.txt everywhere
```

`HARNESS_NODES` changes the droplets, e.g. `HARNESS_NODES="anchor-us:nyc3 anchor-eu:fra1 anchor-asia:sgp1"`. `run_scenario.sh` only pairs `anchor-us` and `anchor-asia`, so give any extra anchor its own case there before relying on it. The settings can also go in `ops/harness.env`.

`home` and `cell` aren't droplets. List them in `ops/harness.hosts` so the harness can reach them:

```
home  local                                              # this laptop
cell  me@localhost -o Port=2222 -J root@<anchor-us ip>   # through a reverse tunnel
```

- **`local`** runs the node on the laptop itself, in `ops/.harness/nodes/home`. The laptop is `home`, so that's the natural choice.
- **`cell`** sits behind CGNAT, so nothing can ssh into it directly. From `cell`, open a reverse tunnel to an anchor, with Remote Login (sshd) enabled on `cell`:

  ```sh
  ssh -N -R 2222:localhost:22 root@<anchor-us ip>
  ```

  The harness then reaches `cell` through the anchor. The tunnel is ordinary outbound TCP, separate from the probe's own UDP traffic. Use `-o Port=N` rather than `-p N` in `harness.hosts`, because the options go to both ssh and scp.

Re-run `push` after every `build`, and `discover` whenever a node joins. Ids stay the same across restarts, because each node keeps its key in `probe-data/secret.key`.

## 7. Running each scenario

Every scenario is `./ops/harness.sh scenario <n> [node]`. With a node, only that node runs its part. Keep `./ops/harness.sh logs` open in a second terminal throughout.

**Scenario 1 — anchor ↔ anchor baseline.** `scenario 1`. Watch for a `paths` event with `kind:ip, selected:true`. Confirms the harness before adding NAT'd nodes.

**Scenario 2 — anchor ↔ home NAT.** `scenario 2`. Watch for `home`'s path list to converge on an `ip` path selected, possibly after an initial `relay`-only period while hole-punching completes.

**Scenario 3 — anchor ↔ cellular CGNAT.** `scenario 3`. Expect `relay`-only more often, or a path list that never gets an `ip` entry — an expected result for CGNAT, not a harness failure.

**Scenario 4 — file transfer via iroh-docs.**
1. On `home`, create the test file in its experiment directory (`ops/.harness/nodes/home/` when `home` is `local`): `head -c 300000000 /dev/urandom > testfile.bin`.
2. `scenario 4 home`. `home` imports the file, and the harness copies the doc ticket to every other node.
3. `scenario 4 anchor-us`, and wait for its `export_done`.
4. `scenario 4 anchor-asia` and `scenario 4 cell`, one straight after the other.

Time from `InsertRemote` to `ContentReady` on each node is the transfer signal. For the changed-file comparison, change one byte of `testfile.bin` on `home` and run `scenario 4 home` again. It keeps the same key, doc and ticket, so the joined nodes pick the change up without rejoining.

Expect the changed file to transfer in full. iroh-blobs addresses content by its whole-file BLAKE3 hash, so a one-byte change is a new blob with nothing in common with the old one. What stays small is the doc sync: one replaced entry, not the whole history.

**Scenario 5 — connection migration.** `scenario 5`. It uses the same `cell` ↔ `anchor-asia` pairing as scenario 3. While the connection is open, toggle `cell`'s network (wifi off, cellular on, or the other way round). The question is whether `paths_stream()` yields a new path on the *same* connection (a new path appears, then the old one closes), or whether the connection closes and a fresh `connected` shows up. Either outcome is informative.

**Scenario 6 — offline catch-up.**
1. Run this after scenario 4, so `cell` already holds the first file.
2. `stop cell`, and wait 10+ minutes.
3. Create `catchup.bin` next to `testfile.bin` on `home`, then `scenario 6 home`. This adds the file as a new entry in the same doc.
4. `scenario 6 cell`.

Measure the time from `cell`'s new `started` line to its last `ContentReady`. `probe.log` is appended to across runs, so scenario 4's lines are still there above it.

## 8. Metrics to watch

| Metric | Source |
| --- | --- |
| Path `kind` (ip/relay) and `selected` over time | `paths` log lines |
| Number of concurrent open paths per connection | length of the `paths` array in each log line |
| Time from `connected` to first `selected:true, kind:ip` | delta between log lines |
| Gap in path events across a migration | scenario 5 |
| `InsertRemote` → `ContentReady` gap, full vs incremental | `docs_event` log lines |
| Time from doc rejoin to last expected `ContentReady` after restart | scenario 6 |

## 9. Monitoring

### 9.1 In the terminal

- **`./ops/harness.sh logs [lines]`** follows every node's `probe.log` in one terminal, one line per event, prefixed with the node name: `[home] 21:20:45 docs_event c324ad04 InsertRemote key=...`. iroh's own warnings are passed through as-is.
- **`./ops/harness.sh status`** shows whether each node's probe is running, plus its last log line.
- **`./ops/harness.sh stop [node]`** stops the probe cleanly, so the doc and blob stores are saved.

The harness only needs ssh, so run it from the laptop, and keep that laptop awake during a run: `home` lives on it too.

### 9.2 Progress posts to Telegram (send-only)

_Status: specified, not implemented yet._

To follow a run from your phone, the harness also posts progress to a private Telegram chat. It is **send-only**. It calls `sendMessage` and nothing else: it never calls `getUpdates`, never reads the chat and never accepts commands. Control stays in the harness, over ssh.

**Who posts.** `harness.sh logs` already follows every node's log, so the posts go out from the laptop, as a side effect of `logs`. The token then lives in one place, the nodes need no network access beyond the experiment itself, and a single sender keeps within the rate limit below. If `logs` isn't running, nothing gets posted.

**Setup.**
1. Create a bot with @BotFather (`/newbot`) and keep the token.
2. In BotFather, set `/setjoingroups` to Disable (after adding the bot to a group, if you use one), and leave `/setprivacy` enabled.
3. Send the bot a message, then read your chat id from `https://api.telegram.org/bot<TOKEN>/getUpdates`. This is a one-time manual lookup; the harness never calls it.
4. Put both in the laptop's environment or in `ops/harness.env`, never in a file that gets copied to a node:

   ```sh
   HARNESS_TG_TOKEN=123456789:AAH...
   HARNESS_TG_CHAT=123456789
   ```

   With either one unset, `logs` works as before and posts nothing.

**What gets posted.** One short line per message, `[node] kind detail`, trimmed to about 200 characters:

| Event | Posted |
| --- | --- |
| `started`, `connected`, `disconnected`, `accepted`, `connect_failed` | always |
| `paths` | only when the path list for that peer differs from the last one posted (kind and selected, ignoring RTT) |
| `import_done`, `export_done`, `export_failed`, `docs_error` | always |
| `docs_event` | only `InsertRemote` and `ContentReady` |
| `doc_ticket`, iroh warnings, anything that isn't a JSON event | never |
| harness actions: `scenario <n> [node]` started, `stop`, `down` | always |

**Rate limit.** Telegram allows a bot about 20 messages a minute in a group (about 1 a second in a private chat). The poster queues messages and sends at most one every 3 seconds. When the queue backs up, for example during a migration test, it merges what's waiting into one message (`[cell] 14 more events, see probe.log`) instead of falling behind. HTTP 429 responses are retried after the `retry_after` they give.

**Best-effort.** A post that fails is dropped and never stops or slows `logs`. `probe.log` on each node remains the record; the posts are for watching, not for results.

**Security.**
- The token only allows posting as the bot. A leaked token lets someone post fake progress, but not control anything, because nothing reads the chat.
- The posts go through Telegram's servers unencrypted. They carry node names, endpoint ids, path kinds, file names and sizes, and nothing secret. Doc tickets aren't posted.
- Revoke the token after the run (section 12).

## 10. Collecting and reading results after a run

The write-up data is each node's full `probe.log`. It's appended to across runs, so it keeps every scenario, each starting with its own `started` line:

```sh
./ops/harness.sh collect      # -> results/<date>/<node>.log
```

Don't try to merge the four files into one global timeline by wall-clock — cross-continent clock skew makes that noisy and it isn't needed for what these scenarios measure. Instead, compute deltas *within* each node's own log (time between its own `connected` and its own first `ip`-path event, time between its own restart and its own last catch-up event in scenario 6), then compare those deltas across nodes. A short `jq` pass per file gets you there:

```sh
jq -c 'select(.kind=="paths")' "results/$(date +%Y-%m-%d)/home.log"
jq -c 'select(.kind=="docs_event")' "results/$(date +%Y-%m-%d)/anchor-asia.log"
```

`results/README.md` in this repo has the convention for naming and keeping these — one dated subdirectory per run, raw logs only, no secrets (the logs shouldn't contain any, but check before committing anywhere shared).

## 11. What this does and doesn't prove

Validates transport-layer behavior: path selection (ip vs relay), multi-path/migration visibility, and docs/blobs transfer and catch-up timing — against APIs read from real source, not assumed from documentation snippets. It says nothing about the Biscuit auth hook or the conflict rules from `doc/SPEC2.md`, which don't need geography and stay on loopback in that spec's own stage 0/4.

## 12. Cost and cleanup

Two VPS instances for a day: under $1 total. Destroy them after the run with `./ops/harness.sh down`, which deletes every droplet tagged `p2p-sync-poc` after asking. If you set up Telegram posts, revoke the bot token in BotFather (`/mybots` → the bot → API Token → Revoke).
