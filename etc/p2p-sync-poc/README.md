# p2p-sync-poc

A local-first, peer-to-peer file sync engine — research and a validation experiment, not yet a working implementation.

## How the pieces fit together

Three documents in `doc/`, in the order they were actually produced, each answering the question the one before it left open:

1. **`doc/SPEC.md`** — a from-scratch design: custom wire protocol, custom storage, custom capability tokens, custom conflict resolution. Complete, buildable, and roughly ten implementation stages of original code.
2. **`doc/SPEC2.md`** — the same requirements, redesigned to reuse existing libraries (`iroh`, `iroh-docs`, `iroh-blobs`, Automerge, Biscuit) instead of hand-rolling the plumbing SPEC.md builds from scratch. Cuts the custom code from roughly ten stages to five small pieces. This is the recommended path; SPEC.md stays as the fallback if a specific piece of the reused stack turns out not to fit.
3. **`doc/EXPERIMENT.md`** — SPEC2 depends on claims about `iroh`'s transport layer (NAT traversal, relay fallback, multi-path, docs catch-up) that were checked against documentation, not against a real network. This is the stage-0 spike that checks them for real, across actual geography, before any of SPEC2's five pieces get built.

The rest of the repo (`src/`, `ops/`) is that experiment's actual code and tooling — not the DistNet product itself.

## Status

Builds cleanly against `iroh` 1.2.0 / `iroh-docs` 0.101.0 / `iroh-blobs` 0.103.0 / `iroh-gossip` 0.101.0, with no remaining `// CHECK` spots. All six scenarios are wired into `run_scenario.sh`. The docs/blobs path (share, join, export, and offline catch-up into a reused doc) and the harness flow (push, discover, scenario 4 with the ticket hand-off, logs, stop) have been run locally, with two nodes on one machine, through n0's public relay and discovery. The harness's DigitalOcean and remote-ssh paths haven't been run yet. Nothing has been run across real geography yet; that's the experiment itself.

## Quick start

From your laptop (tool setup: `doc/EXPERIMENT.md` section 4):

```sh
./ops/harness.sh build        # Linux (glibc) build + native macOS build
./ops/harness.sh up           # create the anchor droplets on DigitalOcean
./ops/harness.sh push         # copy the probe to every node
./ops/harness.sh discover     # collect endpoint ids, write peers.txt everywhere
./ops/harness.sh logs         # in a second terminal: every node's events, merged
./ops/harness.sh scenario 1
./ops/harness.sh collect      # -> results/<date>/<node>.log
./ops/harness.sh down         # delete the droplets
```

`home` and `cell` aren't droplets: list them in `ops/harness.hosts` (`home local` for this laptop; `cell` through a reverse ssh tunnel). Topology, per-scenario steps and what to watch for: **`doc/EXPERIMENT.md`**.

## Layout

```
p2p-sync-poc/
├── Cargo.toml
├── src/
│   ├── main.rs        — connection watcher (NAT/relay/migration scenarios)
│   └── docs.rs          — docs+blobs module (transfer/catch-up scenarios)
├── ops/
│   ├── harness.sh         — create droplets, push, discover, run, watch, collect, tear down
│   └── run_scenario.sh      — per-scenario dispatch, runs on each node
├── doc/
│   ├── SPEC.md            — from-scratch design (fallback)
│   ├── SPEC2.md             — reuse-based design (recommended)
│   └── EXPERIMENT.md          — this experiment, in full
└── results/                     — pulled logs land here, one dated dir per run
```

Each node gets a flat `~/exp` directory with the probe and `run_scenario.sh`; `doc/EXPERIMENT.md` section 2 has the details.
