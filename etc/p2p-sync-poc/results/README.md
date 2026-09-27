# results/

Pulled `probe.log` files land here, one dated subdirectory per run:

```
results/
└── 2026-09-28/
    ├── anchor-us.log
    ├── anchor-asia.log
    ├── home.log
    └── cell.log
```

`./ops/harness.sh collect` populates it; `doc/EXPERIMENT.md` section 10 has the `jq` commands for reading it.

Raw logs only — no secrets should end up in them, but double-check before pushing this directory anywhere shared (a node's `probe-data/secret.key` copied alongside a log file is the realistic failure mode, not the logs themselves).

This directory is empty until you've actually run something.
