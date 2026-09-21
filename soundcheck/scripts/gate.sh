#!/usr/bin/env bash
set -euo pipefail
cargo fmt --check
cargo check --all-targets
cargo clippy --all-targets -- -D warnings
cargo test
