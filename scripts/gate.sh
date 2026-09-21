#!/usr/bin/env bash
# The four quality gates from SPEC.md section 8, in order. Every commit must pass.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== gate 1/4: cargo fmt --check"
cargo fmt --check
echo "== gate 2/4: cargo check --all-targets"
cargo check --all-targets
echo "== gate 3/4: cargo clippy --all-targets -- -D warnings"
cargo clippy --all-targets -- -D warnings
echo "== gate 4/4: cargo test"
cargo test
echo "== all gates passed"
