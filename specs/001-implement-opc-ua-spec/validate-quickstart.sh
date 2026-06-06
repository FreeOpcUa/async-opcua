#!/usr/bin/env bash
set -euo pipefail

cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features
cargo test --workspace --all-features
