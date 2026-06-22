# Quickstart / Verification: Conformance Test Harness

## US1 — CI conformance smoke (Linux, runnable here)
```bash
# sequential / isolated for reliability under the known parallel-load flakiness
cargo test -p async-opcua --test integration_tests --features ecc conformance -- --test-threads=1
```
Every valid (policy × mode × token) cell connects + Read/Browse/Write/Subscribe; negatives reject with the
right StatusCode; no cell skipped.

## US2 — demo-server profiles
```bash
cargo run -p async-opcua-demo-server                      # RSA profile (default, unchanged)
cargo run -p async-opcua-demo-server -- --config samples/demo-server/sample.server.ecc.conf   # ECC profile
```

## US3 — real UACTT (user's Windows VM)
- Follow `docs/ctt-conformance.md`: obtain UACTT, run a profile via `run-conformance.sh`, cross-trust
  certs (printed thumbprints), point UACTT at the endpoint URLs, run the applicable test groups, and use
  the known-gaps table to separate expected (Tier 3) failures from real ones.

## Final gate
```bash
cargo fmt --all --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test -p async-opcua --test integration_tests --features ecc conformance -- --test-threads=1
cargo run -p async-opcua-demo-server -- --help    # config selection works; default unchanged
```
