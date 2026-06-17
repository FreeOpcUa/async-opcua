# Quickstart — Build, Test & Validate (feature 009)

How to build, test, benchmark, and gate this feature. Everything below runs from the repo root. This
is the verification harness behind the Success Criteria; `/speckit-tasks` will reference these commands
in per-finding tasks.

## 1. Build matrix (SC-008 — all three MUST be warning-free)

```bash
cargo build --workspace                              # default features
cargo build --workspace --all-features               # everything (pulls pubsub/TLS, sqlite, etc.)
cargo build --workspace --no-default-features         # legacy crypto EXCLUDED (FR-019 / M12)
cargo clippy --workspace --all-targets -- -D warnings # warning-free gate
```

## 2. Tests

```bash
cargo test --workspace                  # unit + integration
cargo test --workspace --all-features   # include feature-gated paths (websocket, metrics, pubsub)
cargo test -p async-opcua-crypto        # crypto: incl. cross-backend RSA round-trip (FR-042)
cargo test -p async-opcua-types         # decode: incl. recursion-DoS regression tests (FR-001 / C1)
cargo test -p async-opcua-server        # limits, authN, tick (Tracks B/C/E)
cargo test -p async-opcua-client        # robustness, sockets, cert trust (Track D)
```

**Regression-test convention (Constitution I/II)**: each behavioral fix lands with a test that FAILS
before the fix and PASSES after. Crash findings (C1, C2, H7, M1) ship a reproduction test that panics
on the pre-fix code and returns a clean error after (SC-001).

## 3. Fuzzing (Track A — recursion DoS, FR-001)

```bash
cargo +nightly fuzz run fuzz_deserialize   -- -max_total_time=120
cargo +nightly fuzz run fuzz_dynamic_struct -- -max_total_time=120
cargo +nightly fuzz run fuzz_comms          -- -max_total_time=120
# Run with a constrained stack to surface recursion DoS the existing corpus missed.
```

## 4. Benchmarks (Track E — FR-030 / P12; land BEFORE the optimizations they measure)

```bash
cargo bench -p async-opcua-server   # existing: session_lookup, notification_pool
cargo bench -p async-opcua-types    # NEW: encode/decode throughput (ReadRequest, large array, ByteString)
cargo bench -p async-opcua-core     # NEW: encode_into -> apply_security -> verify round trip
                                    #      across None / Sign / SignAndEncrypt
```
Capture a baseline at the start of the feature; SC-006/SC-007 compare against it (latency with NODELAY,
secured-path per-chunk allocation count, idle-server CPU with many idle subscriptions).

## 5. Dependency-advisory gate (Track G — FR-022 / P1)

```bash
cargo deny check advisories bans sources   # uses deny.toml; rsa Marvin recorded as exception
```
Use a `cargo-deny` version that parses CVSS-4.0 advisories (the previously-installed one aborts).

## 6. Interop gate (HARD release gate — FR-046 / SC-010)

```bash
# .NET interop
cd dotnet-tests && dotnet build && cd ..
cargo test -p external-tests            # drives the dotnet TestServer/clients

# open62541 interop
ls 3rd-party/open62541                  # build per its harness; run against the Rust server/client
```
**No change may alter the OPC-UA wire format**; both harnesses MUST pass in CI before any item is done.

## 7. Codegen reproducibility (Track H — FR-036)

```bash
# after editing async-opcua-codegen to drop unsafe impls / derive binary impls:
cargo run --bin async-opcua-codegen code_gen_config.yml
cargo fmt
git status --porcelain    # MUST be empty -> ci_verify_clean_codegen passes
```

## 8. Definition of done (per finding)

A finding is `fixed` only when: its task's regression test passes; the build matrix (§1) is green; the
relevant tests (§2) pass; and — for anything touching decode/crypto/transport — the interop gate (§6)
passes. Otherwise it is `deferred` with a written rationale (SC-009). Every public-API break (catalog
in `contracts/public-api-changes.md`) has a `CHANGELOG.md` entry before release (SC-011).
