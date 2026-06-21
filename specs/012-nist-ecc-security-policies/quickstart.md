# Quickstart / Verification: NIST ECC Security Policies

All commands from the workspace root. Stories are layered (US1→US2→US3); each is independently
checkable.

## Baseline gate (before any change)

```bash
cargo fmt --all --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --workspace
cargo test -p async-opcua --test integration_tests   # 98-test suite
```

## US1 — ECC primitives (SC-003)

- Known-answer tests in `async-opcua-crypto`: ECDSA P-256/SHA-256 and P-384/SHA-384 sign+verify vs
  NIST/RFC vectors; verification rejects tampered input. ECDH: two key pairs derive the same shared
  secret matching a vector. HKDF derivation: shared-secret + spec salts → expected SigningKey/
  EncryptingKey/IV bytes.

## US2 — EC certificates (FR-007)

- Load a P-256 and a P-384 application cert; assert curve/public key parsed and thumbprint computed;
  an expired/untrusted cert is rejected; a cert whose curve ≠ policy is rejected.

## US3 — ECC_nistP256 channel end to end (SC-001)

- Loopback test: server with an `ECC_nistP256` `Sign` endpoint + client connect → channel opens,
  both sides derive identical keys, signed service call succeeds. Repeat for `SignAndEncrypt`. Renew
  the channel → new keys, traffic continues.
- Negative tests (SC-004): malformed/short ephemeral key, wrong curve, RSA cert on ECC policy,
  non-canonical signature → rejected with a protocol error, no panic.

## US4 — ECC_nistP384 (SC-002)

- Repeat the US3 loopback + negative tests with an `ECC_nistP384` endpoint in both modes.

## US5 — negotiation / config / rollout (SC-005)

- Mixed RSA+ECC server config round-trips; ECC-capable client negotiates ECC; RSA-only client still
  negotiates RSA unchanged; `ecc` feature off → ECC requested = cleanly unsupported, RSA/None
  byte-identical.

## Cross-cutting

- Fuzz the ECC handshake/decode path: `cargo +nightly fuzz run fuzz_comms --features nightly --
  -max_total_time=<n>` → zero aborts.
- Interop (SC-007): if a reference ECC peer (open62541 / UA-.NET ECC endpoint) is available, connect
  our client to it and theirs to our server in both modes; otherwise document the gap and rely on
  vectors + loopback.

## Final gate (every story / before each per-story commit)

```bash
cargo fmt --all --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --workspace
```
One commit per user story; one task per codex dispatch; generated code untouched.
