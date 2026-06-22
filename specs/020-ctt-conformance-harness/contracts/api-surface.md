# API Surface: Conformance Test Harness

No public library API changes. Additions:

## US1 — `async-opcua/tests/integration/conformance.rs` (Claude)
- A `#[tokio::test]` (single, sequential — flakiness-safe) that iterates the RSA matrix via
  `Tester::new(default_server(), ..)` and the ECC matrix via `Tester::new_ecc(P256/P384)`, calling
  `tester.connect(policy, mode, token)` per cell and running Read/Browse/Write/Subscribe helpers; plus
  negative-credential assertions. Registered as `mod conformance;` in the integration test entry.
- A module doc-comment (US4) stating: proxy nature (our own client, not an independent authority),
  services exercised, and UACTT areas not covered.

## US2 — `samples/demo-server` (codex)
- `sample.server.ecc.conf`: ECC endpoints + token ids (mirrors the RSA conf shape).
- `src/main.rs`: read a config path / profile from an arg or env (e.g. `--config`/`OPCUA_DEMO_CONFIG`),
  default = existing RSA conf; for the ECC profile provision an EC application cert into the PKI `own/`
  dir and `create_sample_keypair(false)`. Default (no arg) behavior byte-identical to today.

## US3 — docs + script (Claude/codex)
- `docs/ctt-conformance.md`: UACTT obtain/install (Windows VM), build/run both profiles, cert cross-trust,
  UACTT endpoint + test-group setup, expected-results/known-gaps table.
- `run-conformance.sh <rsa|ecc>`: clean PKI, launch the profile, print endpoint URLs + server cert
  SHA1/SHA256 thumbprints to trust.

## Invariants
- Default demo-server behavior unchanged; no new library dependency; ECC = separate server instance;
  `clippy --all-targets --all-features` clean; existing suites pass; smoke surfaces (never hides) a broken
  matrix cell.
