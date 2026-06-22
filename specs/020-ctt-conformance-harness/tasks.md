---
description: "Task list for feature 020 — OPC UA conformance test harness (CTT)"
---

# Tasks: OPC UA Conformance Test Harness (CTT)

**Input**: design docs in `/specs/020-ctt-conformance-harness/`. Conformance backlog "biggest lever".

**Verification division**: the CI smoke IS the conformance test → **Claude authors + runs it**; codex does
the demo-server ECC profile/selection + the launch script (sample/production code). One commit per story.
Gate: `cargo fmt --all --check && cargo clippy --all-targets --all-features --locked -- -D warnings &&
cargo test -p async-opcua --test integration_tests --features ecc conformance -- --test-threads=1`.

**Pinned facts (research.md):** `Tester` (`async-opcua/tests/utils`) already provides `default_server()`
(RSA matrix: None/Basic128Rsa15/Basic256/Basic256Sha256/Aes128Sha256RsaOaep/Aes256Sha256RsaPss ×
Sign+SignAndEncrypt, each w/ ANONYMOUS+user+x509), `Tester::new`, `new_ecc(curve)`, `connect(policy,mode,
token)`, `client_user_token()` (sample1), `client_x509_token()`. ECC = separate server instance
(single-cert constraint; 012 mixed-cert deferred). Real UACTT is Windows/proprietary → out of CI; the
smoke is the Linux proxy. User can run the real UACTT on a Windows VM (US3 = turnkey).

## Phase 1: Setup
- [X] T001 Confirm the `Tester` API + `default_server` policy/token set + `connect`/`client_user_token`/
  `client_x509_token` + `new_ecc`; identify a Read node (`Server_ServiceLevel`), a Browse target
  (RootFolder), a writable node (TestNodeManager/setup), and the subscription/monitored-item pattern from
  `core_tests.rs`/`ecc.rs`. No code change.

## Phase 2: US1 — CI conformance smoke (P1) 🎯 MVP
- [X] T002 [US1] Claude: `async-opcua/tests/integration/conformance.rs` — a sequential `#[tokio::test]`
  iterating the RSA matrix (`Tester::new(default_server())`, every policy×mode) and ECC matrix
  (`new_ecc(P256)`, `new_ecc(P384)`, Sign+SignAndEncrypt) × {Anonymous, UserName(sample1), X509}; per
  valid cell: connect+`wait_for_connection`, Read(ServiceLevel), Browse(RootFolder), Subscribe+MI receive
  a data change, (Write if a writable node is available), disconnect — assert each. Surface (fail on) any
  broken cell. Register `mod conformance;` in the integration entry. (depends T001)
- [X] T003 [US1] Claude: negative cells — wrong-password UserName → activation `Err` (BadUserAccessDenied/
  BadIdentityTokenRejected); a token/policy-mismatch case → documented StatusCode. No silent skips.
- [X] T004 [US4] Claude: module doc-comment in conformance.rs — proxy nature (our own client, not an
  independent authority), services exercised, UACTT areas not covered.
- [X] T005 [US1] Gate (`-- --test-threads=1`, verify in isolation per flakiness practice); **commit US1+US4**
  (`test(020 US1): CI conformance smoke across the full security/token matrix`).

## Phase 3: US2 — demo-server ECC profile + RSA coverage (P2)
- [X] T006 [US2] codex: add `samples/demo-server/sample.server.ecc.conf` (ECC_nistP256/P384 Sign+
  SignAndEncrypt; ANONYMOUS + user + x509 token ids; ECC discovery url). Mirror the RSA conf shape.
- [X] T007 [US2] codex: `samples/demo-server/src/main.rs` — select the config via an arg/env (e.g.
  `--config <path>` or `OPCUA_DEMO_CONFIG`), default = existing RSA conf (byte-identical default
  behavior); for the ECC profile provision an EC application cert (`X509::cert_and_pkey_ecc`,
  `create_sample_keypair(false)`) into the PKI `own/` dir. Verify the RSA conf has a `None` endpoint + all
  3 token types (fill gaps if any). (depends T006)
- [X] T008 [US2] Claude: a small test/assertion that both configs parse + build a server (RSA default
  unchanged; ECC profile loads with EC cert) — or verify via `cargo run -- --help`/a smoke build. Gate;
  **commit US2** (`feat(020 US2): demo-server ECC profile (separate EC cert) + config selection`).

## Phase 4: US3 — UACTT run guide + launch script (P2)
- [X] T009 [US3] Claude: `docs/ctt-conformance.md` — obtain/install UACTT (Windows VM); build+run both
  demo-server profiles; cert provisioning + cross-trust (server cert → UACTT trusted, UACTT client cert →
  server `pki/trusted/`); UACTT project setup (endpoint URLs per profile, policy/mode, sample1 / x509
  credentials, applicable test groups: Security, SecureChannel/Session, Attribute Read/Write, View/Browse,
  Subscription/MonitoredItems, Base/Embedded profile); expected-results / known-gaps table (Tier 3 facets).
- [X] T010 [US3] codex/Claude: `samples/demo-server/run-conformance.sh <rsa|ecc>` — clean PKI, launch the
  chosen profile, print endpoint URLs + server cert SHA1/SHA256 thumbprints to trust. Executable, shellcheck-clean.
- [X] T011 [US3] Gate; **commit US3** (`docs(020 US3): UACTT run guide + launch/cert script`).

## Phase 5: Polish
- [X] T012 Update `specs/conformance-gap-backlog.md`: note the CTT harness (smoke + demo profiles + guide)
  shipped; link the known-gaps table.
- [X] T013 Final gate: fmt + clippy --all-targets --all-features + the conformance smoke (isolated) +
  `cargo run -p async-opcua-demo-server -- --help` (config selection) + existing integration suite spot-check.

---

## Dependencies & Execution
- Setup (T001) → US1 (T002–T005, the runnable MVP) → US2 (T006–T008, codex demo profile) → US3
  (T009–T011, docs+script) → Polish. codex: T006, T007, T010(script). All test/doc tasks = Claude. One
  commit per story.

## Notes
- Real UACTT out of CI (Windows/proprietary); the smoke is a documented proxy (our own client). ECC =
  separate server instance. Deferred: mixed RSA+ECC single-cert server (012); the Tier 3 facets themselves
  (documented known-gaps).
