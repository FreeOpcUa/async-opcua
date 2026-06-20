---
description: "Task list for feature 012 — NIST ECC security policies"
---

# Tasks: NIST ECC Security Policies (ECC_nistP256 / ECC_nistP384)

**Input**: Design documents from `/specs/012-nist-ecc-security-policies/`
**Prerequisites**: plan.md, spec.md, research.md (crypto SPEC-PINNED from Part 6 §6.8 + UA-.NETStandard),
data-model.md, contracts/api-surface.md, quickstart.md

**Tests**: INCLUDED — security-critical crypto; constitution Principle I/IV require known-answer
vectors + negative tests, each failing before the change and passing after.

**Execution discipline**: one task per codex dispatch; verify the failing test first; **one commit per
user story** (the closing gate-&-commit task). Gate before each per-story commit:
`cargo fmt --all --check && cargo clippy --all-targets --all-features --locked -- -D warnings && cargo test --workspace`.
All ECC code behind the `ecc` cargo feature; existing RSA/None paths stay byte-identical.

**Crypto is pinned (research.md):** ECDSA raw `r‖s` (P1363); ephemeral key `X‖Y` no prefix (64/96 B);
IKM = ECDH x-coord; HKDF salts `L‖"opcua-client/server"‖nonce‖nonce` (L=16-bit LE), Extract `HMAC-Hash(salt,IKM)`,
RFC 5869 Expand Info=salt; key layout Sig|Enc|IV; P256=32/16/16 (SHA256/AES128), P384=48/32/16 (SHA384/AES256).

## Format: `[ID] [P?] [Story] Description`

---

## Phase 1: Setup

- [ ] T001 Add an `ecc` cargo feature to `async-opcua-crypto`/`-core`/`-client`/`-server` and the
  RustCrypto deps gated under it (`p256`, `p384` with ecdsa+ecdh, `ecdsa`, `hkdf`; reuse aes/cbc/hmac/sha2);
  workspace builds with and without `--features ecc`; capture the baseline gate.

## Phase 2: Foundational (Blocking Prerequisites)

- [ ] T002 Add `SecurityPolicy::EccNistP256` / `EccNistP384` variants + policy URIs + `FromStr`/`Display`
  round-trip + `supported()` (true only when `ecc` is built) in `async-opcua-crypto/src/security_policy.rs`;
  RSA/None unchanged; recognized-but-unsupported when feature off (fail-closed).
- [ ] T003 Scaffold the `async-opcua-crypto/src/ecc/` module: public API stubs per data-model.md
  (ecdsa sign/verify, ephemeral keygen + `X‖Y` encode/decode, ECDH, HKDF `derive_keys` -> SecurityKeys)
  returning errors/`unimplemented` so US1 tests compile and fail. No logic yet.

**Checkpoint**: policies recognized, ECC module API exists; stories can proceed.

---

## Phase 3: User Story 1 — Verified ECC primitives (Priority: P1) 🎯 foundation

**Goal**: correct ECDSA / ECDH / HKDF, proven against known-answer vectors.
**Independent Test**: `cargo test -p async-opcua-crypto` ECC vector tests pass; tampered inputs rejected.

- [ ] T004 [US1] Add failing known-answer tests in `async-opcua-crypto/src/ecc/` (tests): ECDSA
  P-256/SHA-256 & P-384/SHA-384 sign+verify vs NIST/RFC vectors (raw `r‖s`), tampered sig rejected;
  ECDH two-keypair shared-secret vector; HKDF derived Sig/Enc/IV bytes vs the §6.8.1 salts/labels.
- [ ] T005 [P] [US1] Implement ECDSA sign/verify (raw `r‖s` fixed `Signature`) for P-256/P-384 in `ecc/`. (depends T004)
- [ ] T006 [P] [US1] Implement ephemeral ECDH in `ecc/`: keygen, `X‖Y` (no prefix) encode/decode, raw-x shared secret. (depends T004)
- [ ] T007 [US1] Implement HKDF key derivation in `ecc/`: build ClientSalt/ServerSalt (L=16-bit LE, labels), Extract `HMAC-Hash(salt,IKM)`, RFC 5869 Expand (Info=salt), slice `Sig|Enc|IV` per direction -> SecurityKeys. (depends T004)
- [ ] T007a [US1] Secret hygiene (FR-012, constitution IV): ensure the ephemeral private key, ECDH
  shared secret, and derived key material are **zeroized** after use (e.g. `zeroize`) and do **not**
  expose secret bytes via `Debug`/`Display`/logging; add a unit test asserting a secret-bearing type's
  `Debug` output contains no key material. (depends T006/T007)
- [ ] T008 [US1] Gate; verify T004 passes; **commit US1** (`feat(012 US1): verified ECC primitives (ECDSA/ECDH/HKDF)`).

**Checkpoint**: primitives correct and vector-locked.

---

## Phase 4: User Story 2 — EC application certificates (Priority: P1)

**Goal**: load/validate P-256/P-384 EC application certs; reject curve/policy mismatch.
**Independent Test**: load EC certs, thumbprint, reject expired/untrusted/wrong-curve.

- [ ] T009 [US2] Generate P-256 and P-384 self-signed EC application-cert + key test fixtures (via
  `x509-cert`/RustCrypto in a test helper, or by extending `tools/certificate-creator` if it is
  RSA-only) under the crypto crate's test assets; THEN add failing tests in `async-opcua-crypto` (x509
  tests): load each EC cert, assert curve/public-key parsed + thumbprint; reject expired/untrusted;
  reject curve≠policy. (The fixtures are a prerequisite — the existing test certs are RSA.)
- [ ] T010 [US2] Implement EC public-key parse/validate in `async-opcua-crypto/src/x509.rs` (reuse thumbprint + chain/trust); add curve↔policy match check. (depends T009)
- [ ] T011 [US2] Gate; verify T009 passes; **commit US2** (`feat(012 US2): EC application certificate support`).

**Checkpoint**: ECC peer authentication possible.

---

## Phase 5: User Story 3 — ECC_nistP256 secure channel end to end (Priority: P1) 🎯 MVP

**Goal**: working ECC_nistP256 channel (Sign + SignAndEncrypt) over loopback.
**Independent Test**: loopback client↔server ECC_nistP256 in both modes; identical keys; messages round-trip; renewal works; malformed handshakes rejected.

- [ ] T012 [US3] Add failing loopback + negative tests in `async-opcua` integration tests: server
  `ECC_nistP256` `Sign` + `SignAndEncrypt` endpoints, client connects, signed/encrypted service calls
  succeed, channel renewal works; reject malformed/short ephemeral key, wrong curve, RSA cert on ECC.
- [ ] T013 [US3] In `async-opcua-core/src/comms/secure_channel.rs`, add the ECC key-agreement branch: on
  OpenSecureChannel generate ephemeral, run ECDH+HKDF (US1) to populate the existing `SecurityKeys`; reuse symmetric protect/verify. (depends T012)
- [ ] T014 [US3] Client OpenSecureChannel flow (`async-opcua-client`): put client ephemeral pubkey in `ClientNonce`, ECDSA-sign the request, verify server response signature + derive keys. (depends T013)
- [ ] T015 [US3] Server OpenSecureChannel flow (`async-opcua-server`): verify client signature, gen server ephemeral into `ServerNonce`, derive keys, ECDSA-sign response incl. ChannelThumbprint (§6.7.5). (depends T013)
- [ ] T016 [US3] Gate; verify T012 passes; **commit US3** (`feat(012 US3): ECC_nistP256 secure channel (Sign + SignAndEncrypt)`).

**Checkpoint**: first working elliptic-curve channel (MVP).

---

## Phase 6: User Story 4 — ECC_nistP384 (Priority: P2)

**Goal**: same channel for P-384 (SHA-384 / AES-256).
**Independent Test**: repeat the US3 loopback + negative tests with `ECC_nistP384`.

- [ ] T017 [US4] Add failing loopback + negative tests for `ECC_nistP384` (both modes) in `async-opcua` integration tests.
- [ ] T018 [US4] Generalize the ECC primitives + channel branch (US1/US3) over the curve so P-384/SHA-384/AES-256 dispatches correctly (no P-256 hard-coding). (depends T017)
- [ ] T019 [US4] Gate; verify T017 passes; **commit US4** (`feat(012 US4): ECC_nistP384 support`).

**Checkpoint**: both NIST curves working.

---

## Phase 7: User Story 5 — Negotiation, config & rollout (Priority: P3)

**Goal**: configurable ECC endpoints/selection; correct negotiation; safe feature-gating.
**Independent Test**: mixed RSA+ECC config round-trips; ECC client negotiates ECC, RSA-only client negotiates RSA; feature off → ECC unsupported, RSA/None byte-identical.

- [ ] T020 [US5] Add failing tests: mixed RSA+ECC server config round-trip; ECC-capable client negotiates ECC; RSA-only client still negotiates RSA; `--no-default-features` (ecc off) → ECC policy cleanly rejected, RSA/None byte-identical.
- [ ] T021 [US5] Wire ECC into server endpoint config + client connect surface and the policy/security-level negotiation (`async-opcua-server`/`-client`). (depends T020)
- [ ] T022 [US5] Add a sample ECC endpoint (samples/server.conf or a profile) + ensure `ecc`-off builds are clean; docs pointer. (depends T020)
- [ ] T023 [US5] Gate; verify T020 passes; **commit US5** (`feat(012 US5): ECC endpoint config + negotiation + gating`).

**Checkpoint**: ECC usable and safe to ship.

---

## Phase 8: Polish & Cross-Cutting

- [ ] T024 [P] Fuzz the ECC handshake/decode path: `cargo +nightly fuzz run fuzz_comms --features nightly -- -max_total_time=<n>` → zero aborts.
- [ ] T025 Interop validation (SC-007): if an open62541 / UA-.NETStandard ECC peer is available, connect our client↔their server and theirs↔ours in both modes; otherwise document the gap in research.md.
- [ ] T026 [P] Update `docs/setup.md` (ECC deployment + `ecc` feature) and release notes; record the security-review note (handshake/crypto path).
- [ ] T027 Final gate: `cargo fmt --all --check` + `cargo clippy --all-targets --all-features -- -D warnings` + `cargo test --workspace` + `verify-clean-codegen`; confirm RSA/None wire byte-identity preserved.

---

## Dependencies & Execution Order

- **Setup (T001)** → no deps. **Foundational (T002, T003)** → after Setup; block all stories.
- **US1** (T004→T005/T006/T007→T008) is the crypto foundation; **US2** independent (certs); **US3** depends on US1 (+US2 for non-None auth); **US4** depends on US1/US3; **US5** depends on US3 for the channel surface. Within a story: failing test → impl → gate-&-commit.
- Intra-story `[P]`: US1 T005/T006 parallel (different files) after T004; T007 after (consumes the others' types).
- **Polish (T024–T027)** after the stories.

## Implementation Strategy

**MVP = US1 + US3** (verified primitives + a working `ECC_nistP256` channel). Then US2 (real cert auth),
US4 (P-384), US5 (config/negotiation). Each story is an independently-testable, single-commit
increment. The crypto is already spec-pinned, so US1 is "implement to the recorded values + vectors,"
not "discover the spec."

## Notes

- One task per codex dispatch; verify the failing test before implementing.
- One commit per user story; `ecc` feature gates everything; RSA/None byte-identical.
- No generated-code edits; `verify-clean-codegen` stays green.
- Out of scope (spec): brainpool, PubSub-ECC, ECC user-identity-token encryption, any C backend.
- Residual risk: end-to-end interop (T025/SC-007) — loopback+vectors prove correctness, a third-party peer is the gold standard.
