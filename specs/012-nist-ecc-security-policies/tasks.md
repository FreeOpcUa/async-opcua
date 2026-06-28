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

- [X] T001 Add an `ecc` cargo feature to `async-opcua-crypto`/`-core`/`-client`/`-server` and the
  RustCrypto deps gated under it (`p256`, `p384` with ecdsa+ecdh, `ecdsa`, `hkdf`; reuse aes/cbc/hmac/sha2);
  workspace builds with and without `--features ecc`; capture the baseline gate.

## Phase 2: Foundational (Blocking Prerequisites)

- [X] T002 Add `SecurityPolicy::EccNistP256` / `EccNistP384` variants + policy URIs + `FromStr`/`Display`
  round-trip + `supported()` (true only when `ecc` is built) in `async-opcua-crypto/src/security_policy.rs`;
  RSA/None unchanged; recognized-but-unsupported when feature off (fail-closed).
- [X] T003 Scaffold the `async-opcua-crypto/src/ecc/` module: public API stubs per data-model.md
  (ecdsa sign/verify, ephemeral keygen + `X‖Y` encode/decode, ECDH, HKDF `derive_keys` -> SecurityKeys)
  returning errors/`unimplemented` so US1 tests compile and fail. No logic yet.

**Checkpoint**: policies recognized, ECC module API exists; stories can proceed.

---

## Phase 3: User Story 1 — Verified ECC primitives (Priority: P1) 🎯 foundation

**Goal**: correct ECDSA / ECDH / HKDF, proven against known-answer vectors.
**Independent Test**: `cargo test -p async-opcua-crypto` ECC vector tests pass; tampered inputs rejected.

- [X] T004 [US1] Add failing known-answer tests in `async-opcua-crypto/src/ecc/` (tests): ECDSA
  P-256/SHA-256 & P-384/SHA-384 sign+verify vs NIST/RFC vectors (raw `r‖s`), tampered sig rejected;
  ECDH two-keypair shared-secret vector; HKDF derived Sig/Enc/IV bytes vs the §6.8.1 salts/labels.
- [X] T005 [P] [US1] Implement ECDSA sign/verify (raw `r‖s` fixed `Signature`) for P-256/P-384 in `ecc/`. (depends T004)
- [X] T006 [P] [US1] Implement ephemeral ECDH in `ecc/`: keygen, `X‖Y` (no prefix) encode/decode, raw-x shared secret. (depends T004)
- [X] T007 [US1] Implement HKDF key derivation in `ecc/`: build ClientSalt/ServerSalt (L=16-bit LE, labels), Extract `HMAC-Hash(salt,IKM)`, RFC 5869 Expand (Info=salt), slice `Sig|Enc|IV` per direction -> SecurityKeys. (depends T004)
- [X] T007a [US1] Secret hygiene (FR-012, constitution IV): ensure the ephemeral private key, ECDH
  shared secret, and derived key material are **zeroized** after use (e.g. `zeroize`) and do **not**
  expose secret bytes via `Debug`/`Display`/logging; add a unit test asserting a secret-bearing type's
  `Debug` output contains no key material. (depends T006/T007)
- [X] T008 [US1] Gate; verify T004 passes; **commit US1** (`feat(012 US1): verified ECC primitives (ECDSA/ECDH/HKDF)`).

**Checkpoint**: primitives correct and vector-locked.

---

## Phase 4: User Story 2 — EC application certificates (Priority: P1)

**Goal**: load/validate P-256/P-384 EC application certs; reject curve/policy mismatch.
**Independent Test**: load EC certs, thumbprint, reject expired/untrusted/wrong-curve.

- [X] T009 [US2] Generate P-256 and P-384 self-signed EC application-cert + key test fixtures (via
  `x509-cert`/RustCrypto in a test helper, or by extending `tools/certificate-creator` if it is
  RSA-only) under the crypto crate's test assets; THEN add failing tests in `async-opcua-crypto` (x509
  tests): load each EC cert, assert curve/public-key parsed + thumbprint; reject expired/untrusted;
  reject curve≠policy. (The fixtures are a prerequisite — the existing test certs are RSA.)
- [X] T010 [US2] Implement EC public-key parse/validate in `async-opcua-crypto/src/x509.rs` (reuse thumbprint + chain/trust); add curve↔policy match check. (depends T009)
- [X] T011 [US2] Gate; verify T009 passes; **commit US2** (`feat(012 US2): EC application certificate support`).

**Checkpoint**: ECC peer authentication possible.

---

## Phase 5: User Story 3 — ECC_nistP256 secure channel end to end (Priority: P1) 🎯 MVP

**Goal**: working ECC_nistP256 channel (Sign + SignAndEncrypt) over loopback.
**Independent Test**: loopback client↔server ECC_nistP256 in both modes; identical keys; messages round-trip; renewal works; malformed handshakes rejected.

- [X] T012 [US3] Add failing loopback + negative tests in `async-opcua` integration tests: server
  `ECC_nistP256` `Sign` + `SignAndEncrypt` endpoints, client connects, signed/encrypted service calls
  succeed, channel renewal works; reject malformed/short ephemeral key, wrong curve, RSA cert on ECC.
  — DONE (Claude): `async-opcua/tests/integration/ecc.rs` — P256/P384 × Sign/SignAndEncrypt connect +
  signed/encrypted read, channel renewal, curve-strict negotiation, all over real loopback (EC app certs via
  `cert_and_pkey_ecc` + EC-PEM PKI loading; new `ecc` feature on the umbrella crate). Fail-closed negatives
  (malformed/short ephemeral key, cross-curve ECDH, RSA key on ECC policy, wrong-curve sig length) in
  `ecc_audit.rs`. 104 integration tests green (98 RSA + 6 ECC).
- [X] T013 [US3] In `async-opcua-core/src/comms/secure_channel.rs`, add the ECC key-agreement branch: on
  OpenSecureChannel generate ephemeral, run ECDH+HKDF (US1) to populate the existing `SecurityKeys`; reuse symmetric protect/verify. (depends T012)
  — codex impl; verified by Claude-authored channel round-trip tests (RFC 5903 ephemerals, both directions) +
  symmetric AES-CBC/HMAC reuse (P256=AES128/HMAC-SHA256, P384=AES256/HMAC-SHA384). NOTE follow-up: harden the
  now-unreachable `make_secure_channel_keys` ECC arm (returns empty keys → make `unreachable!`) during T014.
- [X] T014 [US3] Client OpenSecureChannel flow (`async-opcua-client`): put client ephemeral pubkey in `ClientNonce`, ECDSA-sign the request, verify server response signature + derive keys. (depends T013)
  — codex impl (`create_local_nonce`, Role::Client); plus EC application key support (`PrivateKey` made
  RSA|EC polymorphic, `cert_and_pkey_ecc`, EC-PEM load) + ECDSA OSC sign/verify (sign-only) wired. Verified
  by Claude channel + loopback tests.
- [X] T015 [US3] Server OpenSecureChannel flow (`async-opcua-server`): verify client signature, gen server ephemeral into `ServerNonce`, derive keys, ECDSA-sign response. (depends T013)
  — codex impl (Role::Server, server ephemeral). Also fixed a latent server bug Claude's loopback caught: the
  server hardcoded LEGACY sequence numbers and never synced to the negotiated policy, breaking non-legacy ECC
  (now `SendBuffer::configure_sequence_numbers` once at first OSC). **DEFERRED:** ChannelThumbprint (§6.7.5)
  MITM-hardening response signature — tracked as a follow-up, not required for the loopback MVP.
- [X] T016 [US3] Gate; verify T012 passes; **commit US3** (`feat(012 US3): ECC_nistP256 secure channel (Sign + SignAndEncrypt)`).
  — committed `95a7f3cf`; gate green (fmt/clippy --all-features -D warnings/workspace tests). NB: US4 (P-384)
  is already implemented and tested here too (the channel/primitives are curve-generic), so US4 is largely
  satisfied — T017-T019 reduce to confirming/closing out.

**Checkpoint**: first working elliptic-curve channel (MVP).

---

## Phase 6: User Story 4 — ECC_nistP384 (Priority: P2)

**Goal**: same channel for P-384 (SHA-384 / AES-256).
**Independent Test**: repeat the US3 loopback + negative tests with `ECC_nistP384`.

- [X] T017 [US4] Add failing loopback + negative tests for `ECC_nistP384` (both modes) in `async-opcua` integration tests.
  — DONE in US3: `ecc_nistp384_sign` / `ecc_nistp384_sign_and_encrypt` loopback + P-384 channel/crypto/negative tests.
- [X] T018 [US4] Generalize the ECC primitives + channel branch (US1/US3) over the curve so P-384/SHA-384/AES-256 dispatches correctly (no P-256 hard-coding). (depends T017)
  — DONE: production code is curve-generic via `EccCurve` throughout (audited: the only `P256` literals are in
  test code). P-384 loopback exercises AES-256 / SHA-384 / 96-byte ECDSA end to end.
- [X] T019 [US4] Gate; verify T017 passes. **No separate commit** — US4 shipped within the US3 commit (`95a7f3cf`),
  since the curve-generic channel made P-384 fall out for free.

**Checkpoint**: both NIST curves working.

---

## Phase 7: User Story 5 — Negotiation, config & rollout (Priority: P3)

**Goal**: configurable ECC endpoints/selection; correct negotiation; safe feature-gating.
**Independent Test**: mixed RSA+ECC config round-trips; ECC client negotiates ECC, RSA-only client negotiates RSA; feature off → ECC unsupported, RSA/None byte-identical.

- [X] T020 [US5] Add failing tests: ECC-capable client negotiates ECC; RSA-only client still negotiates RSA; `--no-default-features` (ecc off) → ECC policy cleanly rejected, RSA/None byte-identical.
  — DONE: feature-off gating test `security_policy::tests::ecc_policies_recognized_but_unsupported_when_feature_off`
  (ecc-off → recognized-but-unsupported, fail-closed; RSA/None supported); ECC negotiation + curve-strict
  rejection covered by the US3 loopback + `ecc_wrong_curve_is_not_negotiated`; RSA negotiation by the existing
  98-test suite. **Mixed RSA+ECC config round-trip dropped** — needs multi-cert (see research.md Deferred).
- [X] T021 [US5] Wire ECC into server endpoint config + client connect surface and the policy/security-level negotiation.
  — DONE in US3 (required to make the channel work): `add_endpoint` accepts ECC policies, client
  `connect_to_matching_endpoint` selects ECC, negotiation is curve-strict. `is_supported()`/`ensure_supported()`
  gate on `cfg!(feature="ecc")`.
- [X] T022 [US5] Ensure `ecc`-off builds are clean; docs pointer. (depends T020)
  — DONE: gated the SHA-384/test-only items so `clippy --no-default-features --features aws-lc-rs --all-targets
  -D warnings` is clean; added the `ecc` feature + single-cert limitation to `docs/setup.md`. (Standalone sample
  endpoint config deferred to Polish/T026.)
- [X] T023 [US5] Gate; verify T020 passes; **commit US5** (`feat(012 US5): ECC config/negotiation + ecc-off gating`).

**Checkpoint**: ECC usable and safe to ship.

---

## Phase 8: Polish & Cross-Cutting

- [X] T024 [P] Fuzz the ECC handshake/decode path: `cargo +nightly fuzz run fuzz_comms --features nightly -- -max_total_time=<n>` → zero aborts.
  — VERIFIED 2026-06-28: `cargo +nightly fuzz run fuzz_comms --features nightly -- -max_total_time=60`
  completed 15,629,845 runs in 61s with zero aborts/crashes. Grounded in OPC UA Part 6 §6.8.1:
  ECC `OpenSecureChannel` exchanges ephemeral public keys, performs curve-specific shared-secret
  calculation, and derives channel keys with HKDF; `fuzz_comms` exercises the untrusted TCP
  message decode path that reaches secure-channel handshake decoding.
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
