---
description: "Task list for feature 015 — ECC token EphemeralKey exchange (Part 6 §6.8.2)"
---

# Tasks: ECC Token EphemeralKey Exchange (OPC UA Part 6 §6.8.2)

**Input**: design docs in `/specs/015-ecc-token-ephemeral-keys/` (spec, research, plan, data-model,
contracts/api-surface, quickstart). Phase A of two (016 = EccEncryptedSecret).

**Tests**: INCLUDED (security trust-path / authenticated key exchange; Constitution I/IV).
**Verification division**: codex writes production code only (no self-authored tests); **Claude authors
and runs all tests** independently, anchored to Part 6 §6.8.2 + Part 4 §7.15 (Table 136) and round-trip
/ external ground truth — not codex loopback alone (caught a rigged HKDF test on 012). codex no-git
guardrail + verify branch after; do not let codex read/modify test files. **One commit per user story**.
Gate: `cargo fmt --all --check && cargo clippy --all-targets --all-features --locked -- -D warnings &&
cargo test -p async-opcua-crypto -p async-opcua-server -p async-opcua-client` (+ integration where a
story touches the handshake; note the pre-existing integration-suite flakiness — verify failures in
isolation).

**Pinned facts (research + §7.15):** `EphemeralKeyType { publicKey: ByteString (curve-encoded),
signature: ByteString }`; the signature is over the **publicKey bytes**, using the channel
ApplicationInstanceCertificate + the policy's asymmetric signature algorithm; verified with the peer
(server) certificate. `RequestHeader`/`ResponseHeader.additional_header` are `ExtensionObject` (today
always `null()`) — carry an `AdditionalParametersType` name-value list with `ECDHPolicyUri` (String) +
`ECDHKey` (`EphemeralKeyType`, or a StatusCode on error). Reuse 012 `generate_ephemeral_keypair` /
`EphemeralPublicKey` / curve encoding + the policy `asymmetric_sign`/verify. Behind the `ecc` feature.

## Format: `[ID] [P?] [Story] Description`

---

## Phase 1: Setup

- [X] T001 Capture the baseline gate; confirm the generated `EphemeralKeyType` and
  `AdditionalParametersType` field shapes and how a name-value `KeyValuePair` list is represented, and
  re-read Part 4 §7.15 + Part 6 §6.8.1–2 for the exact signed-data / encoding rules. No code change.

## Phase 2: Foundational (Blocking Prerequisites)

- [X] T002 Crypto in `async-opcua-crypto/src/ecc.rs`: `sign_ephemeral_public_key(security_policy,
  signing_key, public_key_bytes) -> signature` and `verify_ephemeral_public_key(security_policy,
  signer_cert, public_key_bytes, signature) -> Result<(), Error>` — sign/verify the EphemeralKey
  `publicKey` bytes with the policy's asymmetric signature algorithm (§7.15), reusing the existing
  asymmetric sign/verify + 012 ephemeral primitives. Panic-free; behind `ecc`.
- [X] T003 Header codec helper (`async-opcua-crypto` or a shared server/client util): build + parse an
  `AdditionalParametersType` carrying `ECDHPolicyUri` (String) and `ECDHKey` (`EphemeralKeyType` or
  StatusCode) into/from a header `ExtensionObject`. Panic-free on malformed bytes; returns None/empty
  when absent (preserving today's null-header behavior).

**Checkpoint**: EphemeralKey sign/verify + AdditionalHeader codec exist; stories can proceed.

## Phase 3: User Story 1 — Server issues a signed EphemeralKey at CreateSession (P1) 🎯 MVP

**Goal**: a valid `ECDHPolicyUri` → server returns a signed `ECDHKey`; invalid → `Bad_SecurityPolicyRejected`; absent → unchanged.

- [X] T004 [US1] Claude-authored failing tests: (a) crypto — sign an ephemeral public key with an EC
  app-cert key and verify it against the cert; a tampered key/signature fails (anchored to §7.15:
  signed data = publicKey bytes). (b) server — a CreateSession whose request `additional_header`
  declares `ECDHPolicyUri=ECC_nistP256/384` yields a response `additional_header` with an `ECDHKey`
  whose signature verifies and `publicKey` is a valid curve point; an invalid policy → the response
  conveys `Bad_SecurityPolicyRejected`; absent → null header unchanged.
- [X] T005 [US1] Implement in `async-opcua-server/src/session/manager.rs` (`create_session`): read
  `ECDHPolicyUri` from `request.request_header.additional_header`; for a supported ECC policy generate
  an ephemeral keypair, sign the public key (T002), and place `ECDHKey` (`EphemeralKeyType`) in the
  response `additional_header`; invalid/unsupported → `Bad_SecurityPolicyRejected` (in place of the
  key); absent → unchanged. Store the issued ephemeral key on the session. (depends T004)
- [X] T006 [US1] Gate; verify T004 passes; **commit US1** (`feat(015 US1): server issues a signed ECC EphemeralKey at CreateSession`).

## Phase 4: User Story 2 — Client requests + verifies + retains the server EphemeralKey (P1)

**Goal**: client advertises `ECDHPolicyUri`, reads + signature-verifies the server `ECDHKey`, retains the most recent.

- [X] T007 [US2] Claude-authored tests: client puts `ECDHPolicyUri` in the request header; given a
  response carrying a validly-signed `ECDHKey`, the client retains it; a forged/wrong-signature or
  invalid-curve-point `ECDHKey` is rejected (not retained); malformed header bytes → no panic.
- [X] T008 [US2] Implement in `async-opcua-client/src/session/services/session.rs`: place the chosen
  `ECDHPolicyUri` in the CreateSession/ActivateSession request `additional_header`; read `ECDHKey` from
  the response, verify its signature against the server certificate + curve point (T002), and retain
  the most-recent verified server EphemeralKey on the session state. (depends T007)
- [X] T009 [US2] Gate; verify T007 passes; **commit US2** (`feat(015 US2): client requests + verifies + retains the server EphemeralKey`).

## Phase 5: User Story 3 — Fresh EphemeralKey + anti-replay at ActivateSession (P2)

**Goal**: §6.8.2 new-vs-retain lifecycle; never accept the same EphemeralKey twice.

- [X] T010 [US3] Claude-authored tests: the pure §6.8.2 decision (`decide_ecdh_key_action`) holds for
  all branches — valid ECC policy → new key; invalid/non-ECC → `Bad_SecurityPolicyRejected`;
  absent+previous-used → new key for the prior policy; absent+previous-unused → retain; absent+no-prior →
  no ECDH. **Scope note (user-approved):** the consumed-key anti-replay only bites when a key is
  *consumed* to decrypt a secret, which is **feature 016**; in 015a `previous_key_consumed` is always
  false, so the reuse-rejection branch is unit-tested in the decision helper but not yet wired to a real
  consumption event (016 supplies the `consumed` input).
- [X] T011 [US3] Implement the ActivateSession side in `manager.rs`: apply the §6.8.2 lifecycle via
  `decide_ecdh_key_action` — `Issue(policy)` issues+stores a fresh signed `ECDHKey` (mirrors
  CreateSession), `Reject` → `Bad_SecurityPolicyRejected`, `Retain`/`None` → no header. The
  consumed-key anti-replay *enforcement* (rejecting a replayed/consumed key) is **deferred to 016**
  where the EphemeralKey is consumed. (depends T010)
- [X] T012 [US3] Gate; verify T010 passes; **commit US3** (`feat(015 US3): EphemeralKey lifecycle + anti-replay at ActivateSession`).

## Phase 6: User Story 4 — Rollout & backward compatibility (P3)

- [X] T013 [P] [US4] Claude-authored regression tests: RSA / `None` / ECC-without-`ECDHPolicyUri`
  sessions create/activate exactly as before (null `additional_header` unchanged); confirm the
  `ecc`-off build behaves identically (no ECDH handling compiled).
- [X] T014 [US4] Gate (incl. `--no-default-features` build); verify T013 passes; **commit US4**
  (`test(015 US4): rollout + backward-compat (RSA/None/no-ECDH unchanged)`).

## Phase 7: Polish

- [ ] T015 [P] Fuzz the attacker-reachable decode: `fuzz_additional_header_ecdh` (or extend an existing
  target) over malformed `AdditionalParametersType` / `EphemeralKeyType` bytes → zero panics.
- [ ] T016 [P] Docs: note the ECC token EphemeralKey exchange (request/response `AdditionalHeader`,
  `ECDHPolicyUri`/`ECDHKey`) in `docs/crypto.md`; record that 016 (EccEncryptedSecret) builds on it.
- [ ] T017 Final gate: fmt + clippy --all-targets --all-features + crypto/server/client tests +
  integration (failures confirmed in isolation as pre-existing flakiness) + `--no-default-features`
  build; confirm RSA/None byte-identical.

---

## Dependencies & Execution Order

- **Setup (T001)** → **Foundational (T002, T003)** block the stories. **US1** (server-issue) →
  **US2** (client-read) → **US3** (lifecycle/anti-replay) → **US4** (rollout). T013/T015/T016 are [P]
  (independent test/doc files). **Polish** last.
- Within a story: Claude failing test → codex impl → gate-&-commit. One task per codex dispatch
  (codex: T002, T003, T005, T008, T011; all test tasks are Claude).

## Implementation Strategy

**MVP = US1** (server issues a signed EphemeralKey). US2 completes the authenticated round-trip; US3
adds the §6.8.2 anti-replay; US4 locks in back-compat. Reuse 012 ECC primitives + the existing
asymmetric sign/verify; the generated `EphemeralKeyType`/`AdditionalParametersType` types.

## Notes

- codex implements production code only; Claude authors/runs all tests, anchored to §6.8.2 + §7.15 +
  round-trip (not codex loopback alone). codex no-git guardrail; verify branch after.
- One commit per story; RSA/None byte-identical; `ecc`-gated.
- This is phase A; **feature 016** (EccEncryptedSecret §7.40.2.5 / §6.8.3) consumes the retained
  EphemeralKey to encrypt/decrypt the actual identity-token secret.
- Deferred (recorded): RSA-DH finite-field EphemeralKeys; GDS; the mixed RSA+ECC multi-cert server.
