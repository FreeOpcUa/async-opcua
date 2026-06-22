# Tasks: Part-14 Conformant UADP PubSub Message Security

**Feature**: `026-pubsub-message-security` | **Spec**: [spec.md](./spec.md) | **Plan**: [plan.md](./plan.md)

## Conventions (binding)

- **Verification division**: tasks tagged **[codex]** = production code, implemented by codex (one
  task per dispatch, no tests, no git; verify branch is `026-pubsub-message-security` after each).
  Tasks tagged **[claude-test]** = tests authored + run by Claude, anchored to Part 14 Tables
  155–157 and external stacks — never to codex output. Per the constitution, a fix lands only with a
  test that FAILS before and PASSES after.
- **One commit per user story** (after its codex + claude-test tasks are green).
- Apply **ponytail**: minimal correct diff, fail-closed, no speculative config; never weaken a check.
- All wire facts: [research.md](./research.md); behavioral contract: [contracts/pubsub-message-security.md](./contracts/pubsub-message-security.md).

---

## Phase 1: Setup

- [ ] T001 Add `ctr = "0.9"` to the workspace `Cargo.toml` `[workspace.dependencies]` and to `async-opcua-crypto/Cargo.toml` (`ctr = { workspace = true }`); run `cargo deny check` to confirm the new crypto dep is advisory-clean and `cargo build -p async-opcua-crypto` compiles.

---

## Phase 2: Foundational (blocks US2–US4)

**Goal**: the NetworkMessage gains the Part-14 NetworkMessage-level SequenceNumber that security,
nonce, and replay all key on.

- [ ] T002 [codex] Extend `UadpNetworkMessage` in `async-opcua-pubsub/src/codec/uadp.rs` with `network_message_number: u16` and a NetworkMessage-level `sequence_number: u32`; encode/decode them in the GroupHeader per Part 14 Figure A.3 (gated by the GroupFlags bits), leaving the existing DataSetMessage-level `sequence_number: u16` intact. Bounds-checked decode, no panic. **Counter ownership (F1)**: the publisher (`engine.rs`, and the `udp.rs`/`bridge.rs` send loops) owns and increments the single NetworkMessage `sequence_number`; the security codec and replay window only *consume* it. Do NOT introduce a second counter inside `security/codec.rs`.
- [ ] T003 [claude-test] In `async-opcua-pubsub/src/codec/uadp.rs` tests (or `tests/`), add a plaintext round-trip asserting NetworkMessageNumber + NetworkMessage SequenceNumber encode/decode correctly and the GroupFlags bits are set/cleared as expected.

**Checkpoint**: plaintext UADP round-trips with the new GroupHeader fields.

---

## Phase 3: User Story 1 — AES-CTR PubSub policies (P1)

**Goal**: `PubSub-Aes128-CTR` / `PubSub-Aes256-CTR` exist with correct AES-CTR encrypt/decrypt and
HMAC-SHA256 sign/verify.
**Independent test**: KAT vectors (Table 157) match for both key sizes; round-trip recovers
plaintext with no padding; mismatched lengths fail closed.

- [ ] T004 [codex] Add `PubSub-Aes128-CTR` and `PubSub-Aes256-CTR` variants to `SecurityPolicy` in `async-opcua-crypto/src/security_policy.rs`: `to_uri()`/`from_uri()` for `…#PubSub-Aes128-CTR` / `…#PubSub-Aes256-CTR`, `is_supported()`, `encrypting_key_length()` (16/32), `symmetric_signature_size()` (32), and accessors for KeyNonce length (4) and MessageNonce length (8).
- [ ] T005 [codex] Implement `Aes128Ctr` / `Aes256Ctr` in `async-opcua-crypto/src/policy/aes.rs` (+ helpers in `src/aes/aeskey.rs`) using `ctr::Ctr32BE<aes::Aes128>` / `Ctr32BE<aes::Aes256>`; build the 16-byte counter block `KeyNonce[4] ‖ MessageNonce[8] ‖ 0x00000001` (Table 157); wire `symmetric_encrypt`/`symmetric_decrypt` dispatch for the CTR policies (no padding, `dst.len() == src.len()`). Fail closed on key/nonce length mismatch.
- [ ] T006 [claude-test] In `async-opcua-pubsub/tests/message_security_vectors.rs` (new), add AES-CTR known-answer tests independently computed from Table 157 — keystream block k = `AES_enc(KeyNonce ‖ MessageNonce ‖ BE32(k))` starting k=1, XOR plaintext — for Aes128 and Aes256; assert exact ciphertext bytes, round-trip, and `Err` on mismatched key/nonce length.
- [ ] T007 [claude-test] In the same file, assert HMAC-SHA256 sign/verify over a fixed range for both CTR policies and that a single tampered byte makes verification fail.

**Checkpoint + commit** (US1): CTR cipher + signature verified against spec vectors.

---

## Phase 4: User Story 2 — Part-14 SecurityHeader + SecurityFooter (P2)

**Goal**: real SecurityHeader framing replaces the `OPCUAPS1` envelope; only the Payload is
encrypted; signature over the whole message; every malformed input fails closed.
**Independent test**: byte-level SecurityHeader field check; round-trip Sign + SignAndEncrypt;
negative corpus rejected without panic.

- [ ] T008 [codex] Implement SecurityHeader encode/parse in `async-opcua-pubsub/src/codec/uadp.rs`: ExtendedFlags1 bit 4; SecurityFlags (bit0 Signed, bit1 Encrypted, bit2=0 no footer, bit3 ForceKeyReset), SecurityTokenId (UInt32), NonceLength (=8), MessageNonce, SecurityFooterSize omitted; interleave so the SecurityHeader sits between the header region and the Payload and only the Payload region is encrypted. Bounds-check NonceLength/payload length against `max_secured_payload_len` and the existing `max_*` caps before allocating; reject reserved-bit-set (bits 4–7), flags/length inconsistency. **ForceKeyReset (F5)**: bit 3 is a *defined* flag, not reserved — decode MUST tolerate it (parse and ignore; no key-reset action in this feature) so a conformant peer's ForceKeyReset message is not wrongly rejected.
- [ ] T009 [codex] Rewrite `async-opcua-pubsub/src/security/codec.rs`: delete the `OPCUAPS1` envelope; implement Part-14 `Sign` and `SignAndEncrypt` over the real layout (encrypt Payload then HMAC-SHA256 over the entire NetworkMessage incl. ciphertext); on decode verify signature **before** decrypt; select the key set by SecurityTokenId via `security/group.rs` (fail closed if not held); wire into `async-opcua-pubsub/src/engine.rs`.
- [ ] T010 [claude-test] In `async-opcua-pubsub/tests/security_tests.rs`, assert on encoded bytes: ExtendedFlags1 bit4=1, SecurityFlags bits for Sign vs SignAndEncrypt, SecurityTokenId present, NonceLength=8, no `OPCUAPS1` magic; round-trip both modes recovers the original NetworkMessage; `Sign`-only verifies without decryption.
- [ ] T011 [claude-test] In `async-opcua-pubsub/tests/security_tests.rs`, add the fail-closed negative corpus: truncated message; NonceLength≠8 with encrypt bit; reserved SecurityFlags bit set; payload length > `max_secured_payload_len`; unknown SecurityTokenId; flipped byte in header / ciphertext / signature — each returns a security `Err` with no panic and no over-allocation.

**Checkpoint + commit** (US2): conformant framing, fail-closed decode.

---

## Phase 5: User Story 3 — Per-message MessageNonce + IV (P3, core fix)

**Goal**: fresh per-message nonce → unique IV; the static-IV reuse is gone.
**Independent test**: same message encoded twice → different nonce + ciphertext; characterization
fails on the pre-fix static-IV behavior.

- [ ] T012 [codex] In `async-opcua-pubsub/src/security/codec.rs`, generate a fresh MessageNonce per encode = `Random[4]` (via `opcua_crypto::random::bytes`) ‖ the NetworkMessage `SequenceNumber` (UInt32) **supplied by the publisher** (T002 / `engine.rs` — the codec does not own the counter); the publisher increments the sequence per message within a key epoch and resets it to 1 on SecurityTokenId/key change; derive the counter block from it. Add the `// ponytail:` ceiling comment (IV-unique while seq doesn't wrap a key epoch; key rotation resets it).
- [ ] T013 [claude-test] In `async-opcua-pubsub/tests/message_security_vectors.rs`, encode the same NetworkMessage twice under one key set and assert the two MessageNonces differ AND the two ciphertexts differ (SC-001); include a forced-static-IV variant (or a pre-fix snapshot) showing the test FAILS without the fix.

**Checkpoint + commit** (US3): IV reuse eliminated.

---

## Phase 6: User Story 4 — Subscriber replay/freshness (P4)

**Goal**: replayed/stale NetworkMessages rejected; bounded memory.
**Independent test**: dup rejected, increasing accepted, reorder-within-window accepted, stale
rejected, token change resets.

- [ ] T014 [codex] Add `async-opcua-pubsub/src/security/replay.rs`: a bounded anti-replay window (`highest_seq: u32` + fixed W-bit bitmap, e.g. W=64) keyed by SecurityTokenId; first message seeds it; accept seq>highest (shift) and unseen-in-window; reject seen/stale-below-floor; reset on SecurityTokenId change; handle §7.2.3 wraparound. Integrate into the subscriber decode path (`engine.rs`/`security/codec.rs`). `// ponytail:` comment on the window-size ceiling.
- [ ] T015 [claude-test] Add `async-opcua-pubsub/tests/replay_tests.rs`: byte-identical replay rejected; strictly-increasing accepted; benign reorder within W accepted; seq below window floor rejected; SecurityTokenId change resets and re-accepts seq=1 (SC-002).

**Checkpoint + commit** (US4): replay protection in place.

---

## Phase 7: User Story 5 — External interop verification (P5)

**Goal**: prove conformance against an external Part-14 stack (or spec-anchored external vectors).
**Independent test**: round-trip both directions for Sign + SignAndEncrypt, ≥1 policy per key size.

- [ ] T016 [claude-test] Extend the interop harness for SignAndEncrypt (test/harness code, authored by Claude per the verification division — not codex): either add a secured-NetworkMessage path to `dotnet-tests/external-tests` `pubsub_tests.rs` (currently plaintext UADP only) and/or an open62541 path under `3rd-party/open62541`; if a live harness can't run in CI, produce and commit external known-answer fixtures (raw secured NetworkMessage bytes + key material) under `async-opcua-pubsub/tests/fixtures/`. (If any Rust *production* glue is needed to expose an encode/decode entry point, split that into a small `[codex]` sub-task.)
- [ ] T017 [claude-test] Add interop assertions: a message encoded here decodes+verifies on the external stack and vice versa for `Sign` and `SignAndEncrypt`, ≥1 policy per key size; OR the committed external fixtures decode+verify here and our re-encode matches the external bytes (SC-004). Document any live-interop gap.

**Checkpoint + commit** (US5): interop proven / gap documented.

---

## Phase 8: Polish & cross-cutting

- [ ] T018 [codex] Remove the "proprietary `OPCUAPS1` / experimental" note in `async-opcua-pubsub/src/lib.rs` and any dead envelope code/constants (`SECURED_UADP_MAGIC`, `ENVELOPE_HEADER_LEN`, etc.); update module docs to describe the Part-14 security path (Principle V).
- [ ] T019 [claude-test] Run the three clippy legs (`--all-targets --all-features`; `--no-default-features` for the core crates; the `json`-off leg) under `-D warnings` and `cargo deny check`; fix any warnings.
- [ ] T020 [P] Update `specs/conformance-gap-backlog.md`: correct the entry that framed this as "merely add a MessageNonce" → full Part-14 secured-NetworkMessage implementation DONE; record any deferred live-interop gap.
- [ ] T021 [claude-test] Run the fork CI legs locally before PR (build matrix: default / all-features / no-default-features; clippy; codegen; the env_expansion gotcha) per the `fork-has-full-rust-ci` notes; open the PR to `occamsshavingkit/async-opcua` and merge when green.

---

## Dependencies & order

- **Setup (T001)** → **Foundational (T002–T003)** → **US1 (T004–T007)** → **US2 (T008–T011)** →
  **US3 (T012–T013)** → **US4 (T014–T015)** → **US5 (T016–T017)** → **Polish (T018–T021)**.
- US2 depends on US1 (cipher) + Foundational (NetworkMessage seq). US3 depends on US1+US2. US4
  depends on Foundational (decoded seq) + US2. US5 depends on US1–US4.
- **MVP** = Setup + Foundational + US1 + US2 + US3 (a conformant, IND-CPA-safe signed+encrypted
  message). US4 + US5 harden and prove it.

## Parallel opportunities

- Within US1: T006 and T007 (claude-test) can be authored in parallel once T004–T005 land.
- T020 (backlog doc) is `[P]` — independent of code.
- Across stories, codex tasks are strictly sequential (shared files `codec/uadp.rs`,
  `security/codec.rs`); do not parallelize them (one-task-per-dispatch).

## Format validation

All tasks use `- [ ] T### [tag] description with file path`; story tasks carry `[US#]` via their
phase; setup/foundational/polish carry none; each names concrete file paths.
