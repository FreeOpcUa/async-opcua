---
description: "Task list for feature 016 — ECC EncryptedSecret for identity tokens (Part 4 §7.40.2.5 / Part 6 §6.8.3)"
---

# Tasks: ECC EncryptedSecret for Identity Tokens (Part 4 §7.40.2.5 / Part 6 §6.8.3)

**Input**: design docs in `/specs/016-ecc-encrypted-secret/` (spec, plan, research, data-model,
contracts/api-surface, quickstart). Phase B of two (follow-on to 015a EphemeralKey exchange, merged).

**Tests**: INCLUDED (cryptographic trust path; Constitution I/IV).
**Verification division**: codex writes production code only (no self-authored tests); **Claude authors
and runs all tests** independently, anchored to **RFC 5869** HKDF vectors + the §7.40.2.5 wire layout +
client↔server round-trips — NOT codex loopback (caught a rigged HKDF test on 012). codex no-git
guardrail + verify branch after; do not let codex read/modify test files. **One commit per user story.**
Gate: `cargo fmt --all --check && cargo clippy --all-targets --all-features --locked -- -D warnings &&
cargo test -p async-opcua-crypto -p async-opcua-server -p async-opcua-client` (+ `--no-default-features`
build where back-compat is touched; pre-existing integration-suite flakiness verified in isolation).

**Pinned facts (research.md — from Part 4/6 1.05.07):** EccEncryptedSecret = ExtensionObject-prefixed
envelope (Table 186): common header (TypeId, EncodingMask=1, Length:Int32, SecurityPolicyUri, Certificate
[null when client app-instance cert known to server], SigningTime, KeyDataLength:UInt16) | **unencrypted**
KeyData (SenderPublicKey, ReceiverPublicKey) | AES-CBC-encrypted payload (AES-128 P-256 / AES-256 P-384) (Nonce, Secret, PayloadPadding,
PayloadPaddingSize:UInt16) | **asymmetric ECDSA Signature** over all preceding bytes. KDF (§6.8.3):
`SecretSalt = L(le16) | "opcua-secret" | SenderPublicKey | ReceiverPublicKey`; HKDF Extract(salt, IKM=ECDH
x-coord)+Expand(info=salt); **derive ONLY EncryptingKey(16 P-256 / 32 P-384)+IV(16)** (Table 71 — no SigningKey); SHA-256/
P-256, SHA-384/P-384. Padding: `BlockSize=IV.len; Data.len=4+Nonce.len+4+Secret.len+2; pad = (Data.len%BS==0)?0:BS-Data.len%BS; if(pad+Secret.len<BS) pad+=BS`. Decrypt order: verify cert+signature → decrypt →
verify padding → check Nonce==current server nonce → extract. Reuse `ecdh_shared_secret`,
`Hkdf::<Sha256/384>`, `AesKey` (AES-128/256-CBC per curve), `asymmetric_sign`/`asymmetric_verify_signature`. Behind `ecc`.

## Format: `[ID] [P?] [Story] Description`

---

## Phase 1: Setup

- [ ] T001 Capture the baseline gate; confirm in-tree the `EccEncryptedSecret` DataType NodeId
  (`async-opcua-types` generated `node_ids.rs`), the `AesKey` AES-128/256-CBC encrypt/decrypt API (`encrypt_aes128_cbc`/`encrypt_aes256_cbc`, NoPadding), and the
  exact signatures of `ecdh_shared_secret`, `Hkdf::<Sha256/384>` usage, and
  `SecurityPolicy::asymmetric_sign`/`asymmetric_verify_signature`; **confirm the 012 ECC policies use
  AES-CBC per curve (P-256 Aes128Cbc / P-384 Aes256Cbc, not AEAD/AES-GCM)** so the §6.8.3 non-AuthenticatedEncryption branch applies;
  re-confirm the §7.40.2.5 / §6.8.3 facts in research.md against `~/opcua-specs`. No code change.

## Phase 2: Foundational (Blocking Prerequisites)

- [ ] T002 [P] Claude-authored failing tests for the §6.8.3 KDF in
  `async-opcua-crypto/src/tests/ecc_encrypted_secret.rs`: (a) the underlying HKDF Extract+Expand matches
  **RFC 5869 Appendix A** vectors (SHA-256; a SHA-384 known vector); (b) `derive_secret_keys` builds the
  `SecretSalt = L | "opcua-secret" | SenderPublicKey | ReceiverPublicKey` and the Table 71 split
  (EncryptingKey[0..EncKeyLen], IV[EncKeyLen..EncKeyLen+16]; EncKeyLen=16 P-256 / 32 P-384) reproduces a hand-computed fixture. Register the module in
  `tests/mod.rs` (ecc-gated).
- [ ] T003 [P] Claude-authored failing tests for the envelope codec: a crafted `EccEncryptedSecret` byte
  fixture (known fields) parses to the exact Table 186 fields and re-serializes byte-identically;
  malformed/truncated/oversized `Length`/`KeyDataLength`/ByteString bytes return an error (no panic).
- [ ] T004 §6.8.3 KDF in `async-opcua-crypto/src/ecc.rs`: `derive_secret_keys(curve, shared_secret,
  sender_public_key, receiver_public_key) -> Result<EccSecretKeys, Error>` (`{ encrypting_key: AesKey,
  iv: Vec<u8> }`, `Zeroizing`), using the `opcua-secret` salt + `L = EncKeyLen + IvLen`, HKDF per curve.
  Panic-free; behind `ecc`. (codex; depends T002)
- [ ] T005 EccEncryptedSecret envelope codec in `async-opcua-crypto/src/ecc.rs` (or a submodule):
  build + parse the Table 186 layout (ExtensionObject TypeId/EncodingMask=1/Length prefix, common header,
  unencrypted KeyData, encrypted-payload blob boundary, trailing Signature). Bound every
  attacker-influenced length before allocating; parse is panic-free and fail-closed. (codex; depends T003)
- [ ] T006 Envelope asymmetric signing in `ecc.rs`: compute the ECDSA Signature over the
  data-to-sign (all bytes preceding the Signature, per Figure 39) with `asymmetric_sign`, and verify it
  with `asymmetric_verify_signature` against a signer cert — used by encrypt/decrypt. (codex; depends T005)

**Checkpoint**: KDF + envelope codec + envelope sign/verify exist and are independently tested; the
stories can proceed.

## Phase 3: User Story 1 — Server decrypts an ECC UserName password (P1) 🎯 MVP

**Goal**: server parses+verifies+decrypts an `EccEncryptedSecret` password under ECC; fail-closed uniform error.

- [ ] T007 [US1] Claude-authored failing tests: a crafted `EccEncryptedSecret` (known P-256/P-384
  ephemeral keys, §6.8.3 KDF, current server nonce) decrypts via `ecc_decrypt_secret` to the exact
  password; signature verified before decrypt; wrong-nonce, tampered ciphertext/signature/header, and a
  malformed envelope each return the **same** uniform error (`BadIdentityTokenRejected`), never a panic.
- [ ] T008 [US1] Implement `ecc_decrypt_secret(security_policy, encrypted, server_nonce,
  server_ephemeral_private, signer_cert) -> Result<ByteString, Error>` in
  `async-opcua-crypto/src/user_identity.rs`: parse (T005) → validate cert + verify Signature (T006) →
  ECDH(server private, SenderPublicKey) + `derive_secret_keys` (T004) → AES-CBC decrypt (per curve) → verify
  padding → check Nonce == server_nonce → return Secret. Single uniform error on any failure; panic-free.
  (codex; depends T004–T006, T007)
- [ ] T009 [US1] Wire the server: add an ECC branch to `decrypt_identity_token_secret` in
  `async-opcua-server/src/info.rs` (when the channel policy is ECC and the token carries an
  `EccEncryptedSecret`, call `ecc_decrypt_secret` with the session's server EphemeralKey private + the
  client cert known from the channel + the current server nonce). Legacy RSA / None branches unchanged.
  (codex; depends T008)
- [ ] T010 [US1] Gate; verify T007 passes; **commit US1** (`feat(016 US1): server decrypts an ECC EccEncryptedSecret UserName password`).

## Phase 4: User Story 2 — Client encrypts a UserName secret (P1)

**Goal**: client wraps the password as an `EccEncryptedSecret` the server (US1) decrypts; round-trip P-256/P-384.

- [ ] T011 [US2] Claude-authored tests: `ecc_encrypt_secret` output round-trips through `ecc_decrypt_secret`
  on real P-256 and P-384 keys (client-encrypt ↔ server-decrypt) recovering the original password; the
  produced bytes parse as a Table 186 envelope bound to the given server nonce.
- [ ] T012 [US2] Implement `ecc_encrypt_secret(security_policy, server_nonce,
  receiver_ephemeral_public_key, signing_key, signing_cert, secret_to_encrypt) -> Result<ByteString, Error>`
  in `async-opcua-crypto/src/user_identity.rs`: create a fresh client EphemeralKey (sender), ECDH +
  `derive_secret_keys`, build payload + padding (§6.8.3 formula), AES-CBC encrypt, serialize the envelope
  (T005), sign (T006), append Signature. Panic-free; behind `ecc`. (codex; depends T004–T006, T011)
- [ ] T013 [US2] Wire the client: in `async-opcua-client/src/session/services/session.rs`, when the
  negotiated policy is ECC and a server `ECDHKey` was retained (015a
  `Session.retained_server_ephemeral_key`), produce an `EccEncryptedSecret` via `ecc_encrypt_secret` for
  the UserName password instead of the legacy RSA secret. RSA / None paths unchanged. (codex; depends T012)
- [ ] T014 [US2] Gate; verify T011 passes; **commit US2** (`feat(016 US2): client encrypts a UserName secret as an EccEncryptedSecret`).

## Phase 5: User Story 3 — IssuedIdentityToken secret under ECC (P2)

**Goal**: the same envelope applied to `IssuedIdentityToken.tokenData`.

- [ ] T015 [US3] Claude-authored tests: an `IssuedIdentityToken` whose `tokenData` is an
  `EccEncryptedSecret` round-trips client→server on P-256/P-384; wrong-nonce/tampered → uniform reject, no panic.
- [ ] T016 [US3] Wire the IssuedIdentityToken path on both sides (client encrypt in
  `session/services/session.rs`; server decrypt branch in `info.rs`) to use the ECC envelope for issued
  token data under ECC policies, reusing T008/T012. RSA / None unchanged. (codex; depends T015)
- [ ] T017 [US3] Gate; verify T015 passes; **commit US3** (`feat(016 US3): IssuedIdentityToken secret under ECC`).

## Phase 6: User Story 4 — Consumed-key anti-replay end-to-end (P1)

**Goal**: server marks its EphemeralKey consumed after a decrypt; consumed key / replayed secret rejected;
the real consumed state drives the §6.8.2 `decide_ecdh_key_action` (closes the 015a deferral).

- [ ] T018 [US4] Claude-authored tests: after a successful ActivateSession that consumed the server
  EphemeralKey, (a) re-presenting the same EphemeralKey / the same `EccEncryptedSecret` is rejected;
  (b) `decide_ecdh_key_action(None, Some(prev), /*consumed=*/true)` is what the next ActivateSession now
  feeds (real state, not hardwired false) → issues a fresh key. Unit-level where a full handshake is heavy.
- [ ] T019 [US4] Implement the consumed-state in `async-opcua-server/src/session/instance.rs` +
  `session/manager.rs`: mark the server EphemeralKey consumed on a successful identity-token decrypt;
  reject reuse of a consumed key / a duplicate secret; replace the 015a hardwired
  `previous_key_consumed = false` at the ActivateSession `decide_ecdh_key_action` call with the real
  per-session consumed flag. (codex; depends T009, T018)
- [ ] T020 [US4] Gate; verify T018 passes; **commit US4** (`feat(016 US4): consumed-key anti-replay enforced end-to-end`).

## Phase 7: User Story 5 — Rollout & backward compatibility (P3)

- [ ] T021 [P] [US5] Claude-authored regression tests: RSA / `None` / no-ECC identity-token
  create+activate behave byte-identically (legacy secret unchanged); the policy correctly selects RSA vs
  ECC vs None; confirm the `ecc`-off build compiles with no ECC secret handling.
- [ ] T022 [US5] Gate (incl. `--no-default-features` build); verify T021 passes; **commit US5**
  (`test(016 US5): rollout + backward-compat (RSA/None/no-ECC unchanged)`).

## Phase 8: Polish

- [ ] T023 [P] Fuzz: extend `fuzz/fuzz_targets/fuzz_ecc.rs` to run `ecc_decrypt_secret` over attacker-
  controlled `EccEncryptedSecret` bytes (fixed curve + key) → zero panics; run a bounded campaign.
- [ ] T024 [P] Docs: document the `EccEncryptedSecret` identity-token path (§7.40.2.5 / §6.8.3 KDF,
  asymmetric signature, nonce-binding, consumed-key anti-replay) in `docs/crypto.md`; note it completes
  the 015a exchange.
- [ ] T025 Final gate: fmt + clippy --all-targets --all-features + crypto/server/client tests +
  integration (failures confirmed in isolation as pre-existing flakiness) + `--no-default-features`
  build; confirm RSA/None byte-identical.

---

## Dependencies & Execution Order

- **Setup (T001)** → **Foundational (T002–T006)** block the stories. Within foundational: T002→T004
  (KDF), T003→T005 (codec), T005→T006 (sign). **US1** (server-decrypt, MVP) → **US2** (client-encrypt,
  enables real round-trips) → **US3** (issued token) ; **US4** (anti-replay) depends on US1's decrypt
  wiring; **US5** (rollout) last before polish.
- One task per codex dispatch (codex: T004, T005, T006, T008, T009, T012, T013, T016, T019; all test
  tasks are Claude). Tests precede their implementation within each story.

## Implementation Strategy

**MVP = US1** (server decrypt) + the foundational KDF/codec/sign. US2 makes the round-trip real; US3
extends to issued tokens; **US4 closes the 015a consumed-key anti-replay deferral**; US5 locks back-compat.
Reuse the 012/015a ECC primitives; AES-CBC (per curve) + asymmetric ECDSA signature; behind `ecc`.

## Notes

- codex implements production code only; Claude authors/runs all tests, with the **KDF anchored to RFC
  5869 vectors** (not loopback) and the envelope anchored to the §7.40.2.5 byte layout.
- One commit per story; RSA/None byte-identical; `ecc`-gated; fail-closed single uniform decrypt error
  (no padding/MAC/validity oracle); no panic on attacker bytes; derived keys zeroized; secrets never logged.
- Deferred (recorded): non-legacy RSA EncryptedSecret (Table 185); RSA-DH (§6.9); AuthenticatedEncryption
  (AES-GCM) variant; GDS; mixed RSA+ECC multi-cert server.
