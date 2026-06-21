# Implementation Plan: ECC EncryptedSecret for Identity Tokens (Part 4 §7.40.2.5 / Part 6 §6.8.3)

**Branch**: `016-ecc-encrypted-secret` | **Date**: 2026-06-21 | **Spec**: [spec.md](./spec.md)
**Input**: Feature specification from `/specs/016-ecc-encrypted-secret/spec.md`

## Summary

Implement the `EccEncryptedSecret` envelope (Part 4 §7.40.2.5, Tables 183/186) and its Part 6 §6.8.3
key-derivation, then wire it into the client (encrypt) and server (decrypt) identity-token paths so
`UserNameIdentityToken` passwords and `IssuedIdentityToken` token data can be protected under the ECC
NIST policies. Phase B of two — consumes the 015a EphemeralKey exchange. The secret is encrypted with
AES-256-CBC using a key+IV derived from ECDH(sender ephemeral, receiver ephemeral) via RFC 5869 HKDF
with the `opcua-secret` salt; integrity is an **asymmetric ECDSA signature** over the serialized
envelope (validated *before* decrypt); the embedded Nonce is bound to the current session server nonce
(replay protection); and the server marks its EphemeralKey **consumed** after a successful decrypt,
finally enforcing the §6.8.2 anti-replay that 015a deferred.

## Technical Context

**Language/Version**: Rust (workspace edition 2021), `async-opcua-crypto` / `-server` / `-client` v0.19.
**Primary Dependencies**: in-tree RustCrypto — `p256`/`p384` (`ecdh_shared_secret`), `hkdf` + `sha2`
(already deps; `Hkdf::<Sha256/384>`), `aes`/`cbc` (`AesKey` AES-256-CBC), the policy
`asymmetric_sign`/`asymmetric_verify_signature` (ECDSA). No new C dependency.
**Storage**: N/A (per-session in-memory key state; reuses `Session.ecdh_ephemeral_key` /
`Session.retained_server_ephemeral_key` from 015a).
**Testing**: `cargo test` — Claude-authored, anchored to RFC 5869 HKDF vectors + the §7.40.2.5 wire
layout + client↔server round-trips on real P-256/P-384 keys (verification division).
**Target Platform**: all async-opcua targets (incl. embedded); behind the `ecc` feature.
**Project Type**: library (network protocol stack).
**Performance Goals**: N/A beyond "bounded time on attacker input" — no unbounded allocation/recursion.
**Constraints**: pure-Rust; no panics on attacker bytes; **fail-closed, single uniform decrypt error
(no padding/MAC/validity oracle)**; legacy RSA + `None` byte-identical; `ecc`-off build identical;
`clippy --all-targets --all-features` clean.
**Scale/Scope**: one envelope codec + one §6.8.3 KDF + client/server identity-token wiring + consumed-key
state. ~2 crypto modules + 2 wiring sites.

## Constitution Check

- **I. Correctness Over Completion (NON-NEGOTIABLE)**: wire format + KDF pinned from the actual Part 4
  §7.40.2.5 / Part 6 §6.8.3 PDFs (see research.md), not guessed. ✅
- **IV. Security Is Paramount**: attacker-facing decrypt path — MUST NOT panic, MUST bound the
  envelope `Length`/`KeyDataLength`/padding before allocating, MUST fail closed with a **single
  uniform error** (no padding-vs-MAC distinction → no oracle), validates the ECDSA signature *before*
  decrypting (per §6.8.3 "Receivers shall validate the SigningCertificate and signature before
  decrypting"), binds to the current server nonce (anti-replay), marks keys consumed (anti-replay),
  zeroizes derived keys. Secrets never logged. ✅
- **II. Do It Right Once / III. Individual Task Discipline**: one codex task per implementation unit;
  one commit per user story; reuse the existing ECDH/HKDF/AES/ECDSA primitives rather than re-rolling. ✅
- **V. Leave It Better**: the consumed-key state replaces 015a's hardwired `previous_key_consumed=false`
  with real state (closing the documented gap); no scaffolding left behind. ✅
- **Verification division**: codex implements; Claude authors/runs all tests anchored to external ground
  truth (RFC 5869 vectors specifically — the division caught a rigged HKDF test on 012). ✅

**Gate: PASS** — no violations; no Complexity Tracking entries required.

## Project Structure

### Documentation (this feature)

```
specs/016-ecc-encrypted-secret/
├── spec.md
├── plan.md            # this file
├── research.md        # §7.40.2.5 layout + §6.8.3 KDF pinned facts + decisions
├── data-model.md      # EccEncryptedSecret envelope + KDF + consumed-state entities
├── quickstart.md      # verification commands per story
├── contracts/
│   └── api-surface.md  # new crypto helpers + wiring points
└── checklists/
    └── requirements.md
```

### Source Code (repository root)

```
async-opcua-crypto/src/
├── ecc.rs                     # ADD: derive_secret_keys (§6.8.3 KDF), EccEncryptedSecret
│                              #      build/parse + ECDSA sign/verify of the envelope
├── user_identity.rs           # ADD: ecc_encrypt_secret / ecc_decrypt_secret (mirror legacy_*)
└── tests/
    └── ecc_encrypted_secret.rs  # NEW (Claude): RFC 5869 KDF vectors, fixture decrypt,
                                  #   round-trip, tamper/wrong-nonce/uniform-error, replay
async-opcua-server/src/
├── info.rs                    # decrypt_identity_token_secret: add ECC branch
└── session/manager.rs         # mark EphemeralKey consumed after decrypt; feed real
                               #   previous_key_consumed into decide_ecdh_key_action
async-opcua-client/src/
└── session/services/session.rs # encrypt UserName/Issued secret as EccEncryptedSecret under ECC
fuzz/fuzz_targets/
└── fuzz_ecc.rs                # EXTEND: ecc_decrypt_secret over attacker envelope bytes
```

**Structure decision**: extend the existing crypto module (`ecc.rs` + `user_identity.rs`) and the two
existing identity-token wiring sites; no new crate or module layout. `EccEncryptedSecret` is **not** a
codegen struct (only its DataType NodeId exists) — it is hand-serialized per Table 183/186 with the
ExtensionObject TypeId/EncodingMask/Length prefix.

## Complexity Tracking

No constitution violations; no entries.
