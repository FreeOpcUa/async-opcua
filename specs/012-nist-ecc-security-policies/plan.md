# Implementation Plan: NIST ECC Security Policies (ECC_nistP256 / ECC_nistP384)

**Branch**: `012-nist-ecc-security-policies` | **Date**: 2026-06-20 | **Spec**: [spec.md](./spec.md)
**Input**: Feature specification from `/specs/012-nist-ecc-security-policies/spec.md`

## Summary

Add the OPC UA NIST ECC secure-channel policies (`ECC_nistP256`, `ECC_nistP384`) for client and
server, in pure Rust. ECC differs from the existing RSA policies only in the **asymmetric /
key-agreement half**: instead of RSA-encrypting a nonce, each peer exchanges an **ephemeral EC public
key** in `OpenSecureChannel`, both compute an **ephemeral-ephemeral ECDH** shared secret, and derive
the symmetric session keys with **HKDF** (RFC 5869). Asymmetric message signatures use **ECDSA**
against the peers' EC application certificates. The symmetric layer (AES-CBC + HMAC) and the
chunking/secure-channel framework are **reused unchanged**. Brainpool, PubSub-ECC, ECC user tokens,
and any C backend are out of scope.

## Technical Context

**Language/Version**: Rust (workspace MSRV; edition 2021)
**Primary Dependencies (new, pure-Rust RustCrypto)**: `p256`, `p384` (curves + ECDSA + ECDH via
`elliptic-curve`), `ecdsa`, `hkdf`; **reuse** existing `aes`, `cbc`, `hmac`, `sha2`, `x509-cert`,
`rand`. **No `aws-lc-rs`/C dependency on the ECC path.**
**Storage**: N/A.
**Testing**: `cargo test --workspace` (unit + 98-test integration) incl. new ECC vector tests +
loopback channel tests; `cargo +nightly fuzz` for the ECC decode/handshake path;
`cargo clippy --all-targets --all-features -- -D warnings`.
**Target Platform**: same as the crate (Linux servers + embedded Linux).
**Project Type**: Rust library workspace.
**Performance Goals**: ECC handshake is per-channel-open (not hot path); existing RSA/None paths
unchanged and byte-identical.
**Constraints**: pure-Rust; additive + feature-gated (`ecc` feature); clippy/tests/codegen gates
green; no generated-code edits; secrets never logged; no panics on attacker-controlled handshake input.
**Scale/Scope**: ~5 crates touched; 5 user stories; security-critical crypto path.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | Assessment |
|-----------|-----------|
| **I. Correctness Over Completion** | ✅ Crypto correctness is the whole point — every primitive is gated on NIST/RFC/spec **known-answer vectors** (US1) before the channel is built on it; loopback + negative tests for the handshake. |
| **II. Do It Right Once** | ✅ Reuse the existing symmetric/chunking/X.509 framework; ECC touches only the asym/KDF half. Exact wire/KDF details pinned from Part 6 §6.8 (see research.md), not guessed. |
| **III. Individual Task Discipline** | ✅ Decomposed one-task-per-line; one task per codex dispatch; one commit per user story. |
| **IV. Security Is Paramount** | ✅ **The highest-stakes principle here.** New code sits on the untrusted handshake path: MUST be fail-closed (reject bad points/curves/sigs), panic-free, constant-time where the primitives allow, and never log secrets. Each story gets a security-focused review. |
| **V. Leave It Better** | ✅ Additive, feature-gated; no regression to RSA/None; documents the ECC deployment story. |

**Gate result: PASS** — with the standing condition that the crypto is validated against published
vectors and that the **interop-validation limitation** (SC-007: a third-party ECC peer may be
unavailable in CI) is carried as a recorded risk, not silently ignored. No Complexity Tracking
entries required.

## Project Structure

### Documentation (this feature)

```text
specs/012-nist-ecc-security-policies/
├── plan.md · research.md · data-model.md · quickstart.md
├── contracts/api-surface.md
├── checklists/requirements.md
└── tasks.md            # created by /speckit-tasks
```

### Source Code — crates touched per story

```text
async-opcua-crypto/src/
├── security_policy.rs           # US5: EccNistP256/EccNistP384 variants, URIs, FromStr/Display, supported()
├── ecc/ (new module)            # US1: ECDSA sign/verify, ephemeral ECDH, HKDF key derivation, point enc/dec
├── x509.rs / certificate code   # US2: EC (P-256/P-384) public-key parse/validate, curve<->policy match
└── lib.rs / hash.rs             # US1: wire ECC algorithm IDs / key-derivation helpers
async-opcua-core/src/comms/
├── secure_channel.rs            # US3/US4: ECC key-agreement branch + HKDF-derived SecurityKeys
└── (chunker/message protection) # reused unchanged (symmetric AES-CBC+HMAC)
async-opcua-client/src/ + async-opcua-server/src/
└── (OpenSecureChannel flow)     # US3/US4: send/receive ephemeral EC pubkey; US5: endpoint/connect config + negotiation
async-opcua-types/src/           # US5: policy URI constants (+ any ECC algorithm constants)
samples/ + docs/                 # US5: ECC endpoint example + docs
```

**Structure Decision**: New `ecc` module in `async-opcua-crypto`; an ECC branch in the
`secure_channel` key-agreement/derivation step; ephemeral-key plumbing in the client/server
OpenSecureChannel flow. Everything else (symmetric protection, chunking, cert trust) is reused. All
ECC code behind an `ecc` cargo feature.

## Complexity Tracking

> No constitution violations — section intentionally empty.
