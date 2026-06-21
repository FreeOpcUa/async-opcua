# Implementation Plan: ECC Token EphemeralKey Exchange (OPC UA Part 6 §6.8.2)

**Branch**: `015-ecc-token-ephemeral-keys` | **Date**: 2026-06-21 | **Spec**: [spec.md](./spec.md)
**Input**: Feature specification from `specs/015-ecc-token-ephemeral-keys/spec.md`

## Summary

Phase A of ECC identity-token secrets (the user-confirmed split). Implement the Part 6 §6.8.2
EphemeralKey exchange that `EccEncryptedSecret` (feature 016) will depend on: the client advertises an
`ECDHPolicyUri` in the CreateSession/ActivateSession **request AdditionalHeader**; the server
generates a fresh ECC EphemeralKey for that policy, **signs** it (so the client can authenticate it),
returns it as `ECDHKey` = `EphemeralKeyType` in the **response AdditionalHeader**, tracks it per the
§6.8.2 lifecycle, and **never accepts the same EphemeralKey twice** (anti-replay). The client reads,
verifies the signature against the server certificate, and retains the most recent server EphemeralKey.
This feature does **not** build `EccEncryptedSecret` itself (feature 016).

**Approach (pinned by research):** reuse the feature-012 ECC primitives (`generate_ephemeral_keypair`,
`EphemeralPublicKey`, the curve point encoding) in `async-opcua-crypto`; add a small EphemeralKey
sign/verify helper there (the exact signed-data layout from Part 4 §7.15 / Part 6 §6.8.1 pinned at
task time). Wire `AdditionalParametersType` / `EphemeralKeyType` (already generated types) into the
server CreateSession/ActivateSession header handling and the client session services. No new
dependency.

## Technical Context

**Language/Version**: Rust (workspace MSRV) — `async-opcua-crypto`, `-server`, `-client`. `-types`
provides the generated `EphemeralKeyType` / `AdditionalParametersType` (used, not modified).
**Primary Dependencies**: existing — `ecc.rs` (012 ECDH/ephemeral primitives), `verify_signature_data`
/ `create_signature_data`, `X509`. **No new dependency.** Behind the `ecc` feature.
**Storage**: in-memory per-session server EphemeralKey state (issued key + consumed set for
anti-replay).
**Testing**: `cargo test` — crypto unit tests (EphemeralKey sign/verify, curve-point validation),
server + client unit/integration for the AdditionalHeader round-trip and the §6.8.2 lifecycle; crafted
attacker AdditionalHeader/EphemeralKeyType bytes (no panic). Claude-authored, anchored to §6.8.2 +
Table 136.
**Target Platform**: any Rust target (pure-Rust path).
**Project Type**: library (network-facing protocol stack).
**Performance Goals**: per-handshake; one ephemeral keygen + one sign/verify — negligible. The
consumed-key set is bounded per session.
**Constraints**: no panic on attacker-supplied header/key bytes; fail-closed
(`Bad_SecurityPolicyRejected` on bad policy; reject unverified/duplicate keys); RSA + `None` +
no-ECDH byte-identical; `clippy --all-targets --all-features` clean.
**Scale/Scope**: server session manager (CreateSession/ActivateSession header in/out + key lifecycle),
client session services (header out + read/verify/retain), a crypto EphemeralKey sign/verify helper.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

- **I. Correctness Over Completion** — ✅ Research surfaced the true scope (a protocol layer, not just
  crypto) and split it so each feature is correct and verifiable; anti-replay + signature verification
  are first-class requirements, not afterthoughts.
- **II. Do It Right Once** — ✅ Reuses the 012 ECC primitives and the existing signature helpers; the
  EphemeralKey exchange is the shared prerequisite for 016 (built once, here).
- **III. Individual Task Discipline** — ✅ Decomposed into server-issue, client-read/verify, lifecycle/
  anti-replay, rollout; one task per codex dispatch; one commit per story.
- **IV. Security Is Paramount** — ✅ This is security work (authenticated key exchange + anti-replay on
  an attacker-reachable handshake). Fail-closed; signature-verified ephemeral keys; panic-free header
  parsing; no secret logging. Strongly aligned.
- **V. Leave It Better** — ✅ Turns the generated-but-unused `EphemeralKeyType` into a wired, tested
  mechanism; lays the clean foundation for 016.

**Result: PASS — no violations.** No Complexity Tracking entries required.

## Project Structure

### Documentation (this feature)

```text
specs/015-ecc-token-ephemeral-keys/
├── plan.md              # This file
├── research.md          # Phase 0 — §6.8.2/§6.8.3 + §7.40.2.5 findings + the scope split
├── data-model.md        # Phase 1 — EphemeralKey exchange entities + state
├── quickstart.md        # Phase 1 — how to verify each story
├── contracts/
│   └── api-surface.md   # Phase 1 — additive API + wire (AdditionalHeader) behavior
└── tasks.md             # Phase 2 (/speckit-tasks)
```

### Source Code (repository root)

```text
async-opcua-crypto/src/
└── ecc.rs               # add EphemeralKey sign (server) + verify (client) helpers; reuse
                         #   generate_ephemeral_keypair / EphemeralPublicKey / curve encoding

async-opcua-server/src/session/
└── manager.rs           # CreateSession/ActivateSession: read ECDHPolicyUri from request
                         #   AdditionalHeader; generate+sign+return ECDHKey; track issued key;
                         #   §6.8.2 new-vs-retain lifecycle + anti-replay (never reuse a key)
└── (session state)      # per-session issued/consumed EphemeralKey

async-opcua-client/src/session/services/
└── session.rs           # send ECDHPolicyUri in request AdditionalHeader; read ECDHKey from
                         #   response, verify signature vs server cert, retain most-recent
```

**Structure Decision**: The crypto (sign/verify the EphemeralKey) lives in `async-opcua-crypto/ecc.rs`
beside the 012 primitives; the protocol plumbing lives where the headers are built/consumed (server
`session/manager.rs`, client `session/services/session.rs`). The `EphemeralKeyType` /
`AdditionalParametersType` types are reused from `async-opcua-types` (generated).

## Complexity Tracking

> No Constitution Check violations — section intentionally empty.
