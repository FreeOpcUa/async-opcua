# Implementation Plan: Part-14 Conformant UADP PubSub Message Security

**Branch**: `026-pubsub-message-security` | **Date**: 2026-06-22 | **Spec**: [spec.md](./spec.md)
**Input**: Feature specification from `specs/026-pubsub-message-security/spec.md`

## Summary

Replace the proprietary `OPCUAPS1` / AES-CBC secured-UADP envelope with OPC UA Part 14 §7.2.4.4
conformant NetworkMessage security: add the `PubSub-Aes128-CTR` / `PubSub-Aes256-CTR` symmetric
policies (AES-CTR encryption via the RustCrypto `ctr` crate's `Ctr32BE`, HMAC-SHA256 signature),
emit the real Part-14 SecurityHeader (SecurityFlags, SecurityTokenId, NonceLength, MessageNonce)
interleaved between the header region and the encrypted Payload, generate a fresh per-message
MessageNonce (Random[4] ‖ NetworkMessage SequenceNumber) that derives a unique AES-CTR counter
block per message (eliminating the static-IV / IND-CPA reuse), enforce a bounded subscriber
anti-replay window on the NetworkMessage SequenceNumber, and prove conformance with spec-anchored
known-answer vectors plus external-stack interop. The exact wire layout is locked in
[research.md](./research.md) against the local Part 14 1.05.06 spec (Tables 155–157, §7.2.2.2.3,
Annex A.4).

## Technical Context

**Language/Version**: Rust (workspace edition; stable + beta CI legs)
**Primary Dependencies**: existing `aes` 0.8 + `cbc` 0.1 + `hmac`/`sha2` (RustCrypto) symmetric
stack in `async-opcua-crypto`; **new**: `ctr` 0.9 (RustCrypto, `Ctr32BE`) — user-approved, same
`cipher` 0.4 family already in the tree, no new transitive deps, cargo-deny clean. Randomness via
existing `opcua_crypto::random`. No other new runtime dependency.
**Storage**: N/A (wire codec + in-memory per-group replay window)
**Testing**: `cargo test` / `cargo nextest`; independent tests authored by Claude anchored to Part
14 Tables 155–157 KAT vectors + external-stack fixtures (`dotnet-tests/external-tests`,
`3rd-party/open62541`); NOT codex loopback.
**Target Platform**: Linux (CI); library consumed cross-platform
**Project Type**: Rust library (network protocol stack) — crates `async-opcua-crypto`,
`async-opcua-pubsub`, `async-opcua-types`
**Performance Goals**: PubSub publish/subscribe hot path; AES-CTR is in-place and size-preserving,
encrypt/decrypt + HMAC per NetworkMessage; replay check O(1) amortized over a fixed window.
**Constraints**: every decode path fails closed, no panic/unwrap/over-allocation on
attacker-controlled bytes; bounded replay-tracking memory; clippy `-D warnings` across
`--all-features`, `--no-default-features`, and `json`-off legs; fork's full Actions CI green.
**Scale/Scope**: 3 crates touched; ~1 new crypto policy pair, 1 SecurityHeader codec, 1 replay
window, KAT + interop tests. Breaking change to the secured-UADP wire format (pre-release format,
no compat shim per FR-013).

## Constitution Check

*GATE: must pass before Phase 0 and re-checked after Phase 1.*

| Principle | Assessment |
|---|---|
| **I. Correctness Over Completion** | PASS — done = byte-exact against Part 14 Tables 155–157 KAT vectors + external interop + fail-closed negative tests, not just round-trip. Wire layout pinned to the local spec, not guessed. |
| **II. Do It Right Once** | PASS — full Part-14 conformance (the user chose this over a minimal in-envelope patch), removing the proprietary format rather than layering on it; audited `ctr` crate over hand-rolled crypto. |
| **III. Individual Task Discipline** | PASS — tasks decomposed per user story (US1→US5), one verifiable change at a time; codex implements one task per dispatch (no batching). |
| **IV. Security Is Paramount** | PASS (central goal) — fixes the static-IV IND-CPA reuse and adds replay protection; AES-CTR per-message IV; verify-then-decrypt; fail-closed on every malformed input; bounded replay memory resists DoS; keys/nonces not logged. New crypto dep checked vs advisories (cargo-deny). |
| **V. Leave It Better Than You Found It** | PASS — deletes the misleading `OPCUAPS1` envelope + the stale "experimental, proprietary" lib.rs note, replaces with conformant interoperable security; tightens tests. |

**Network-facing / untrusted-input gate**: the decode path is reachable from the network (UDP/MQTT
PubSub subscriber). All SecurityHeader length fields (NonceLength, SecurityFooterSize, payload
bounds) MUST be bounds-checked before allocation, reuse the existing `max_secured_payload_len` /
`max_*` `DecodingOptions` caps, and reject malformed input with an error (no panic). This is an
explicit acceptance gate for US2.

No violations → Complexity Tracking section omitted.

## Project Structure

### Documentation (this feature)

```text
specs/026-pubsub-message-security/
├── plan.md              # This file
├── research.md          # Phase 0 — wire format + decisions (DONE)
├── data-model.md        # Phase 1 — entities (DONE)
├── quickstart.md        # Phase 1 — how to exercise/verify (DONE)
├── contracts/
│   └── pubsub-message-security.md   # Phase 1 — crypto-policy + codec API contract (DONE)
├── checklists/
│   └── requirements.md  # spec quality checklist (DONE)
└── tasks.md             # Phase 2 — /speckit-tasks (NOT created here)
```

### Source Code (repository root)

```text
async-opcua-crypto/
├── Cargo.toml                       # + ctr = "0.9"
└── src/
    ├── security_policy.rs           # + PubSub-Aes128-CTR / PubSub-Aes256-CTR variants,
    │                                #   URIs, key/nonce/sig lengths, symmetric_* dispatch
    ├── policy/aes.rs                # + Aes128Ctr / Aes256Ctr (Ctr32BE) encrypt/decrypt;
    │                                #   counter-block construction per Table 157
    └── aes/aeskey.rs                # + ctr keystream helpers if needed

async-opcua-types/
└── src/                             # (only if a new DecodingOptions cap or flag is needed;
                                     #  prefer reusing existing max_secured_payload_len etc.)

async-opcua-pubsub/
├── Cargo.toml
└── src/
    ├── codec/uadp.rs                # SecurityHeader emit/parse INTERLEAVED; NetworkMessage-level
    │                                #   SequenceNumber + NetworkMessageNumber in GroupHeader;
    │                                #   ExtendedFlags1 bit4; encrypt only the Payload region
    ├── security/
    │   ├── codec.rs                 # REWRITE: remove OPCUAPS1 envelope; Part-14 sign/encrypt over
    │   │                            #   the real layout; verify-then-decrypt; MessageNonce gen
    │   ├── group.rs                 # SecurityKeySet/SecurityGroup gain SecurityTokenId awareness
    │   ├── replay.rs (new)          # bounded anti-replay window keyed by token id (US4)
    │   └── mod.rs
    ├── engine.rs                    # wire codec into encode/decode; select key set by token id
    └── lib.rs                       # delete the "proprietary OPCUAPS1 / experimental" note

async-opcua-pubsub/tests/
├── security_tests.rs               # extend: Part-14 header fields, IV-uniqueness, fail-closed
├── message_security_vectors.rs (new) # Table 155–157 KAT vectors + interop fixtures (US1, US5)
└── replay_tests.rs (new)           # US4 replay/window/wrap/reset

dotnet-tests/external-tests/         # extend pubsub interop to SignAndEncrypt (US5, stretch)
```

**Structure Decision**: existing 3-crate split is kept. Crypto primitives + policies live in
`async-opcua-crypto` (US1); the Part-14 framing, nonce, and replay live in `async-opcua-pubsub`
(US2–US4); interop fixtures/tests live in `async-opcua-pubsub/tests` and `dotnet-tests` (US5). No
new crate. The one new module is `security/replay.rs` (a single, self-contained responsibility).

## Verification Division (binding for implement phase)

- **codex** implements production code only — one task per dispatch, no tests, no git operations
  (no-git guardrail; verify branch is `026-pubsub-message-security` after each dispatch). Apply
  ponytail: minimal correct diff, fail-closed, no speculative config.
- **Claude** authors and runs ALL tests independently, anchored to Part 14 Tables 155–157 and the
  external interop stack — never to codex's own output. Each story gets tests that FAIL before the
  change and PASS after (IV reuse, replay, malformed-header fail-closed, CTR KAT, interop).
- PRs target the FORK `occamsshavingkit/async-opcua` (private disclosure pending; no upstream PR).
- One commit per user story.

## Phasing / dependency order

US1 (CTR policies) → US2 (SecurityHeader framing) → US3 (per-message nonce/IV) → US4 (replay) →
US5 (interop). US1 is the cipher foundation; US2 carries the nonce/token; US3 is the core fix and
needs both; US4 needs the decoded NetworkMessage SequenceNumber; US5 validates the whole. MVP =
US1+US2+US3 (a conformant, IND-CPA-safe signed+encrypted message); US4 and US5 harden and prove it.
