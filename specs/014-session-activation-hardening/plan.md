# Implementation Plan: Session-Activation Hardening (OPC UA Part 4 §5.6)

**Branch**: `014-session-activation-hardening` | **Date**: 2026-06-21 | **Spec**: [spec.md](./spec.md)
**Input**: Feature specification from `specs/014-session-activation-hardening/spec.md`

## Summary

Phase-0 research ([research.md](./research.md)) established that most of OPC UA Part 4 §5.6 session
hardening is **already implemented and (mostly) tested** in `async-opcua-server`: session↔channel
binding on every request, client-signature/nonce verification, per-activation nonce freshness with
stale-nonce rejection, user-identity-token nonce binding, and endpoint-URL host validation. The scope
is therefore trimmed (user-confirmed) to:

1. **Close the one genuine gap** — the `manager.rs:593` TODO: at ActivateSession, when the security
   policy is not `None`, verify the session's CreateSession client certificate matches the activating
   channel's peer certificate (`SecureChannel::remote_cert()`), rejecting a mismatch with
   `Bad_SecurityChecksFailed`. Remove the stale `manager.rs:213` TODO comment.
2. **Lock in** the existing behavior with independently-authored regression tests (cross-channel
   service-request rejection for a secured session; CreateSession endpoint-host mismatch; malformed
   activation fields → no panic).

The activated-secured-session reconnection affordance is **kept** (user decision).

## Technical Context

**Language/Version**: Rust (workspace MSRV) — crate `async-opcua-server` (+ test helpers).
**Primary Dependencies**: existing only — `opcua_crypto` (`X509`, `verify_signature_data`,
thumbprint), `SecureChannel::remote_cert()` (`async-opcua-core`). **No new dependency.**
**Storage**: N/A (in-memory session state).
**Testing**: `cargo test` — server unit tests (`session/manager.rs` test module) + the `async-opcua`
integration loopback suite for the cross-channel end-to-end case; crafted CreateSession/ActivateSession
scenarios authored by Claude.
**Target Platform**: any Rust target (pure-Rust path).
**Project Type**: library (network-facing protocol stack).
**Performance Goals**: per-handshake; a single certificate equality check — negligible.
**Constraints**: no panics on attacker-supplied activation fields; fail-closed; `None` path unchanged;
conformant clients unaffected; `clippy --all-targets --all-features` clean.
**Scale/Scope**: ~1 production file touched (`async-opcua-server/src/session/manager.rs`), plus the
server test module and (for the lock-in cross-channel test) the integration test harness.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

- **I. Correctness Over Completion** — ✅ The research pass prevented re-implementing already-correct
  code; the feature targets the one real gap + closes test-coverage holes. Correctness is the point.
- **II. Do It Right Once** — ✅ Reuses existing crypto/`X509`/cert-equality and the existing
  validation flow; adds one check at the documented TODO rather than a parallel mechanism. Removes a
  stale comment rather than leaving misleading debris.
- **III. Individual Task Discipline** — ✅ Decomposed into a small US1 (cert-binding) + US2 (lock-in
  tests); one task per codex dispatch; one commit per story.
- **IV. Security Is Paramount** — ✅ This is security work (session-activation trust binding).
  Fail-closed; panic-free on attacker certs; `None` unchanged; no secret logging. Strongly aligned.
- **V. Leave It Better** — ✅ Replaces the `:593` TODO with a real check and removes the stale `:213`
  TODO; adds regression tests that lock in previously-untested security behavior.

**Result: PASS — no violations.** No Complexity Tracking entries required.

## Project Structure

### Documentation (this feature)

```text
specs/014-session-activation-hardening/
├── plan.md              # This file
├── research.md          # Phase 0 — code-state map + scope recalibration
├── data-model.md        # Phase 1 — entities touched (Session, SecureChannel)
├── quickstart.md        # Phase 1 — how to verify each story
├── contracts/
│   └── api-surface.md   # Phase 1 — (internal) behavior contract; no public API change
└── tasks.md             # Phase 2 (/speckit-tasks)
```

### Source Code (repository root)

```text
async-opcua-server/src/session/
├── manager.rs           # add the client-cert↔channel binding at ActivateSession (~:593);
│                        #   remove the stale endpoint-URL TODO (~:213); reuse verify path
│                        #   (test module here for the unit-level activation tests)
└── instance.rs          # (read-only) session.client_certificate() accessor reused

async-opcua-core/src/comms/secure_channel.rs   # (read-only) SecureChannel::remote_cert() reused

async-opcua/tests/                              # integration lock-in test: cross-channel service
                                                #   request rejected for an activated secured session
```

**Structure Decision**: The change lives where the TODO is — `session/manager.rs::activate_session`,
reusing `session.client_certificate()` and `channel.remote_cert()`. Tests are split: unit tests in the
server `manager.rs` test module (activation-level cert match/mismatch, malformed fields), and one
integration test in the `async-opcua` loopback suite for the end-to-end cross-channel service-request
rejection.

## Complexity Tracking

> No Constitution Check violations — section intentionally empty.
