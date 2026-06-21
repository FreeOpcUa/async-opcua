---
description: "Task list for feature 014 — session-activation hardening (Part 4 §5.6)"
---

# Tasks: Session-Activation Hardening (OPC UA Part 4 §5.6)

**Input**: design docs in `/specs/014-session-activation-hardening/` (spec.md, research.md, plan.md,
data-model.md, contracts/api-surface.md, quickstart.md)
**Scope (recalibrated, see research.md)**: most of §5.6 is already implemented. This feature closes the
ONE real gap — client-cert↔channel binding at ActivateSession (`manager.rs:593`) — and locks in the
existing (under-tested) behavior with regression tests. Reconnection affordance kept.

**Tests**: INCLUDED (security trust-path; Constitution I/IV). **Verification division**: codex writes
production code only (no self-authored tests); **Claude authors and runs all tests** independently.
codex no-git guardrail + verify branch after. **One commit per user story** (the gate-&-commit task).
Gate: `cargo fmt --all --check && cargo clippy --all-targets --all-features --locked -- -D warnings &&
cargo test -p async-opcua-server && cargo test -p async-opcua --test integration_tests` (note the
pre-existing integration-suite flakiness — verify failing tests in isolation, don't chase timeouts).

## Format: `[ID] [P?] [Story] Description`

---

## Phase 1: Setup

- [X] T001 Capture the baseline gate (fmt + clippy --all-targets --all-features + `-p async-opcua-server`
  tests) so the US1 red→green and any regression is attributable. Read the existing server test module
  helpers (`async-opcua-server/src/session/manager.rs` tests `cross_channel_transfer_rules`,
  `activate_session_rejects_stale_nonce_after_intervening_activation`) + `SecureChannel::remote_cert()`
  to confirm how a `Session` + `SecureChannel` + ActivateSession are constructed in tests. No code change.

## Phase 2: User Story 1 — Client certificate ↔ secure-channel binding at ActivateSession (P1) 🎯 MVP

**Goal**: a session whose CreateSession client cert differs from the channel's peer cert is rejected at
ActivateSession (non-`None`); matching/`None` unchanged.
**Independent Test**: matching cert → activates; mismatched cert → `Bad_SecurityChecksFailed`; `None` →
unchanged; missing/malformed cert → no panic.

- [X] T002 [US1] Claude-authored failing tests in the `async-opcua-server` `session/manager.rs` test
  module: construct a session whose stored client certificate differs from the activating
  `SecureChannel`'s peer certificate → ActivateSession rejected with `Bad_SecurityChecksFailed`; a
  matching certificate → activates; `SecurityPolicy::None` → unchanged (no check); a missing/empty
  channel or session certificate on a secured policy → rejected without panic. Anchor to the existing
  test helpers from T001.
- [X] T003 [US1] Implement the binding in `async-opcua-server/src/session/manager.rs` `activate_session`
  at the `// TODO additional secure channel validation ...` site (~:593): when `security_policy != None`,
  compare `session.client_certificate()` to the activating channel's peer certificate
  (`channel.remote_cert()`) by DER/thumbprint equality; reject mismatch with
  `Error::new(StatusCode::BadSecurityChecksFailed, ...)`; panic-free on missing/malformed certs. Also
  REMOVE the stale endpoint-URL TODO comment (~:213) since `validate_endpoint_hostname` already performs
  that check. (depends T002)
- [X] T004 [US1] Gate; verify T002 passes; **commit US1**
  (`feat(014 US1): bind client certificate to the secure channel at ActivateSession`).

## Phase 3: User Story 2 — Conformance lock-in tests (P2)

**Goal**: lock in the already-correct channel-binding / endpoint-host behavior so it can't silently
regress.
**Independent Test**: cross-channel service request rejected; endpoint-host mismatch rejected; malformed
activation fields → no panic.

- [ ] T005 [P] [US2] Claude-authored integration test in `async-opcua/tests/` (loopback harness):
  activate a secured session on one secure channel, then issue a session-scoped service (e.g. Read) on a
  second channel for the same session → `Bad_SecureChannelIdInvalid` (locks in
  `controller.rs:768` `validate_secure_channel_id`). Use the existing multi-client tester helpers.
- [ ] T006 [P] [US2] Claude-authored unit tests (`async-opcua-server`): a CreateSession whose
  `endpointUrl` host is neither advertised nor in the server-cert SAN is rejected
  (`Bad_CertificateHostNameInvalid`/`Bad_TcpEndpointUrlInvalid`); malformed/oversized/truncated
  CreateSession & ActivateSession fields (absent client cert, bad nonce length, truncated signature)
  are rejected without panic.
- [ ] T007 [US2] Gate; verify T005/T006 pass; **commit US2**
  (`test(014 US2): lock in session channel-binding + endpoint-host regression tests`).

## Phase 4: Polish

- [ ] T008 Final gate: `cargo fmt --all --check` + `cargo clippy --all-targets --all-features -- -D warnings`
  + `cargo test -p async-opcua-server` + `cargo test -p async-opcua --test integration_tests` (failing
  integration tests confirmed in isolation as pre-existing flakiness). Confirm `None` path unchanged and
  the existing `cross_channel_transfer_rules` / stale-nonce tests still pass.

---

## Dependencies & Execution Order

- **Setup (T001)** → no deps. **US1** (T002→T003→T004) is the MVP fix. **US2** (T005, T006 are [P] —
  different test files — then T007) depends only on US1 being committed (so the gate runs against the
  final behavior). **Polish (T008)** last.
- Within US1: failing test → codex impl → gate-&-commit. One task per codex dispatch (only T003 is codex;
  all test tasks are Claude).

## Implementation Strategy

**MVP = US1** (the one real binding gap). US2 is pure test lock-in (no production code, all
Claude-authored). Small, single-file production change; reuse existing crypto + `SecureChannel`/`X509`.

## Notes

- codex implements T003 only; everything else is Claude-authored tests. codex no-git guardrail; verify
  branch after; do not let codex read/modify test files.
- One commit per story; `None` path byte-identical; reconnection affordance preserved.
- Deferred (recorded): strict same-channel re-activation; typed AuditCertificate*/audit events;
  client-side changes.
