---
description: "Task list for feature 025 — security audit remediation (round 2)"
---

# Tasks: Security Audit Remediation (round 2)

**Verification division**: codex implements the production fixes applying **ponytail** (minimal,
fail-closed, no over-engineering, smallest diff, no new dep); **Claude authors + runs ALL tests** — each
finding gets a test that FAILS on current code and PASSES after the fix, anchored to OPC UA Part 2/4/6/14
+ the 2026-06-22 review (NOT codex loopback). VERIFY-BEFORE-FIX: write/observe the failing test (or a
documented code trace) before the fix. Non-reproducing finding → document + skip. One commit per US.

**Gate**: `cargo fmt --all --check && cargo clippy --all-targets --all-features --locked -- -D warnings`
+ no-default / json-off legs + the touched crates' tests, single-threaded. Valid inputs must still pass.

## Phase 1: Setup
- [ ] T001 Confirm exact fix sites + that the repo's VALID fixture certs/tokens/messages are available to
  use as no-false-reject guards. No code change.

## Phase 2: US1 — certificate validation (P1) 🎯
- [ ] T002 [P] [US1] Claude: failing tests in async-opcua-crypto (cert_chain) — (a) CA-issuer w/o
  BasicConstraints CA:TRUE rejected; (b) leaf w/ required-but-absent KeyUsage/EKU rejected; (c) pathlen
  violation rejected; (d) non-self-signed leaf as own anchor (trust_unknown_certs) w/ a bad signature
  rejected; (e) revoked cert w/ DN/serial-encoding-mismatched CRL rejected (strict); PLUS valid fixture
  certs still pass. (verify-before-fix)
- [ ] T003 [US1] codex: fix cert_chain.rs fail-closed per the OPC UA app-instance-cert profile (don't
  over-tighten) — required-ext absence fails, pathLenConstraint enforced, verify_chain_signatures never
  skips an unverified non-self-signed cert (fix comment), CRL issuer/serial matching robust (structural,
  not lossy), strict revocation fails closed. (depends T002)
- [ ] T004 [US1] Gate (incl. valid-cert no-regression); **commit US1**.

## Phase 3: US2 — OAuth2 / JWT (P2)
- [ ] T005 [P] [US2] Claude: failing tests — JWT signed by a non-issuer trusted cert rejected; unset
  oauth2_issuer/audience (issued-token auth enabled) fails closed; a JWT signed by the configured issuer
  still accepted. (verify-before-fix)
- [ ] T006 [US2] codex: pin JWT verify to a configured OAuth2 issuer cert (not the whole trust dir);
  require issuer/audience explicitly (fail closed if unset) — document the behavior change. (depends T005)
- [ ] T007 [US2] Gate; **commit US2**.

## Phase 4: US3 — PubSub (P3)
- [ ] T008 [P] [US3] Claude: failing tests in async-opcua-pubsub — two SignAndEncrypt messages get
  DISTINCT IVs; encrypt→decrypt round-trips; a replayed message is rejected by the subscriber. (verify-before-fix)
- [ ] T009 [US3] codex: per-message IV (Part 14) in security/codec.rs; subscriber replay reject
  (monotonic/bounded sequence). Evaluate decrypt-then-MAC: fix only if a real contained exposure, else
  doc-comment the construction. (depends T008)
- [ ] T010 [US3] Gate; **commit US3**.

## Phase 5: US4 — Safety SPDU (P4)
- [ ] T011 [P] [US4] Claude: failing tests in async-opcua-safety — one reordered/dropped SPDU then next
  valid SPDU still validates (bounded window); first-packet + wraparound handled; future-dated timestamp
  rejected. (verify-before-fix)
- [ ] T012 [US4] codex: bounded sequence window + first-packet/wraparound + timeout bounding in
  validator.rs; add the black-channel CRC doc comment (no CRC change). (depends T011)
- [ ] T013 [US4] Gate; **commit US4**.

## Phase 6: US5 — decoder + audit (P5)
- [ ] T014 [P] [US5] Claude: a small message claiming a near-cap array length doesn't eager-allocate
  proportionally (assert via a bounded-reservation observable or a focused decode test); an integration
  test that a successful ActivateSession emits its audit event. (verify-before-fix)
- [ ] T015 [US5] codex: bounded/incremental reservation in encoding.rs + variant/mod.rs; emit success
  ActivateSession/CreateSession audit events (remove the TODOs). (depends T014)
- [ ] T016 [US5] Gate; **commit US5**.

## Phase 7: Polish
- [ ] T017 Update specs/conformance-gap-backlog.md / a SECURITY note: record the remediated findings, the
  two documented behavior changes (revocation strict posture, required OAuth2 issuer config), and the
  black-channel-CRC clarification. Note any finding that didn't reproduce.
- [ ] T018 Final gate: fmt + clippy --all-targets --all-features + no-default/json-off legs + the full
  touched-crate test set single-threaded + existing-suite spot-check.

---

## Dependencies & Execution
- Setup (T001) → US1 → US2 → US3 → US4 → US5 → Polish. Within each US: Claude failing test [P] →
  codex fix → gate+commit. codex: T003,T006,T009,T012,T015. Claude: all tests + docs. One commit per US.

## Notes
- Verify-before-fix is mandatory (FR-008): the test must fail on current code first.
- Don't over-tighten cert checks (valid OPC UA certs must still pass) or silently flip the revocation
  default. Two deliberate documented behavior changes only: strict-revocation posture + required OAuth2
  issuer config.
- Doc-only / not changed: unkeyed-CRC black-channel model. No new dependency anywhere.
