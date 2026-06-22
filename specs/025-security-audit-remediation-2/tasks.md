---
description: "Task list for feature 025 — security audit remediation (round 2, RE-SCOPED)"
---

# Tasks: Security Audit Remediation (round 2)

**RE-SCOPED (2026-06-22, post-verification):** original US1 (cert validation) DROPPED — verified false
positives (deliberate, tested, RFC-5280-correct; see spec Scope Revision). Remaining: US1 OAuth2/JWT
(confirmed real), US2 PubSub IV+replay (confirmed real), US3 Safety SPDU (verify→fix), US4 decoder+audit
(verify→fix). Cert pathlen + trust_unknown_certs sig path = backlog checks, not fixes here.

**Verification division**: codex implements fixes applying **ponytail** (minimal, fail-closed, smallest
diff, no new dep); **Claude authors + runs ALL tests** — fail-before/pass-after per finding, anchored to
OPC UA Part 4/6/14 + the review (NOT codex loopback). Verify-before-fix is mandatory. One commit per US.

**Gate**: `cargo fmt --all --check && cargo clippy --all-targets --all-features --locked -- -D warnings`
+ no-default/json-off legs + touched-crate tests single-threaded. Valid inputs must still pass.

## Phase 1: US1 — OAuth2 / JWT issuer pinning + required config (P1) 🎯 [CONFIRMED REAL]
Confirmed: `identity/jwt_validator.rs:125` accepts a JWT verified by ANY cert in the trust dir;
`info.rs:838` defaults issuer/audience to hardcoded values when unset.
- [X] T001 [P] [US1] Claude: failing tests — JWT signed by a trusted NON-issuer cert is rejected; unset
  oauth2_issuer/audience (issued-token auth enabled) fails closed; JWT signed by the configured issuer
  still accepted. (verify-before-fix)
- [X] T002 [US1] codex: pin JWT verify to a configured OAuth2 issuer cert (not the whole trust dir);
  require issuer/audience explicitly, fail closed if unset; document the behavior change. (depends T001)
- [X] T003 [US1] Gate; **commit US1** (`fix(025 US1): pin OAuth2 JWT issuer + require iss/aud (fail closed)`).

## Phase 2: US2 — PubSub per-message IV + replay [SPLIT OUT → own feature]
Deferred to a dedicated Part-14 PubSub-message-security feature (the fix needs a SecurityHeader/MessageNonce
wire change + an encrypted-PubSub interop test vs the .NET reference stack / open62541; not a quick patch).
IND-CPA IV-reuse hole tracked as known-until-then. T004-T006 moved to that feature.
Confirmed: `pubsub/security/codec.rs:259` IV = `key_nonce[..block]` (static per epoch); subscriber
discards sequence_number.
- [~] T004 (SPLIT to PubSub-security feature) [P] [US2] Claude: failing tests — two SignAndEncrypt messages get DISTINCT IVs;
  encrypt→decrypt round-trips; a replayed message is rejected. (verify-before-fix)
- [~] T005 (SPLIT to PubSub-security feature) [US2] codex: per-message IV (Part 14, from MessageNonce/sequence); subscriber replay reject
  (monotonic/bounded sequence). decrypt-then-MAC: doc-comment unless a real contained exposure. (depends T004)
- [~] T006 (SPLIT to PubSub-security feature) [US2] Gate; **commit US2** (`fix(025 US2): PubSub per-message IV + replay rejection`).

## Phase 3: US3 — Safety SPDU (P3) [VERIFY → FIX]
- [X] T007 [P] [US3] Claude: VERIFY first — tests for: one reordered/dropped SPDU then next valid SPDU
  (does it permanently desync today?); first-packet; wraparound; future-dated timestamp. If current
  behavior is actually correct, document + skip. Else failing tests. (verify-before-fix)
- [~] T008 [US3] (NO FIX — verified fail-safe-by-design) codex (IF T007 confirms bugs): bounded sequence window + first-packet/wraparound +
  timeout bounding in safety/validator.rs; add the black-channel-CRC doc comment (no CRC change). (depends T007)
- [X] T009 [US3] documented no-fix (validator doc comment); **commit US3** (`fix(025 US3): Safety SPDU sequence window + timeout`) — or commit
  the documented "no-fix, verified correct" outcome.

## Phase 4: US4 — decoder eager-alloc + success audit (P4) [VERIFY → FIX]
- [X] T010 [P] [US4] Claude: VERIFY — (a) does a small message claiming near-cap array length eager-
  allocate? (b) is a successful ActivateSession audit event truly absent? Failing/observing tests. (verify-before-fix)
- [~] T011 [US4] (NO FIX — bounded by MAX_ARRAY_LENGTH=1000; audit gaps = completeness) codex (IF confirmed): bounded/incremental reservation in encoding.rs + variant/mod.rs;
  emit success ActivateSession/CreateSession audit events (remove the TODOs). (depends T010)
- [X] T012 [US4] documented no-fix; **commit US4** (`fix(025 US4): bounded decode reservation + success audit events`).

## Phase 5: Polish
- [X] T013 Backlog/SECURITY note: record the remediated REAL bugs (US1/US2 + any of US3/US4 confirmed),
  the documented behavior changes (required OAuth2 issuer config; any pubsub-IV wire impact), the
  black-channel-CRC clarification, AND the REJECTED US1-cert findings (why they were false positives) +
  the two open verify items (cert pathlen, trust_unknown_certs sig path).
- [ ] T014 Final gate: fmt + clippy --all-targets --all-features + no-default/json-off legs + touched-
  crate tests single-threaded + existing-suite spot-check.

## Notes
- Verify-before-fix mandatory. US3/US4 explicitly "verify → fix or document-skip" (the US1-cert lesson:
  don't fix tested, intended behavior). No new dependency. Ponytail: smallest fail-closed diff per fix.
