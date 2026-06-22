# Feature Specification: Security Audit Remediation (round 2)

**Feature Branch**: `025-security-audit-remediation-2`
**Created**: 2026-06-22
**Status**: Draft
**Input**: Fix the confirmed findings from the 2026-06-22 security review (cert validation, OAuth2/JWT,
PubSub security, Safety SPDU, binary decoder, audit). Verify each finding first; fix minimally and
fail-closed; document the by-design ones.

## Context *(mandatory)*

A focused security review of the fork's additions surfaced defects clustered in the **trust-boundary and
untrusted-input surface**. The core secured path (anonymous/username/password over a secured channel) is
sound; the weaknesses are in certificate validation (always reachable, pre-auth) and in opt-in subsystems
(OAuth2 issued tokens, PubSub, Safety). This feature remediates them.

**Method (mandatory for every item):** first **confirm** the finding (a test that fails on current code,
or a documented code trace); only then **fix it minimally and fail-closed**; keep each fix the smallest
correct change. If a finding does not reproduce, record why and skip it — no invented fixes. Security
correctness is never simplified away; "minimal" applies to the *fix*, not to the *validation*.

## User Scenarios & Testing *(mandatory)*

### User Story 1 — Certificate validation fails closed (Priority: P1) 🎯

As a server/client operator, I want certificate validation to reject certificates that omit required
constraints or whose signature is never verified, so an attacker cannot present a crafted/forged
certificate that passes by exploiting an absent extension or a trust shortcut.

**Why this priority**: Always reachable, pre-authentication; the highest-impact, broadest surface.

**Independent Test**: Craft certs/chains that (a) omit KeyUsage/EKU/BasicConstraints, (b) use a
non-self-signed leaf as its own trust anchor, (c) violate pathLenConstraint, (d) are revoked with a
mismatched-DN-string CRL — each is currently accepted and must be rejected after the fix; valid certs
still pass.

**Acceptance Scenarios**:

1. **Given** a CA certificate with no BasicConstraints (or CA:FALSE), **When** used as a chain issuer,
   **Then** the chain is rejected (was: accepted).
2. **Given** a leaf whose KeyUsage/EKU is required by policy but absent, **When** validated, **Then** it
   is rejected (was: accepted by fail-open).
3. **Given** a chain that exceeds an issuer's pathLenConstraint, **When** validated, **Then** it is
   rejected.
4. **Given** the "trust unknown certs" path and a **non-self-signed** leaf, **When** validated, **Then**
   its signature is actually verified (a forged/unsigned leaf is rejected); the misleading code comment
   is corrected.
5. **Given** a revoked certificate and its CRL (with DN/serial encodings that differ as bytes/strings),
   **When** validated in the secure configuration, **Then** it is rejected (revocation is not silently
   skipped); the secure/strict revocation posture is the documented default or a clearly-available,
   documented option.

---

### User Story 2 — OAuth2/JWT issued-token trust is pinned and explicit (Priority: P2)

As an operator enabling issued-token (JWT) authentication, I want the JWT signer pinned to a configured
issuer and the issuer/audience required explicitly, so that neither an unrelated trusted certificate nor
a missing config can mint accepted identity tokens.

**Why this priority**: Auth-bypass class, but gated behind enabling OAuth2 issued tokens.

**Independent Test**: A JWT signed by a trusted *client* (non-issuer) cert is rejected; a server with
issued-token auth enabled but `oauth2_issuer`/`oauth2_audience` unset refuses to validate (fail closed)
rather than accepting the hardcoded defaults.

**Acceptance Scenarios**:

1. **Given** a JWT validly signed by a cert in the channel trust store that is **not** the configured
   OAuth2 issuer, **When** an identity token is presented, **Then** it is rejected (was: accepted —
   confused deputy).
2. **Given** issued-token auth enabled with no issuer/audience configured, **When** a token is
   validated, **Then** validation fails closed (was: accepted using hardcoded `"opcua-issuer"`/
   `"opcua-server"`).

---

### User Story 3 — PubSub message security (Priority: P3)

As an operator using PubSub SignAndEncrypt, I want a unique per-message IV and replay protection, so an
eavesdropper cannot exploit IV reuse and a captured message cannot be replayed.

**Why this priority**: Real confidentiality/replay defects, but gated on PubSub.

**Independent Test**: Encrypt two messages under one key and confirm distinct IVs (was: identical);
replay a captured valid message and confirm the subscriber rejects it (was: accepted).

**Acceptance Scenarios**:

1. **Given** two SignAndEncrypt messages under the same key epoch, **When** encrypted, **Then** their IVs
   differ (per-message IV).
2. **Given** a previously-accepted message, **When** replayed, **Then** the subscriber rejects it on
   sequence/freshness.
3. *(Conditional)* **Given** the SignAndEncrypt construction, **When** evaluated, **Then** the
   sign/encrypt ordering is corrected only if it is a real exposure and the fix is contained; otherwise
   documented.

---

### User Story 4 — Safety SPDU robustness (Priority: P4)

As an operator of the OPC UA Safety layer, I want SPDU sequence validation to tolerate reordering within
a bounded window and handle first-packet/wraparound, so a single lost/reordered SPDU does not
permanently disable the safety channel, and stale/future SPDUs are bounded.

**Why this priority**: Availability + freshness on the opt-in Safety subsystem.

**Independent Test**: Reorder/drop one SPDU and confirm subsequent valid SPDUs still validate (was:
permanent desync); a replay outside the window and a future-dated timestamp are rejected.

**Acceptance Scenarios**:

1. **Given** an out-of-order or single dropped SPDU, **When** the next valid SPDU arrives, **Then** it
   validates (bounded window), instead of permanent SequenceMismatch.
2. **Given** the very first SPDU and a sequence wraparound, **When** validated, **Then** both are handled
   correctly (no silent wrap-accept).
3. **Given** a future-dated SPDU timestamp, **When** the timeout is checked, **Then** it is bounded
   (not treated as zero-delay-fresh).
4. **Documentation only**: the unkeyed CRC-32C is the OPC UA Safety "black-channel" model (corruption
   detection; authentication is the secure channel's job) — a doc comment states this; it is per-spec,
   not changed.

---

### User Story 5 — Decoder allocation + audit completeness (Priority: P5)

As an operator, I want decoding not to eagerly allocate on a claimed length and successful security
events to be audited, so a small crafted message can't force a large allocation and security audits are
complete.

**Why this priority**: Lower impact (allocation is already capped; audit is completeness).

**Independent Test**: A small message claiming a max-length array does not allocate proportionally before
elements are read; a successful ActivateSession/CreateSession emits an audit event.

**Acceptance Scenarios**:

1. **Given** a small message claiming an array length near the cap, **When** decoded, **Then** memory is
   not eagerly reserved for the full claimed length (reserved incrementally / bounded chunk).
2. **Given** a successful ActivateSession (and CreateSession), **When** it completes, **Then** the
   corresponding success audit event is emitted (was: only failures audited).

---

### Edge Cases

- A finding that does not reproduce on verification → documented as a non-bug, no fix.
- A fix that changes a default (revocation strictness, requiring OAuth2 issuer config) → called out as a
  deliberate security-hardening behavior change and documented; unrelated configs unaffected.
- Valid certs/tokens/messages/SPDUs continue to pass after each fix (no false-reject regressions).
- All fixes hold under crafted/oversized/malformed input without panic.

## Requirements *(mandatory)*

- **FR-001**: Certificate chain validation MUST fail closed when a required constraint is absent — a CA
  used as an issuer MUST have BasicConstraints CA:TRUE; KeyUsage/EKU required by policy MUST be present;
  pathLenConstraint MUST be enforced. Every accepted certificate's signature MUST be verified (the
  trust-unknown-cert / single-element-chain path MUST NOT skip signature verification); the misleading
  comment MUST be corrected.
- **FR-002**: Certificate revocation MUST fail closed in the documented-secure configuration (a missing
  CRL for a CA in scope is a rejection, not a silent pass), and CRL-issuer / serial matching MUST be
  robust to encoding differences (not a lossy string/byte compare). Any change to the revocation default
  MUST be documented as a deliberate behavior change.
- **FR-003**: OAuth2/JWT identity-token validation MUST pin the accepted signer to a configured OAuth2
  issuer (not "any cert in the channel trust store"), and MUST require issuer/audience to be explicitly
  configured when issued-token auth is enabled — failing closed if unset (no hardcoded-default
  acceptance).
- **FR-004**: PubSub SignAndEncrypt MUST use a unique per-message initialization vector, and the
  subscriber MUST reject replayed/stale messages via sequence/freshness. The sign/encrypt ordering MUST
  be corrected only if verification shows a real exposure with a contained fix; otherwise documented.
- **FR-005**: Safety SPDU sequence validation MUST tolerate bounded reordering, handle first-packet and
  wraparound (no silent wrap-accept), and bound future-dated timestamps in the timeout check. The unkeyed
  CRC MUST be documented as the intended black-channel model (not changed).
- **FR-006**: Binary array decoding MUST NOT eagerly reserve memory proportional to a claimed length
  before elements are read (bounded/incremental reservation), staying within existing length caps.
- **FR-007**: Successful ActivateSession and CreateSession MUST emit their audit events (failure auditing
  already exists).
- **FR-008**: Every finding MUST be confirmed before it is fixed (a failing-then-passing test or a
  documented code trace); a non-reproducing finding MUST be documented and skipped, not patched.
- **FR-009**: No new runtime dependency; each fix is the smallest correct, fail-closed change; the
  workspace builds and lints clean (`clippy --all-targets --all-features` + no-default-features /
  json-off legs under `-D warnings`); existing suites pass.

### Key Entities *(include if feature involves data)*

- **Finding**: a reviewed defect → {confirmed?, severity, fix or documented-skip, test}.
- **Trust anchor / chain / CRL**: the certificate-validation inputs whose handling must fail closed.
- **OAuth2 issuer config**: the pinned signer + required issuer/audience.
- **Per-message IV / sequence number**: PubSub message-security state.
- **SPDU sequence window**: bounded replay/reorder tolerance for Safety.

## Success Criteria *(mandatory)*

- **SC-001**: Each confirmed finding has a test that **fails on current code and passes after the fix**;
  non-reproducing findings are documented as such.
- **SC-002**: Crafted certs (absent extensions, non-self-signed anchor, pathlen violation, revoked) are
  rejected; valid certs still pass.
- **SC-003**: A JWT signed by a non-issuer trusted cert is rejected; unset issuer/audience fails closed.
- **SC-004**: PubSub IVs are per-message unique; replays are rejected.
- **SC-005**: A single reordered/dropped SPDU no longer permanently desyncs; stale/future SPDUs bounded.
- **SC-006**: Small messages can't force large eager allocation; successful session events are audited.
- **SC-007**: No new dependency; clippy clean across all feature legs; existing unit + integration suites
  pass; deliberate behavior-change defaults are documented.

## Assumptions

- The 2026-06-22 review findings are the input; cert-validation and ECC core were already reviewed (ECC
  clean). This is a focused remediation, not a re-audit.
- **Verification division** (established): codex implements the production fixes applying **ponytail**
  (minimal, fail-closed, no over-engineering, smallest diff); Claude authors + runs ALL tests
  independently — each finding gets a fail-before/pass-after test anchored to OPC UA Part 2/4/6/14 + the
  review (crafted cert/chain/CRL, forged JWT, static-IV/replayed PubSub message, reordered/wrapped SPDU,
  oversized-array decode), NOT codex loopback.
- **Out of scope / documented (not fixed)**: the unkeyed-CRC black-channel design (doc only);
  FindServersOnNetwork / mDNS; anything requiring a new dependency.
