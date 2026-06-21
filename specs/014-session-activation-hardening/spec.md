# Feature Specification: Session-Activation Hardening (OPC UA Part 4 §5.6)

**Feature Branch**: `014-session-activation-hardening`
**Created**: 2026-06-21
**Status**: Draft (scope recalibrated after Phase-0 research — see `research.md`)
**Input**: User description: harden server-side CreateSession/ActivateSession against confused-deputy
and token/channel-binding attacks — the session-activation hardening TODOs deferred from feature 013
(Tier 1 #2 in `specs/conformance-gap-backlog.md`).

## Context & scope recalibration *(mandatory)*

The original intent was to close several §5.6 gaps. A read-only investigation of the server session
code (recorded in `research.md`) found that **most of the §5.6 hardening is already implemented**:

- **Session↔channel binding** is enforced on *every* session-scoped request, for all security modes
  (`SessionController::validate_request` → `Session::validate_secure_channel_id`). An activated session
  cannot be driven from a different secure channel.
- **Client signature** is verified over (server cert ‖ session nonce) with the session's client
  certificate; a **fresh server nonce** is issued per ActivateSession and a stale-nonce activation is
  rejected (`Bad_NonceInvalid`) — already regression-tested.
- **User identity tokens** (username / x509 / issued) are bound to the server nonce
  (decrypt/verify-over-nonce), preventing replay.
- **Endpoint-URL host** is already validated against the advertised endpoints and the server
  certificate SubjectAltName (`validate_endpoint_hostname`); the `manager.rs:213` TODO comment is
  **stale**.

The **one genuine remaining gap** is the `manager.rs:593` TODO: at ActivateSession the session's
client certificate (presented at CreateSession) is **not** checked against the certificate that
secured the channel (`SecureChannel::remote_cert()`). This feature closes that gap and adds the
regression tests that lock in the already-correct (but currently under-tested) channel-binding,
nonce-replay, and endpoint-host behavior, so none of it can silently regress. The
activated-secured-session reconnection affordance (re-activating on a new channel with a valid
signature + token) is **kept** by decision.

## User Scenarios & Testing *(mandatory)*

### User Story 1 — Client certificate bound to the secure channel at ActivateSession (Priority: P1) 🎯 MVP

As a server operator, I want the application certificate a client presented at CreateSession to match
the certificate that actually secured its channel, so a client cannot create a session under one
application identity while its channel was established under another (identity confusion / binding
bypass).

**Why this priority**: This is the single concrete §5.6 binding gap (the `manager.rs:593` TODO). The
clientSignature is checked with the session's stored cert, but nothing ties the CreateSession
`client_certificate` to the channel's peer certificate.

**Independent Test**: A session whose CreateSession `client_certificate` matches the channel's peer
certificate activates normally; a session whose CreateSession certificate differs from the channel's
peer certificate is rejected at ActivateSession with the documented status code.

**Acceptance Scenarios**:

1. **Given** a session created on a secured channel where the CreateSession `client_certificate`
   equals the channel's peer certificate, **When** ActivateSession is processed, **Then** it succeeds
   as today.
2. **Given** a session whose CreateSession `client_certificate` differs from the channel's peer
   certificate, **When** ActivateSession is processed, **Then** it is rejected
   (`Bad_SecurityChecksFailed`).
3. **Given** the `None` security policy (no channel certificate), **When** ActivateSession is
   processed, **Then** behavior is unchanged (no cert-binding check applies).

---

### User Story 2 — Conformance lock-in tests for existing §5.6 behavior (Priority: P2)

As a maintainer, I want the already-correct session-binding behaviors covered by explicit tests, so a
future refactor cannot silently reintroduce a hijack/replay/endpoint hole.

**Why this priority**: The behaviors exist but are under-tested (no end-to-end cross-channel
service-request test, no endpoint-host-mismatch test at CreateSession). Locking them in is cheap and
directly serves correctness.

**Independent Test**: Independently-authored tests assert that an activated **secured** session is
rejected when a *service request* arrives on a different channel; that a CreateSession with a
non-matching endpoint-URL host is rejected; and that malformed CreateSession/ActivateSession fields are
rejected without panic.

**Acceptance Scenarios**:

1. **Given** an activated secured session on channel A, **When** a Browse/Read (any session service)
   for it arrives on channel B, **Then** it is rejected (`Bad_SecureChannelIdInvalid`).
2. **Given** a CreateSession whose `endpointUrl` host is not advertised and not in the server cert
   SAN, **When** processed, **Then** it is rejected (`Bad_CertificateHostNameInvalid` /
   `Bad_TcpEndpointUrlInvalid`).
3. **Given** malformed/oversized/truncated CreateSession or ActivateSession fields, **When** processed,
   **Then** they are rejected with a status code and **never panic**.

### Edge Cases

- `None` security policy: no channel certificate — the cert-binding check is skipped; existing
  behavior preserved.
- Re-ActivateSession of an activated secured session on a new channel (reconnection) continues to work
  (kept by decision), and the cert-binding check still applies to the new channel's certificate.
- Malformed/absent client certificate or signature at ActivateSession → rejected, no panic.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: At ActivateSession, when the security policy is not `None`, the server MUST verify that
  the session's client application certificate (bound at CreateSession) matches the certificate that
  secured the activating channel (`SecureChannel::remote_cert()`), by certificate equality
  (DER/thumbprint); a mismatch MUST be rejected with `Bad_SecurityChecksFailed`. (Closes
  `manager.rs:593`.)
- **FR-002**: The `None` security-policy path MUST be unchanged (no channel certificate, no
  cert-binding check), and conformant clients MUST continue to create/activate/use sessions unchanged.
- **FR-003**: The cert-binding check (and surrounding activation validation) MUST be **panic-free** on
  attacker-supplied/missing certificate fields.
- **FR-004**: The stale `manager.rs:213` TODO comment MUST be removed (the endpoint-host check it
  references already exists), leaving the code's intent accurate.
- **FR-005** (lock-in): The already-implemented behaviors MUST be covered by regression tests:
  (a) an activated secured session rejected on a different channel for a service request; (b) a
  CreateSession endpoint-URL host mismatch rejected; (c) malformed activation fields rejected without
  panic.

### Key Entities *(include if feature involves data)*

- **Session**: holds the owning `secure_channel_id`, the client certificate bound at CreateSession,
  the current server nonce, and activation state.
- **Secure channel**: the secured channel; exposes its peer certificate (`remote_cert()`) used for the
  new binding check.

## Success Criteria *(mandatory)*

- **SC-001**: A session whose CreateSession certificate does not match its channel's peer certificate
  is rejected at ActivateSession; a matching one succeeds — verified by tests.
- **SC-002**: An activated secured session cannot be used (any session service) from a different
  secure channel — verified by an end-to-end test.
- **SC-003**: A CreateSession with a non-matching endpoint-URL host is rejected; malformed
  CreateSession/ActivateSession fields are rejected without panic.
- **SC-004**: Conformant clients (RSA, ECC, None) connect, activate, and use sessions unchanged; the
  existing unit + integration suites pass and `None` is byte-identical.
- **SC-005**: `cargo clippy --all-targets --all-features` is clean; no new dependency.

## Assumptions

- **Already delivered (verified, see `research.md`)**: session↔channel binding on every request,
  client-signature/nonce verification, per-activation nonce freshness + stale-nonce rejection, user
  identity token nonce binding, and endpoint-URL host validation. This feature does **not**
  reimplement them; it adds the one missing cert-binding check and regression tests.
- **Reconnection kept**: an activated secured session may re-activate on a new channel (still requires
  a valid client signature + user token) — confirmed by the user; strict same-channel binding is NOT
  adopted.
- **Server-side only**; reuse existing crypto and the feature-013 cert engine where needed.
- **Out of scope / deferred**: strict same-channel re-activation; typed `AuditCertificate*`/audit-event
  work; client-side changes; anything covered by feature 013.
- **Verification division**: codex implements the cert-binding check; Claude authors and runs all
  tests independently (matching/mismatching channel cert at ActivateSession, cross-channel service
  request, endpoint-host mismatch, malformed fields) verifying the exact Part 4 §5.6 status codes.
