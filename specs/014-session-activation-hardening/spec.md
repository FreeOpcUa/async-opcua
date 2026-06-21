# Feature Specification: Session-Activation Hardening (OPC UA Part 4 §5.6)

**Feature Branch**: `014-session-activation-hardening`
**Created**: 2026-06-21
**Status**: Draft
**Input**: User description: harden server-side CreateSession/ActivateSession against confused-deputy
and token/channel-binding attacks — the session-activation hardening TODOs deferred from feature 013
(Tier 1 #2 in `specs/conformance-gap-backlog.md`).

## User Scenarios & Testing *(mandatory)*

A malicious or buggy OPC UA client interacts with the server's session lifecycle (CreateSession →
ActivateSession → use). Part 4 §5.6 requires the server to bind a session to the identity and the
secure channel that created it, and to confirm the client reached the endpoint it intended. Today the
server verifies the client's signature over the session nonce and already refuses cross-channel
transfer of an unsecured (`None`) session, but two hardening steps are still marked `TODO` in
`async-opcua-server/src/session/manager.rs`: (1) the **endpoint URL** the client supplies at
CreateSession is not checked for consistency with the server's own endpoints / application
certificate, and (2) at ActivateSession the **client certificate and user identity token are not
fully bound to the secure channel**. This feature closes those gaps so a session cannot be activated
or reused on a channel it does not belong to, a captured identity token cannot be replayed, and a
client cannot be steered to a spoofed endpoint — each rejection mapped to its exact OPC UA status code.

### User Story 1 — Client certificate & session bound to the secure channel (Priority: P1) 🎯 MVP

As a server operator, I want a session to be usable only on the secure channel that created and
activated it, and the activating client to be the same one that created the session, so a stolen or
guessed session/authentication token cannot be replayed on a different channel (session hijack).

**Why this priority**: This is the core of §5.6's channel-binding requirement and the highest-value
gap — without it, an attacker who obtains a session's identifiers could attempt to drive that session
from another secure channel. It extends the existing `None`-only cross-channel protection to all
security modes and binds the client certificate presented at CreateSession.

**Independent Test**: Create a session on channel A; attempt ActivateSession (and subsequent service
calls) for that session from channel B → rejected. Activate on channel A with a client certificate
that differs from the one presented at CreateSession → rejected. Normal same-channel activation
succeeds.

**Acceptance Scenarios**:

1. **Given** a session created on secure channel A, **When** an ActivateSession (or any session
   service) for it arrives on a different secure channel B, **Then** it is rejected
   (`Bad_SecurityChecksFailed` / `Bad_SessionNotActivated` as appropriate) for all security modes,
   not only `None`.
2. **Given** a session created with client certificate C1, **When** ActivateSession presents a
   different client certificate, **Then** activation is rejected.
3. **Given** a session created and activated on the same channel with the same client certificate,
   **When** it is used, **Then** it works unchanged.

---

### User Story 2 — User identity token bound to the current server nonce (replay protection) (Priority: P1)

As a server operator, I want every ActivateSession to require proof of identity tied to a fresh
server-issued nonce, so a captured or replayed user identity token (signed/encrypted secret) cannot
be reused to activate or re-authenticate a session.

**Why this priority**: Token replay is a direct authentication bypass. The server must issue a new
nonce per ActivateSession and require the client's token signature/encryption to be over that current
nonce; a token bound to a stale nonce must be rejected.

**Independent Test**: Activate with a user identity token whose signature/encryption is over the
current server nonce → succeeds. Replay the same token (bound to a previous nonce) on a fresh
ActivateSession → rejected. A token signed over the wrong data → rejected.

**Acceptance Scenarios**:

1. **Given** the server issued nonce N for an ActivateSession, **When** the client's user identity
   token proof is computed over N, **Then** activation succeeds.
2. **Given** a user identity token whose proof is over a stale/previous nonce, **When** ActivateSession
   is attempted, **Then** it is rejected (`Bad_IdentityTokenRejected` / `Bad_UserAccessDenied` as
   appropriate).
3. **Given** the server issues a new nonce on each ActivateSession, **When** two activations occur,
   **Then** the nonces differ and a proof for one is not valid for the other.

---

### User Story 3 — Endpoint-URL consistency at CreateSession (Priority: P2)

As a server operator, I want the endpoint URL a client used at CreateSession to be checked against the
server's actual endpoints / application certificate, so a client that was steered to a spoofed
endpoint is detected (confused-deputy), per §5.6.2.

**Why this priority**: Real but lower frequency than channel/token binding; completes the §5.6.2
endpointUrl handling already stubbed (`validate_endpoint_hostname` exists; the cert-hostname check is
the `TODO` at `manager.rs:213`).

**Independent Test**: CreateSession with an endpoint URL whose host does not match the server's
certificate/endpoint host → rejected/flagged with the documented status; a matching endpoint URL →
accepted.

**Acceptance Scenarios**:

1. **Given** a CreateSession whose `endpointUrl` host does not correspond to any of the server's
   endpoints / its application-certificate host names, **When** processed, **Then** it is rejected with
   the documented status (`Bad_TcpEndpointUrlInvalid` / `Bad_SecurityChecksFailed`).
2. **Given** a CreateSession with a matching, known endpoint URL, **When** processed, **Then** it is
   accepted as today.

---

### User Story 4 — Configuration, rollout & backward compatibility (Priority: P3)

As an operator of an existing deployment, I want the hardening to default to safe behavior without
breaking conformant clients, and to be configurable where strictness could affect interop.

**Why this priority**: Adoption/safety. Conformant clients (correct channel, fresh-nonce proofs,
valid endpoint URLs) must keep working; the `None` security policy path stays correct.

**Independent Test**: A standard client (correct channel, fresh-nonce token, valid endpoint) connects
and activates unchanged across all security policies; the existing loopback + ECC suites stay green.

**Acceptance Scenarios**:

1. **Given** a conformant client and an upgraded server, **When** it connects/activates/uses a session,
   **Then** it succeeds exactly as before.
2. **Given** any strictness toggle the feature introduces, **When** an operator changes it, **Then**
   enforcement matches the configuration and the safe default is documented.

### Edge Cases

- Malformed / missing CreateSession or ActivateSession fields (absent client cert, empty/oversized
  nonce, truncated signature, malformed identity token) MUST be rejected with a protocol error and
  **never panic** (attacker-controlled, fuzzable input).
- Re-ActivateSession on the same channel (legitimate identity change / nonce refresh) MUST continue to
  work.
- A session that is created but never activated, then targeted from another channel, MUST NOT be
  usable from that other channel.
- `None` security policy: no certificate/signature is present; channel binding still applies and the
  existing protection MUST NOT regress.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The server MUST bind each session to the secure channel on which it was created, and MUST
  reject ActivateSession (and session-scoped service use) arriving on a different secure channel, for
  **all** security modes (extending the existing `None`-only protection) → `Bad_SecurityChecksFailed` /
  `Bad_SessionNotActivated`.
- **FR-002**: At ActivateSession the server MUST confirm the activating client is the same one that
  created the session — the client application certificate presented/used at ActivateSession MUST match
  the one bound at CreateSession; a mismatch is rejected.
- **FR-003**: The server MUST verify the `clientSignature` over (server application certificate ‖
  server nonce) using the session's client certificate (preserve existing behavior; ensure it is over
  the **current** nonce).
- **FR-004**: The server MUST issue a **fresh** server nonce on each ActivateSession and MUST require
  the user identity token's signature/encryption proof to be bound to that current nonce; a proof over
  a stale/previous nonce MUST be rejected (`Bad_IdentityTokenRejected` / `Bad_UserAccessDenied`).
- **FR-005**: The server MUST validate the CreateSession `endpointUrl` for consistency with the
  server's endpoints / application-certificate host names; an inconsistent URL is rejected with the
  documented status (`Bad_TcpEndpointUrlInvalid` / `Bad_SecurityChecksFailed`). (Builds on the existing
  `validate_endpoint_hostname`.)
- **FR-006**: All CreateSession/ActivateSession validation MUST be **fail-closed** and **panic-free** on
  attacker-supplied fields (missing/oversized/truncated nonces, signatures, certificates, identity
  tokens), rejecting malformed input with a status code.
- **FR-007**: Conformant clients MUST continue to connect, activate, and use sessions unchanged across
  all security policies; the `None` path MUST remain correct and the existing cross-channel protection
  MUST NOT regress.

### Key Entities *(include if feature involves data)*

- **Session**: server-side session with its owning secure-channel id, the client certificate bound at
  CreateSession, the current/last server nonce, and activation state.
- **Secure channel**: the transport-level secured channel; a session is bound to exactly one.
- **Server nonce**: a fresh random value issued per CreateSession/ActivateSession, used to bind the
  client signature and the user-identity-token proof and to prevent replay.
- **Client (application) certificate**: presented at CreateSession; the activating client must match it.
- **User identity token**: the activating user's credential (anonymous / username / x509 / issued),
  whose signature/encryption MUST be bound to the current server nonce.

## Success Criteria *(mandatory)*

- **SC-001**: A session created on one secure channel cannot be activated or used from a different
  secure channel, for every security mode — verified by crafted cross-channel ActivateSession/use tests.
- **SC-002**: A user identity token (or client signature) bound to a stale/previous server nonce is
  rejected on ActivateSession; a token bound to the current nonce succeeds — verified by replay tests.
- **SC-003**: A CreateSession with an endpoint URL inconsistent with the server's endpoints/certificate
  is rejected with the documented status; a matching URL is accepted.
- **SC-004**: Malformed CreateSession/ActivateSession fields are rejected without any panic (negative +
  fuzz tests over the activation decode/verify path).
- **SC-005**: Conformant clients connect, activate, and use sessions unchanged across all policies
  (RSA, ECC, None); the existing unit + integration suites pass and `None` is byte-identical.
- **SC-006**: `cargo clippy --all-targets --all-features` is clean; no new C-toolchain dependency.

## Assumptions

- **Builds on existing mechanisms**: `verify_client_signature` over the session nonce and
  `is_cross_channel_transfer_forbidden` (the recent `None`-session fix) already exist; this feature
  extends channel binding to all modes, adds the client-cert and endpoint-URL checks, and confirms
  per-ActivateSession nonce freshness. The exact delta vs current code is pinned during planning.
- **Server-side only**: scope is the server's CreateSession/ActivateSession validation; client-side
  behavior is unchanged. The certificate-validation engine from feature 013 is reused where the client
  certificate must be validated.
- **Default = strict-but-conformant**: the hardening is on by default (it is the conformant behavior and
  does not break correct clients); any toggle that could affect interop has a safe, documented default.
- **Out of scope / deferred**: anything already delivered by feature 013 (cert chain/usage/revocation);
  the broader typed `AuditCertificate*` / audit-event work; client-side changes; GDS.
- **Verification division**: coding goes to codex (implementation only); Claude authors and runs all
  tests independently — crafted CreateSession/ActivateSession fixtures + loopback scenarios (valid
  activation, cross-channel use, wrong/replayed nonce, signature/token over the wrong data, mismatched
  endpoint URL, malformed fields) verifying the exact Part 4 §5.6 status-code mapping, plus negative/fuzz
  tests.
