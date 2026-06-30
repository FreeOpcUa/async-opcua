# Feature Specification: X.509 User Token Validation

**Feature Branch**: `042-x509-user-token-validation`  
**Created**: 2026-06-29  
**Status**: Draft  
**Input**: User description: "Validate X.509 user identity token certificates before accepting ActivateSession, including trust-chain, usage, revocation, status-code, and audit-event behavior required by OPC UA Part 4"

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Reject Untrusted User Certificates (Priority: P1)

An OPC UA server operator can require X.509 user identity tokens without accepting a user certificate solely because its thumbprint is configured. The presented user certificate must pass certificate validation before the session is authenticated as that user.

**Why this priority**: This is the primary fail-closed security requirement. A configured thumbprint is an identity mapping, not a replacement for certificate trust, validity, revocation, and usage checks.

**Independent Test**: Configure an endpoint that supports X.509 user identity tokens and a known user thumbprint, then attempt activation with a certificate that matches the configured identity but fails certificate validation. The session activation must fail and must not assign the X.509 user identity.

**Acceptance Scenarios**:

1. **Given** an endpoint supports X.509 user identity tokens and the user's thumbprint is configured, **When** the user certificate is not trusted by the server trust list, **Then** ActivateSession fails with a certificate-validation failure and the session remains unauthenticated as that user.
2. **Given** an endpoint supports X.509 user identity tokens and the user's thumbprint is configured, **When** the certificate is expired, revoked, incomplete, or not allowed for the requested operation, **Then** ActivateSession fails before the user identity is accepted.
3. **Given** the same session remains open after a rejected activation attempt, **When** the client retries with an allowed identity, **Then** the rejected X.509 identity does not persist from the failed attempt.

---

### User Story 2 - Preserve Valid X.509 Authentication (Priority: P2)

A client with a trusted, valid X.509 user certificate and a valid user-token signature can still activate a session successfully, and signature failures remain distinguishable from certificate-validation failures.

**Why this priority**: The security fix must not break existing conformant X.509 user authentication or blur distinct OPC UA error classes that clients use for recovery.

**Independent Test**: Activate a session with a trusted and configured X.509 user certificate, then repeat with the same certificate and an invalid user-token signature. The first attempt must succeed; the second must fail with the user-signature error instead of a certificate-validation error.

**Acceptance Scenarios**:

1. **Given** a trusted, valid X.509 user certificate whose thumbprint is configured for a supported endpoint, **When** the client supplies the required user-token signature, **Then** ActivateSession succeeds and the authenticated user identity is the certificate identity.
2. **Given** a trusted, valid X.509 user certificate, **When** the user-token signature is missing or invalid, **Then** ActivateSession fails with the OPC UA user-signature failure and not with a trust-list failure.
3. **Given** an endpoint does not support X.509 user identity tokens, **When** a client supplies an X.509 identity token, **Then** ActivateSession rejects the identity without attempting to authenticate it as a configured user.

---

### User Story 3 - Audit Certificate Validation Outcomes (Priority: P3)

An operator who subscribes to audit events can see certificate-validation failures and suppressed certificate-validation findings for X.509 user identity tokens, using the matching AuditCertificate event type.

**Why this priority**: OPC UA Part 4 requires suppressed certificate-validation errors to be reported via auditing. Without this, operators cannot distinguish accepted-but-suppressed user certificate findings from ordinary successful authentication.

**Independent Test**: Subscribe to audit events, trigger an X.509 user-token validation failure and a suppressed validation finding, and verify the emitted AuditCertificate event type, status, and certificate payload.

**Acceptance Scenarios**:

1. **Given** audit event monitoring is enabled, **When** X.509 user identity certificate validation fails, **Then** the server emits the matching AuditCertificate event subtype with the certificate and failure status.
2. **Given** a non-critical certificate-validation error is explicitly suppressed by server policy, **When** ActivateSession accepts the X.509 user identity despite the suppressed finding, **Then** the server still emits the matching AuditCertificate event subtype for that suppressed finding.
3. **Given** multiple suppressed findings occur during one user certificate validation, **When** the session activation succeeds, **Then** every suppressed certificate finding is represented by an audit event.

### Edge Cases

- Certificate bytes cannot be parsed as an X.509 certificate.
- Certificate signature proof is missing or invalid even though certificate validation would otherwise pass.
- The certificate is valid for application use but not for the user identity operation.
- The configured user thumbprint matches a certificate that is now expired or revoked.
- The certificate chain is incomplete or issued by an untrusted issuer.
- A suppressed certificate finding occurs on a successful activation and must not be mistaken for a failed activation.
- Audit subscribers are absent; validation behavior must remain identical.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The server MUST validate an X.509 user identity token certificate before accepting the user identity during ActivateSession.
- **FR-002**: The server MUST fail closed when the X.509 user certificate fails trust-chain, validity-period, revocation, security-policy, or usage checks.
- **FR-003**: A configured X.509 user thumbprint MUST NOT by itself make an otherwise invalid or untrusted certificate acceptable.
- **FR-004**: The server MUST preserve successful activation for X.509 user certificates that are trusted, valid, allowed for user identity use, configured for the endpoint, and accompanied by the required valid signature.
- **FR-005**: The server MUST preserve distinct failure outcomes for malformed certificate data, invalid or missing user-token signatures, unsupported X.509 identity tokens, rejected identities, and certificate-validation failures.
- **FR-006**: The server MUST NOT assign or retain the rejected X.509 user identity after a failed ActivateSession attempt.
- **FR-007**: The server MUST emit the matching AuditCertificate event subtype when X.509 user certificate validation fails and audit event monitoring is available.
- **FR-008**: The server MUST emit the matching AuditCertificate event subtype for every explicitly suppressed X.509 user certificate validation finding, even when ActivateSession ultimately succeeds.
- **FR-009**: Audit events for X.509 user certificate validation MUST include enough information for operators to identify the certificate, the validation status, and the session/authentication context without logging secrets.
- **FR-010**: The validation path MUST be bounded and must reject malformed or hostile certificate input without panics.

### Key Entities *(include if feature involves data)*

- **X.509 User Identity Token**: The certificate-based user identity presented during ActivateSession, including certificate bytes, policy id, and associated user-token signature.
- **User Certificate Validation Result**: The outcome of validating the presented user certificate, including success, hard failure, or suppressed finding.
- **Configured User Identity Mapping**: The server-side mapping that allows a validated certificate thumbprint to authenticate as a user for an endpoint.
- **Certificate Audit Event**: The operator-visible event that records failed or suppressed certificate-validation findings.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: 100% of X.509 user identity activation attempts with untrusted, expired, revoked, incomplete, or wrong-usage certificates are rejected before user identity assignment.
- **SC-002**: 100% of existing valid X.509 user identity activation scenarios covered by the test suite continue to succeed.
- **SC-003**: 100% of invalid user-token signature scenarios covered by the test suite continue to report a user-signature failure rather than a certificate trust failure.
- **SC-004**: 100% of certificate-validation hard failures and suppressed findings exercised by tests emit the expected AuditCertificate event subtype when audit monitoring is active.
- **SC-005**: Malformed X.509 user certificate input exercised by tests is rejected without panic or process abort.

## Assumptions

- Existing application-instance certificate validation rules are the baseline for chain, validity, revocation, security-policy, and trust-list handling.
- X.509 user identity certificates use certificate usage rules appropriate for user authentication rather than silently inheriting server-application usage.
- Existing endpoint user-token policy behavior remains authoritative for deciding whether X.509 user identity tokens are supported.
- This feature does not add a new user identity provider or new trust-store format; it applies validation to the existing X.509 user identity flow.
- This feature does not change anonymous, username/password, or issued-token authentication except where tests prove they remain unaffected.
