# Feature Specification: Audit Findings Remediation

**Feature Branch**: `[043-fix-audit-findings]`
**Created**: 2026-06-29
**Status**: Draft
**Input**: User description: "Fix all findings surfaced by the parallel security audit, Codex Security bounded triage, OPC UA spec-to-code compliance review, code review, and negative-path testing backlog."

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Enforce Identity And Session Trust Boundaries (Priority: P1)

As an OPC UA server operator, I need identity-token and session-activation failures to be rejected at the earliest correct trust boundary so that credentials, user mappings, certificate audit records, and session state cannot be affected by a malformed or cross-channel activation attempt.

**Why this priority**: These findings protect authentication, credential confidentiality, and session integrity. They have the highest security impact because a wrong decision can expose reusable secrets, validate the wrong user, or perform expensive identity work before a secure-channel precondition is satisfied.

**Independent Test**: This can be tested by attempting session activation with invalid channel binding, plaintext protected credentials, legacy-only X.509 proof on enhanced policy, missing X.509 proof, and failed-then-retried identity tokens. Each scenario must fail with the expected public status and leave identity/session state unchanged.

**Acceptance Scenarios**:

1. **Given** a session created on one secure channel, **When** activation is attempted over a different channel with any user token, **Then** the attempt fails with the secure-channel mismatch status before user authentication or certificate audit side effects occur.
2. **Given** a protected endpoint that requires user-token secrecy, **When** username/password or issued-token credentials are sent without the required token protection, **Then** the server rejects the token and does not authenticate the user.
3. **Given** an endpoint whose policy requires enhanced channel-bound user-token signatures, **When** an X.509 user token supplies only the legacy signature form, **Then** activation fails with the user-token signature status.
4. **Given** a failed X.509 user-token activation, **When** a valid identity is activated afterward on the same session, **Then** only the successful identity is assigned and no rejected identity state remains.

---

### User Story 2 - Align Certificate And GDS Management Outcomes (Priority: P2)

As a security administrator, I need certificate validation and certificate-management methods to follow OPC UA conformance rules so that trust decisions, audit records, role restrictions, and certificate replacement outcomes are predictable and recoverable.

**Why this priority**: Certificate-chain policy checks and GDS operations control long-lived trust material. Incorrect outcomes can silently broaden trust, lose auditability, or leave credentials half-rotated.

**Independent Test**: This can be tested by exercising certificate chains with rejected-store hits, weak issuer or revocation signatures, constrained CA paths, missing trust-store directories, malformed GDS inputs, non-administrator GDS calls, and credential write failures. Each test must prove the expected status, audit behavior, and preservation or rejection of trust material.

**Acceptance Scenarios**:

1. **Given** a certificate that is already rejected or violates the selected certificate policy, **When** it is presented for user identity validation, **Then** the result is certificate-specific, auditable, and does not unintentionally change existing application-certificate behavior.
2. **Given** a certificate chain with a disallowed issuer signature algorithm, disallowed revocation signature algorithm, or path-length violation, **When** the chain is validated under the selected certificate-chain policy, **Then** validation rejects the chain with the selected certificate status.
3. **Given** a non-SecurityAdmin user, **When** that user invokes certificate-management methods such as rejected-list retrieval, certificate update, signing request creation, or request completion, **Then** the operation is rejected before trust material or registry state changes.
4. **Given** a certificate replacement operation, **When** the new certificate or key material is malformed or persistence fails partway through, **Then** the existing valid credential set remains intact and the failure is visible.
5. **Given** an OpenSecureChannel certificate-validation failure, **When** auditing is enabled, **Then** certificate audit events use the OPC UA-specified event fields and source names.

---

### User Story 3 - Harden Protocol Negative Paths And Status Conformance (Priority: P3)

As a library integrator and conformance tester, I need malformed protocol inputs and unsupported service cases to fail deterministically with spec-aligned statuses so that clients, servers, and PubSub subscribers remain live and observable after invalid traffic.

**Why this priority**: These items reduce denial-of-service and interoperability risk across binary transport, service dispatch, PubSub, SKS key retrieval, XML import, SQLite-backed history, and encoding helpers.

**Independent Test**: This can be tested by sending malformed or boundary-case protocol inputs and verifying that each failure is bounded, status-specific, and leaves the affected session, channel, subscriber, or data store in a usable state.

**Acceptance Scenarios**:

1. **Given** a binary message chunk with an impossible declared size, oversized declared size, excessive chunk count, replayed sequence number, or unknown service id, **When** it is processed, **Then** the public failure status matches the relevant OPC UA rule and the channel or session remains usable when the rule requires it.
2. **Given** a PubSub UADP message with invalid or reserved flags, an overflowing field count, trailing secured payload bytes, malformed security nonce, or oversized secured payload, **When** a publisher or subscriber processes it, **Then** it fails without updating subscriber state or accepting truncated data.
3. **Given** an SKS request with a specific older StartingTokenId, **When** matching historical keys are available, **Then** the available historical key range is returned instead of an unnecessary not-found failure.
4. **Given** XML import, history storage, or encoding helper inputs that are malformed, oversized, or corrupt, **When** they are processed, **Then** the failure is explicit, bounded, and does not silently discard an error.

### Edge Cases

- Wrong-channel activation paired with an otherwise valid user token must still fail before any identity-specific work.
- User-token protection failures must not be masked as generic access denial when a more precise security or identity-token status is required.
- Certificate status improvements for user identity validation must not unintentionally alter existing application-certificate acceptance or rejection contracts unless explicitly covered by acceptance tests.
- Suppressed certificate-validation findings must still produce auditable records when the operation succeeds.
- Missing or corrupt PKI storage must fail closed and preserve auditability where certificate context is available.
- GDS certificate replacement must not leave a new certificate paired with an old key, or an old certificate paired with a new key.
- PubSub decode failures must not update subscriber target state before the full message is validated.
- Unknown or future service requests must not tear down reusable channels unless the relevant OPC UA rule requires termination.
- Local XML and history import paths must remain bounded even when inputs are not remote service requests.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The system MUST reject cross-channel session activation before user authentication, certificate validation, identity assignment, or certificate audit emission for that activation attempt.
- **FR-002**: The system MUST require the correct user-token protection for username/password and issued-token credentials whenever the selected endpoint or user-token policy requires protected credentials.
- **FR-003**: The system MUST support OPC UA channel-bound X.509 user-token signatures for policies that require enhanced secure-channel signatures, while preserving legacy signature behavior only where the selected policy permits it.
- **FR-004**: The system MUST preserve precise public failure statuses for missing, invalid, or malformed user-token proof so operators and clients can distinguish signature failures from certificate-validation failures and access-denial failures.
- **FR-005**: The system MUST ensure failed identity-token validation cannot assign, retain, or reuse rejected user identity, role, or claim state on later successful activations.
- **FR-006**: The system MUST map user identity certificate trust-list, key-length, signature, usage, validity, revocation, and chain failures to certificate-specific statuses and certificate audit events when certificate context is available.
- **FR-007**: The system MUST preserve existing application-certificate failure contracts unless an acceptance scenario explicitly declares and verifies an intentional conformance change.
- **FR-008**: The system MUST enforce the selected certificate-chain policy expectations, including disallowed weak issuer signatures, disallowed weak revocation signatures, and CA path-length constraints.
- **FR-009**: The system MUST restrict certificate-management operations to authorized security administrators and reject unauthorized attempts before state changes occur.
- **FR-010**: The system MUST reject malformed certificate-management inputs and preserve existing trust material if certificate or key replacement cannot complete successfully.
- **FR-011**: The system MUST emit OPC UA-conformant certificate and secure-channel audit event fields, source names, linked certificate-error context, and status details for covered certificate failures.
- **FR-012**: The system MUST handle malformed binary transport messages with bounded resource use and spec-aligned public status codes.
- **FR-013**: The system MUST reject invalid PubSub UADP flags, counts, secured payload shapes, security nonces, and trailing payload data before subscriber state changes.
- **FR-014**: The system MUST return available SKS historical keys according to OPC UA expectations when a requested non-current StartingTokenId identifies older keys that are still available.
- **FR-015**: The system MUST make unsupported or unknown service dispatch failures explicit and keep channels live when the protocol permits continued use.
- **FR-016**: The system MUST expose encoding, XML import, and history corruption failures instead of silently ignoring errors or accepting unbounded input.
- **FR-017**: Every remediation item MUST start with a negative-path test that fails for the targeted behavior before production behavior is changed.
- **FR-018**: Every accepted remediation MUST be traceable to at least one audit finding, conformance rule, or regression test expectation in the selected-finding matrix, which is the authoritative in-repository scope for P0/P1 findings, covered cases, and accepted remediation status.

### Key Entities

- **Audit Finding**: A security, conformance, code-review, or testing gap identified by the parallel review passes; includes severity, affected behavior, evidence, and remediation expectation.
- **Negative-Path Test**: A test that exercises malformed, unauthorized, mismatched, expired, unsupported, or boundary input and verifies the expected failure status and side effects.
- **Trust Boundary**: A point where session identity, secure channel, certificate trust, credential secrecy, role authorization, message integrity, or subscriber state must be validated before use.
- **Certificate Material**: Application certificate, user identity certificate, issuer certificate, revocation evidence, private key, or replacement credential set used in trust decisions.
- **Audit Event**: A security-relevant event emitted for certificate, secure-channel, session, or method outcomes and observable by audit subscribers.
- **Protocol Message**: Any binary transport, service request, PubSub, SKS, XML import, history, or encoded value input that can be malformed or adversarial.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: 100% of P0 and P1 findings listed in the selected-finding matrix have a passing negative-path test and a documented remediation outcome.
- **SC-002**: 100% of identity-token and certificate failures listed in the selected-finding matrix return the expected distinguishable status in acceptance tests.
- **SC-003**: 100% of certificate-validation successes with suppressed findings listed in the selected-finding matrix produce auditable records when auditing is enabled.
- **SC-004**: 100% of malformed binary transport and PubSub inputs listed in the selected-finding matrix fail without unbounded allocation, unhandled panic, or unintended state update.
- **SC-005**: 100% of certificate-management authorization and replacement scenarios listed in the selected-finding matrix either complete fully or leave existing trust material unchanged.
- **SC-006**: The remediation suite completes with all existing conformance, interoperability, audit, footprint, and code-quality checks passing.
- **SC-007**: No accepted remediation lacks traceability to an audit finding, OPC UA conformance rule, or explicit negative-path test.

## Assumptions

- The audit findings from the five parallel review passes are the authoritative scope for this remediation feature.
- The selected-finding matrix created before implementation is the authoritative in-repository index for which audit findings are P0/P1, which cases are covered, and which remediation outcomes are accepted.
- The bounded Codex Security pass was not a sealed exhaustive scan, so deferred coverage areas are included as backlog candidates but do not block this feature unless selected during planning.
- P0 and P1 findings are remediated before P2/P3 findings unless planning identifies a dependency that makes another order safer.
- Existing X.509 user-token validation improvements remain in scope and must not regress.
- Current application-certificate behavior is preserved unless a conformance rule and acceptance test justify a deliberate behavior change.
- Spec planning may split this feature into multiple implementation tasks, but each task must remain independently testable and follow failing-test-first discipline.
