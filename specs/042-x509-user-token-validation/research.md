# Research: X.509 User Token Validation

## Decision 1: Treat X.509 user-token certificate validation as a Part 4 authentication requirement

**Decision**: Validate the certificate carried by `X509IdentityToken` before accepting the user identity during ActivateSession.

**Rationale**: OPC UA Part 4 defines X.509 identity tokens as certificate-backed user credentials, and Part 4 certificate validation requires each validation step to report failures. A configured thumbprint identifies which validated certificate maps to a user; it does not replace trust-chain, validity, revocation, policy, and usage validation.

**Alternatives considered**:

- Keep current thumbprint-only acceptance for configured users. Rejected because it lets an expired, untrusted, revoked, or wrong-usage certificate authenticate if its thumbprint is configured.
- Validate only on application-instance certificates. Rejected because user identity certificates are a separate presented credential and are independently attacker-controlled input.

## Decision 2: Validate certificate acceptability before verifying the user-token signature

**Decision**: For X.509 identity tokens, parse and validate the certificate first, then verify the user-token signature for certificates that passed validation.

**Rationale**: The conformance audit flags the current ordering as verifying a signature before validating the signing certificate. A certificate that is not acceptable for the operation should fail as a certificate-validation error. A trusted and valid certificate with a missing or bad signature should still produce `BadUserSignatureInvalid`.

**Alternatives considered**:

- Preserve current signature-first ordering. Rejected because it hides certificate-validation failures behind signature failures and contradicts the audit finding.
- Always return `BadIdentityTokenRejected`. Rejected because OPC UA exposes more precise certificate and user-signature status codes that clients and operators use for remediation.

## Decision 3: Reuse the existing certificate-chain validator and PKI store

**Decision**: Add a user-identity validation entry point around the existing `CertificateStore` / `validate_certificate_chain` machinery instead of creating a parallel validator.

**Rationale**: The existing validator already handles trust anchors, issuer chains, key/security-policy checks, validity periods, usage checks, CRLs, OCSP inputs, and suppressed findings. Reuse avoids divergent security behavior and keeps validation policy consistent with the rest of the server.

**Alternatives considered**:

- Add a minimal "is trusted thumbprint" helper. Rejected because it repeats the current defect.
- Add a second standalone user-certificate validator. Rejected because duplicated crypto policy would drift and need separate tests.

## Decision 4: Use the existing client-certificate purpose unless a more specific user-certificate purpose is required

**Decision**: Validate X.509 user identity certificates with the existing client-side certificate usage rules initially. Add a new user-identity purpose only if implementation tests prove the OPC UA user-certificate semantics need a different extended-key-usage mapping.

**Rationale**: The existing chain validator has server-application and client-application purposes. X.509 user tokens represent a client-presented credential and should not be validated as server certificates. Avoiding a new purpose keeps the change smaller unless a concrete conformance mismatch appears.

**Alternatives considered**:

- Add a new `UserIdentity` certificate purpose immediately. Deferred because no distinct standard EKU mapping has been identified in the current MCP-backed research.
- Skip EKU/usage checks for user certificates. Rejected because Part 4 status codes include certificate use restrictions and the feature requires wrong-usage rejection.

## Decision 5: Return suppressed findings to the server audit layer

**Decision**: The validation path used by X.509 user identity tokens must surface suppressed findings to the server layer so each finding can emit the matching `AuditCertificate*` event.

**Rationale**: The current application certificate validation helper logs suppressed findings inside the crypto crate. OPC UA Part 4 6.1.3 requires suppressed validation errors to be reported via auditing. Logging alone is not an OPC UA audit event.

**Alternatives considered**:

- Keep logging-only suppressed findings. Rejected because it leaves the audit backlog gap open.
- Emit audit events from the crypto crate. Rejected because the crypto crate has no session, server, or subscription audit context.

## Decision 6: Test at the lowest layer that proves each contract

**Decision**: Use crypto/server unit tests for helper behavior and integration tests for externally visible ActivateSession and audit outcomes.

**Rationale**: Certificate fixture construction and status-code mapping can be tested quickly at lower layers, but the user-observable contract is ActivateSession behavior and audit event delivery.

**Alternatives considered**:

- Only add integration tests. Rejected because certificate edge fixtures can be expensive and less precise when every case needs a full server/client handshake.
- Only add unit tests. Rejected because the current gap is in wiring validation into ActivateSession.
