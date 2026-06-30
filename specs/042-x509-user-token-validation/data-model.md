# Data Model: X.509 User Token Validation

## Entity: X509UserIdentityToken

Represents the user certificate credential supplied during ActivateSession.

Fields:

- `policy_id`: User token policy identifier. Must match an endpoint policy that supports certificate identity tokens.
- `certificate_data`: DER certificate bytes. Must parse as an X.509 certificate before authentication can continue.
- `user_token_signature`: Proof-of-possession over the server certificate and nonce, required for X.509 identity tokens.

Validation rules:

- Missing, malformed, or unsupported token data fails before user identity assignment.
- The certificate must pass certificate-chain validation before thumbprint-based user mapping is accepted.
- A trusted certificate with a missing or invalid signature fails with the user-signature status.

## Entity: UserCertificateValidationResult

Represents the certificate-validation outcome for the presented X.509 user certificate.

Fields:

- `certificate`: Parsed X.509 certificate.
- `status`: `Good` for hard success or the certificate status code for a hard failure.
- `suppressed_findings`: Zero or more suppressed non-critical certificate validation findings.

Validation rules:

- Any hard failure stops X.509 user authentication.
- Suppressed findings do not stop authentication, but each must be audited.
- The result must not contain secrets or private key material.

## Entity: ConfiguredUserIdentityMapping

Represents the server-side mapping from a validated certificate to a user.

Fields:

- `endpoint_policy`: Endpoint user-token policy that allows X.509 identity tokens.
- `thumbprint`: Certificate thumbprint configured for a user.
- `user_token`: Authenticated user token returned after validation and mapping succeed.

Validation rules:

- Mapping is evaluated only after certificate validation succeeds.
- A matching thumbprint is insufficient if certificate validation fails.
- Unsupported endpoint policy fails before mapping.

## Entity: CertificateAuditEvent

Represents an OPC UA audit event for a certificate-validation failure or suppressed finding.

Fields:

- `event_type`: Matching `AuditCertificate*` subtype for the certificate status code.
- `certificate`: The subject certificate bytes when available.
- `status`: Certificate-validation status code being audited.
- `session_context`: Session/authentication context available at the point of validation.

Validation rules:

- Hard certificate failures that map to an AuditCertificate subtype must emit one event when audit monitoring is active.
- Each suppressed finding must emit its own event even when authentication succeeds.
- Audit event data must not include passwords, private keys, decrypted secrets, or raw user-token signatures.

## State Transitions

```text
Token received
  -> Certificate parse failed
       -> Reject activation; no user identity assigned
  -> Certificate parsed
       -> Certificate hard validation failed
            -> Emit AuditCertificate event when possible; reject activation
       -> Certificate validation succeeded with suppressed findings
            -> Emit AuditCertificate event for each finding
            -> Verify user-token signature
       -> Certificate validation succeeded without suppressed findings
            -> Verify user-token signature

Signature verification
  -> Failed
       -> Reject activation with user-signature status; no user identity assigned
  -> Succeeded
       -> Check endpoint policy and configured user mapping

User mapping
  -> Missing/unsupported
       -> Reject activation; no user identity assigned
  -> Matched
       -> Assign X.509 user identity to session
```
