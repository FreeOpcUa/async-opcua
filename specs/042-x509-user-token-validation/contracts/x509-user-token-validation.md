# Contract: X.509 User Token Validation

## Normative References

- OPC-10000-4 6.1.3: certificate trust validation and audit reporting for suppressed validation errors.
- OPC-10000-4 5.7.3: ActivateSession behavior and service results, including user signature failures.
- OPC-10000-4 7.40.5: X.509 identity token certificate and user-token signature requirements.
- OPC-10000-4 7.38.2: certificate status code meanings, including use-not-allowed and untrusted certificate failures.

## ActivateSession Contract

### Trusted valid X.509 user certificate

Given:

- Endpoint supports certificate identity tokens.
- Presented user certificate is trusted, valid, not revoked, allowed for the requested operation, and compatible with the selected user-token security policy.
- Presented certificate thumbprint is configured for a user.
- User-token signature is valid.

Expected outcome:

- ActivateSession succeeds.
- Session user identity is the configured X.509 user identity.
- No certificate failure audit event is emitted.

### Invalid certificate with configured thumbprint

Given:

- Endpoint supports certificate identity tokens.
- Presented certificate thumbprint is configured for a user.
- Presented certificate fails trust-chain, validity, revocation, policy, or usage validation.

Expected outcome:

- ActivateSession fails before assigning the X.509 user identity.
- The returned failure identifies certificate validation, not user mapping success.
- A matching `AuditCertificate*` event is emitted when audit monitoring is active.

### Valid certificate with invalid user-token signature

Given:

- Endpoint supports certificate identity tokens.
- Presented user certificate passes validation and maps to a configured user.
- User-token signature is missing or invalid.

Expected outcome:

- ActivateSession fails with `BadUserSignatureInvalid`.
- The X.509 user identity is not assigned.
- The failure is not reported as a certificate trust failure.

### Unsupported endpoint policy

Given:

- Endpoint does not support certificate identity tokens.
- Client presents an X.509 user identity token.

Expected outcome:

- ActivateSession rejects the identity token.
- The X.509 user identity is not assigned.
- Certificate validation need not proceed because the endpoint policy disallows the token type.

### Suppressed certificate finding

Given:

- Endpoint supports certificate identity tokens.
- Presented certificate has one or more explicitly suppressed non-critical validation findings.
- No hard certificate failure remains.
- User-token signature and configured mapping succeed.

Expected outcome:

- ActivateSession succeeds.
- One matching `AuditCertificate*` event is emitted for each suppressed finding when audit monitoring is active.
- The session user identity is assigned only after validation, signature verification, and mapping all succeed.

## Non-Regression Contract

- Anonymous, username/password, and issued-token activation behavior is unchanged.
- Application-instance certificate validation remains unchanged.
- Malformed X.509 user certificate bytes are rejected without panic or process abort.
- No private keys, passwords, decrypted secrets, or raw signatures appear in audit events or logs.
