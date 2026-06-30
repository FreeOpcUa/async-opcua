# Quickstart: X.509 User Token Validation

Run the focused verification commands from the repository root after each completed task.

## Fast Checks

```bash
cargo test -p async-opcua-crypto cert_chain
cargo test -p async-opcua-server certificate_audit
cargo test -p async-opcua-server x509
```

## Integration Checks

```bash
cargo test -p async-opcua --test integration_tests adversarial::tampered_x509_user_token_signature_is_rejected
cargo test -p async-opcua --test integration_tests conformance::trusted_x509_user_token_activates
cargo test -p async-opcua --test integration_tests conformance::conformance_smoke_rsa_matrix
```

If the exact test names change during task execution, run the closest targeted filter first, then the full package tests below.

## Full Verification Before Completion

```bash
cargo test -p async-opcua-crypto
cargo test -p async-opcua-server
cargo test -p async-opcua --test integration_tests
```

## Expected Evidence

- A configured but untrusted/expired/revoked/wrong-usage X.509 user certificate cannot authenticate.
- A trusted, valid, configured X.509 user certificate with a valid user-token signature can authenticate.
- A trusted, valid certificate with a bad user-token signature returns the user-signature failure.
- Failed and suppressed certificate-validation findings emit matching AuditCertificate events when audit monitoring is active.
- Malformed certificate bytes are rejected without panic.
