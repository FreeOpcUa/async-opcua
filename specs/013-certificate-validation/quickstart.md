# Quickstart / Verification: Certificate Validation Conformance

All commands from the workspace root. Each user story is independently checkable. Fixtures (PKI
chains, CRLs) are generated in-test via `x509-cert`'s `builder` + the in-tree RSA/ECDSA keys —
Claude authors these independently of the implementation.

## Baseline gate (before any change)

```bash
cargo fmt --all --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --workspace
cargo test -p async-opcua --test integration_tests   # RSA/None loopback regression
```

## US1 — CA chain build + signature (SC-001/002)

Fixtures: root CA → (intermediate CA →) leaf.
- Valid leaf with the CA(s) in `issuer/` and root trusted → **validates**.
- Missing intermediate → `Bad_CertificateChainIncomplete`.
- Tampered signature (flip a byte in `signature`) → `Bad_CertificateInvalid`.
- Self-signed leaf placed directly in `trusted/` → **validates** (its own issuer).
- Chain to an untrusted root → `Bad_CertificateUntrusted`.

## US2 — Certificate usage (KeyUsage/EKU)

- App cert lacking the required KeyUsage/EKU → `Bad_CertificateUseNotAllowed`.
- Chain CA lacking `keyCertSign` / `basicConstraints CA` → `Bad_CertificateIssuerUseNotAllowed`.

## US3 — CRL revocation

- CRL (signed by the CA, in `*_crls/`) listing the leaf serial → `Bad_CertificateRevoked`.
- CA serial on its issuer's CRL → `Bad_CertificateIssuerRevoked`.
- Revocation required, no CRL present → `Bad_CertificateRevocationUnknown`.
- Revocation disabled for that CA → Find-Revocation-List does not error.

## US4 — Security-policy check + suppression/audit

- Key length outside the policy min/max → `Bad_CertificatePolicyCheckFailed`.
- Suppress a non-critical step that fails → validation passes **and** an `AuditCertificate*`-class
  event is raised.
- A critical step (structure/chain/signature/untrusted/URI) failing → rejected regardless of
  suppression.

## US5 — config / backward compatibility

- Existing self-signed-in-`trusted/` deployment (the certificate-creator default) connects unchanged.
- Toggle the validation policy → enforcement changes as documented.
- `None` security policy path byte-identical.

## Negative / fuzz (SC-003)

- Malformed certs and CRLs (truncated DER, absurd lengths, cyclic/deep chains) → rejected with a
  protocol error, **no panic**: `cargo +nightly fuzz run fuzz_cert_chain -- -max_total_time=<n>` → zero aborts.

## Final gate (every story)

```bash
cargo fmt --all --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --workspace
```
One commit per user story; coding tasks to codex; tests authored + run by Claude.
