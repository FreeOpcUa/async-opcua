# Data Model: Certificate Validation Conformance

Entities are internal to `async-opcua-crypto` unless marked public. The X.509 `Certificate`,
`CertificateList` (CRL), and the `CertificateStore` are existing/`x509-cert` types, extended.

## PKI store layout (extends existing)

| Dir | Exists? | Holds |
|-----|---------|-------|
| `own/`, `private/` | yes | the application's own cert + key |
| `trusted/` | yes | administrator-trusted certs (leaf or CA) — the **trust anchor** |
| `rejected/` | yes | auto-stored unknown certs |
| `issuer/` | **new** | CA certs available for chain building but not directly trusted |
| `trusted_crls/`, `issuer_crls/` | **new** | CRLs for the trusted / issuer CA certs |

## Certificate (existing `X509`, new accessors)

| Accessor (new, public) | Returns | Use |
|------------------------|---------|-----|
| `issuer_name()` | issuer DN | chain matching |
| `serial_number()` | serial bytes | CRL lookup |
| `tbs_der()` | TBS DER bytes | signature verification input |
| `signature_and_algorithm()` | (sig bytes, alg OID, params) | signature verification |
| `key_usage()` | KeyUsage bits (option) | Certificate Usage step |
| `extended_key_usage()` | EKU OIDs (option) | Certificate Usage step |
| `basic_constraints()` | (is_ca, pathLen) (option) | CA / pathLen checks |
| `authority_key_identifier()` / `subject_key_identifier()` | bytes (option) | chain cross-check |
| `is_self_signed()` | bool | chain termination (root) |

Existing (reused): `public_key`, `key_length`, `subject_name`, `not_before/after`, `is_time_valid`,
`is_hostname_valid`, `is_application_uri_valid`, `thumbprint`, `to_der`.

## Certificate chain (internal, transient)

- Ordered `Vec<X509>`: leaf → … → self-signed root, assembled from the leaf + issuer/trusted lists.
- Built during validation; **bounded depth** (≤ a fixed max) and **cycle-detected** (Constitution IV).

## CRL (`x509-cert::crl::CertificateList`, new validation logic)

- Parsed from `*_crls/`. Fields used: `tbs_cert_list.issuer`, `this_update`/`next_update`,
  `revoked_certificates[].serial_number`, and `tbs_cert_list.to_der()` + `signature` for the CRL's
  own signature verification (a CRL is trusted only if signed by a CA in the chain).

## ValidationPolicy / options (new, public config-driven)

| Field | Meaning | Default |
|-------|---------|---------|
| enforce chain+signature | run Build-Chain + Signature steps | **on** |
| enforce certificate-usage | run KeyUsage/EKU/BasicConstraints | **on** |
| enforce security-policy check | algorithm + key-length per policy | on (suppressible) |
| revocation mode | off / lenient (check if CRL present) / required | **lenient** |
| per-step suppression set | which suppressible steps are suppressed | none |

Critical steps (structure, build-chain, signature, untrusted, URI) are **not** in the suppression set.
The existing `set_skip_verify_certs` / `set_trust_unknown_certs` / `set_check_time` toggles remain.

## ValidationOutcome (internal)

- Result of the ordered Table 100 run: `Ok(())` or the first non-suppressed step's specific
  `StatusCode` (Bad_Certificate{Invalid,ChainIncomplete,PolicyCheckFailed,Untrusted,TimeInvalid,
  HostNameInvalid,UriInvalid,UseNotAllowed,RevocationUnknown,Revoked} + the `Issuer*` variants).
- Suppressed-step failures: validation continues, but each emits an `AuditCertificate*`-class event.

## State transition — validation (per §6.1.3 Table 100, ordered)

```
Structure → Build-Chain → [for each cert in chain: Signature, Security-Policy, …]
  → Trust-List → Validity → HostName(server only) → URI → Certificate-Usage
  → Find-Revocation-List → Revocation-Check
Halt on first non-suppressed failure (its status code). Suppressed failures → audit + continue.
Self-signed leaf in trusted/: chain = [leaf]; signature self-verifies; trusted.
```
