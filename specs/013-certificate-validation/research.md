# Research & Design Decisions: Certificate Validation Conformance

Sources: OPC UA Part 4 §6.1.3 (Table 100, extracted verbatim during specify); RFC 5280 (X.509 path
validation + §6.3 CRL); codebase + crate research (2026-06-21). All crate versions confirmed from
`Cargo.lock`.

## Decision 1 — Hand-roll chain + CRL over `x509-cert` + RustCrypto (no new dependency)

- **Decision**: Implement chain building, per-certificate signature verification, and CRL revocation
  by hand over the already-vendored **`x509-cert` 0.2.5** (parsing) and the **in-tree RustCrypto
  verify primitives** (`rsa` 0.9 pkcs1v15/PSS, `p256`/`p384`/`ecdsa` 0.16). Add a new
  `async-opcua-crypto/src/cert_chain.rs` module.
- **Rationale**: pure-Rust, no C toolchain, no new dependency to advisory-check; reuses the exact
  verify code already shipping (`aes/rsa_private_key.rs:604-634` RSA pkcs1v15/PSS; `ecc.rs` ECDSA);
  matches OPC UA's trust-list semantics (explicit trusted + issuer lists, application-URI/SAN rules,
  OPC-UA KeyUsage requirements) that a WebPKI validator cannot express.
- **Alternatives rejected**:
  - **`rustls-webpki` 0.103** (the only path validator in the lock): pulls in **`ring` (C/asm)** —
    violates the pure-Rust / no-C constraint and is reachable only via the TLS stack, not
    `async-opcua-crypto`; and its `EndEntityCert::verify_for_usage` + DNS-name API is WebPKI/TLS
    oriented, not OPC UA trust-list / URI-SAN oriented.
  - **OpenSSL**: explicitly excluded by the project.
  - **`x509-cert`'s own validator**: none exists (parsing only).

## Decision 2 — DER-encoded ECDSA signature verification (the one new primitive)

- **Decision**: Add a DER `Ecdsa-Sig-Value` verification path in `ecc.rs` (using
  `p256::ecdsa::Signature::from_der` / `p384::ecdsa::Signature::from_der`, or `ecdsa::der::Signature`),
  used for certificate and CRL signatures. Keep the existing raw-`r‖s` `ecdsa_verify` (used by the
  ECC secure-channel handshake) unchanged.
- **Rationale**: X.509 / CRL ECDSA signatures are DER `SEQUENCE { r INTEGER, s INTEGER }`, **not** the
  fixed-length raw `r‖s` that the handshake uses; feeding the cert signature to the existing
  `ecc::ecdsa_verify` (which validates exact length) fails. The DER APIs exist in the locked
  `ecdsa 0.16.9` / `p256` / `p384`.
- **Alternatives rejected**: re-encoding DER→raw before calling the existing verifier (fragile,
  duplicates parsing). [confirm: handle the SHA-256 (P-256) vs SHA-384 (P-384) hash by the signature
  algorithm OID, not the curve, at implementation time.]

## Decision 3 — Signature material extraction (`x509-cert` mechanics)

- The signed bytes for a certificate are `cert.tbs_certificate.to_der()` (TBS derives `der::Encode`).
  The signature bits are `cert.signature.as_bytes()`; the algorithm is `cert.signature_algorithm.oid`
  (+ `parameters` for RSASSA-PSS). CRL: `crl.tbs_cert_list.to_der()` + `crl.signature`.
- Map the signature-algorithm OID (via `const-oid` 0.9.6 `db::rfc5280`) to the verifier:
  `sha256WithRSAEncryption` → RSA-PKCS1v15-SHA256; `id-RSASSA-PSS` → RSA-PSS; `ecdsa-with-SHA256` →
  P-256 DER; `ecdsa-with-SHA384` → P-384 DER. (SHA-1 RSA only under `legacy-crypto`.)
- Issuer public key from `issuer.tbs_certificate.subject_public_key_info` (SPKI) — the in-tree
  `rsa`/`spki`/`pkcs1` decode it (already round-tripped in `rsa_private_key.rs`).

## Decision 4 — X509 extension accessors (additive, `x509-cert` typed `get::<T>()`)

- Add public accessors on `X509`: `issuer_name`, `serial_number`, `signature_der_and_alg`,
  `tbs_der`, `key_usage`, `extended_key_usage`, `basic_constraints` (CA flag + pathLen),
  `authority_key_identifier`, `subject_key_identifier`.
- Implemented via `self.value.tbs_certificate.get::<T>()` with the typed PKIX extension types
  `x509_cert::ext::pkix::{KeyUsage, ExtendedKeyUsage, BasicConstraints, AuthorityKeyIdentifier,
  SubjectKeyIdentifier}` (each carries its `AssociatedOid`). The existing SubjectAltName access
  (`x509.rs:962`) is the template.

## Decision 5 — Chain build & trust anchoring (§6.1.3 + RFC 5280)

- **Chain walk**: from the leaf, find the issuer in the **issuer-cert list** (and trusted list) by
  matching `subject.issuer == issuer.subject`, cross-checked by `AuthorityKeyIdentifier`↔
  `SubjectKeyIdentifier` when present; verify each `subject.tbs.to_der()` against the issuer SPKI;
  stop at a self-signed root. Missing link → `Bad_CertificateChainIncomplete`. Bound depth (e.g. ≤10)
  and detect cycles to prevent unbounded work (Constitution IV).
- **Trust anchor (§6.1.3)**: the cert is trusted iff the leaf **or at least one CA in its chain** is
  in the **trusted list**; else `Bad_CertificateUntrusted`. This preserves today's behavior for a
  self-signed leaf in `trusted/` (its chain is itself).
- **BasicConstraints/KeyUsage for CAs**: each non-leaf must be a CA (`basicConstraints CA=TRUE`,
  `keyUsage keyCertSign`); pathLen respected → otherwise `Bad_CertificateIssuerUseNotAllowed` /
  chain invalid.

## Decision 6 — CRL revocation (RFC 5280 §6.3)

- New PKI dirs: `issuer/` (CA certs), `trusted_crls/` + `issuer_crls/` (CRLs). Load CRLs, **verify
  each CRL's signature** against its issuing CA SPKI (a CRL is only trusted if its issuer is in the
  chain/trust), then scan `revoked_certificates` by serial number.
- **"Find Revocation List"**: if revocation is required for a CA but no valid CRL is present →
  `Bad_CertificateRevocationUnknown` / `…IssuerRevocationUnknown` (suppressible). If the admin
  disabled revocation for that CA, the step does not error.
- **Default**: revocation is **lenient** — checked when a CRL store/CRLs are present or explicitly
  required; not required by default so CRL-less deployments don't break. [confirm at plan with user.]
- **OCSP**: out of scope (deferred).

## Decision 7 — Security-Policy Check (Table 100)

- Verify the certificate's **signature algorithm** matches the policy's CertificateSignatureAlgorithm
  and its **asymmetric key length** is within Min/MaxAsymmetricKeyLength for the negotiated
  SecurityPolicy (Part 7). `SecurityPolicy::is_valid_keylength` exists; extend with the
  signature-algorithm/min-max where needed. Failure → `Bad_CertificatePolicyCheckFailed` (suppressible).

## Decision 8 — Suppression & audit (§6.1.3)

- A **ValidationOptions/policy** carries which suppressible steps are enforced vs suppressed
  (security-policy, validity, host-name, certificate-usage, find-revocation-list) and whether
  revocation is required (global / per-CA). Critical steps (structure, build-chain, signature,
  untrusted, URI) are **never** suppressible.
- **Audit**: a suppressed failure passes validation but MUST raise the corresponding `AuditCertificate*`
  event. The server currently has no `AuditCertificate*` types — only generic `AuditSecurityEventType`
  (`session/audit.rs`). **[DECISION — confirm]**: report suppressed/failed cert steps via the existing
  audit surface with the precise status code now, and add the typed `AuditCertificate*` event types as
  a follow-up refinement (keeps US4 from ballooning). Record this as a deliberate, documented scope cut.

## Decision 9 — Default enforcement mode (the spec's open decision)

- **Decision (proposed, confirm with user)**: chain + signature + certificate-usage validation is
  **ON by default** (conformant; self-signed-in-`trusted/` unaffected because a self-signed leaf is
  its own chain). Revocation is **off/lenient by default** (only when CRLs configured/required).
  Configurable via the new validation-policy config; the `None` security policy path is byte-identical.
- **Rationale**: honors the user's "existing trust-list-only deployments must keep working"; the only
  behavior change is for CA-signed-leaf-without-the-CA setups, which cannot fully work today anyway.

## Codebase integration points (confirmed)

- `CertificateStore::validate_application_instance_cert` (`certificate_store.rs:280-427`) — the
  function to extend; today: rejected-folder, trusted-folder (byte-equality), key-length, time,
  hostname, URI. Accessors: `trusted_certs_dir`/`rejected_certs_dir`/`ensure_pki_path`. Toggles:
  `set_skip_verify_certs`/`set_trust_unknown_certs`/`set_check_time`.
- Call sites: **server** `session/manager.rs:248` (client cert, hostname=None, app URI from
  ClientDescription); **client** `session/services/session.rs:234` (server cert, hostname from
  endpoint URL, app URI from endpoint). Same engine both sides (FR-013).
- Config: server `CertificateValidation` (`config/server.rs:298`, applied `server.rs:323`); client
  `ClientConfig` (`config.rs:265`, applied `client.rs:75`).
- `SecurityPolicy::is_valid_keylength` (`security_policy.rs:316`), `asymmetric_signature_algorithm`
  (`:277`).

## Open items to confirm at plan/clarify

- Default enforcement mode (Decision 9) — confirm ON-by-default for chain/sig/usage, lenient revocation.
- Audit typed events (Decision 8) — confirm using the existing audit surface now vs adding
  `AuditCertificate*` types in this feature.
