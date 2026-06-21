# Public Surface Changes: Certificate Validation Conformance

All changes are **additive** to existing public APIs; no breaking change to RSA/None or the existing
trust-list behavior for self-signed-in-`trusted/` deployments.

## async-opcua-crypto

### `X509` (new accessors)
- `issuer_name`, `serial_number`, `tbs_der`, `signature_and_algorithm`, `key_usage`,
  `extended_key_usage`, `basic_constraints`, `authority_key_identifier`, `subject_key_identifier`,
  `is_self_signed`. Each returns parsed data or `None`/error on absence; **never panics** on malformed
  extensions.

### `ecc` (new — DER ECDSA verification)
- A DER `Ecdsa-Sig-Value` verify entry point (e.g. `ecdsa_verify_der(curve, pubkey, msg, der_sig)`),
  alongside the existing raw-`r‖s` `ecdsa_verify` (unchanged). Used by chain/CRL signature checks.

### `cert_chain` (new module — the Table 100 engine)
- A function that, given a leaf cert, the trusted + issuer cert lists, the available CRLs, the
  negotiated `SecurityPolicy`, the requested use (server/client app cert vs CA), optional hostname +
  application URI, and a `ValidationOptions`, returns `Result<(), Error>` whose error carries the
  exact §6.1.3 status code. Internal; consumed by `CertificateStore`.

### `CertificateStore`
- New PKI dir accessors: `issuer_certs_dir`, `trusted_crls_dir`, `issuer_crls_dir`; loaded in
  `ensure_pki_path` (created if absent).
- `validate_application_instance_cert` gains the full Table 100 pipeline (chain, signature,
  security-policy, usage, revocation) behind the validation policy; existing trusted/rejected/time/
  hostname/URI behavior preserved.
- New setter(s) to configure the validation policy (mirroring `set_check_time` etc.), e.g.
  `set_validation_options(ValidationOptions)`. `ValidationOptions` is public.

## async-opcua-server / async-opcua-client (config)
- Server `CertificateValidation` and client `ClientConfig` gain validation-policy fields (enforce
  chain, enforce usage, revocation mode, suppression set) with safe defaults (chain/usage on,
  revocation lenient). Builder methods mirror existing ones (`trust_client_certs`, `check_time`, …).
- Both apply the policy to the `CertificateStore` at startup; both validate the peer's application
  certificate through the same engine (server↔client parity, FR-013).

## Behavioral contracts (no signature change to existing call sites)
- Server `manager.rs` and client `services/session.rs` keep calling
  `validate_or_reject_application_instance_cert(cert, policy, hostname, app_uri)`; the additional
  validation happens inside. The `None` policy path is byte-identical.

## Invariants preserved (verified by tests)
- Self-signed application cert in `trusted/` still validates.
- `None` security policy wire path unchanged.
- No panic on attacker-supplied certs/chains/CRLs; bounded chain depth.
- No new C-toolchain dependency; `clippy --all-targets --all-features` clean.
