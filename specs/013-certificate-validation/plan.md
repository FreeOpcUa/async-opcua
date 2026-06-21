# Implementation Plan: Certificate Validation Conformance (OPC UA Part 4 §6.1.3)

**Branch**: `013-certificate-validation` | **Date**: 2026-06-21 | **Spec**: [spec.md](./spec.md)
**Input**: Feature specification from `specs/013-certificate-validation/spec.md`

## Summary

Bring X.509 ApplicationInstanceCertificate validation into conformance with OPC UA Part 4 §6.1.3
(Table 100) on both server (validating client certs) and client (validating server certs). Today
`CertificateStore::validate_application_instance_cert` does trusted/rejected folder membership +
validity period + hostname + URI + a key-length check. This feature adds the missing steps —
**CA chain build, signature verification up the chain, Security-Policy key/algorithm check,
Certificate Usage (KeyUsage/EKU/BasicConstraints), and CRL revocation** — each mapped to its exact
status code, with the spec's suppressible/critical + audit model.

**Technical approach (pinned by research):** hand-roll the chain walk and CRL check over the
already-vendored **`x509-cert` 0.2.5** (parsing only — it has a `crl` module and typed PKIX extension
accessors) plus the **in-tree RustCrypto verify primitives** (`rsa` pkcs1v15/PSS, `p256`/`p384`
ECDSA). No new dependency; no C toolchain. `rustls-webpki` is rejected (pulls in `ring` = C, and its
WebPKI/TLS-name API does not fit OPC UA's trust-list model). The one new crypto primitive needed is
**DER-encoded ECDSA signature verification** (X.509 sigs are DER `Ecdsa-Sig-Value`, whereas the
existing `ecc::ecdsa_verify` only accepts raw fixed-length r‖s).

## Technical Context

**Language/Version**: Rust (workspace MSRV) — crates `async-opcua-crypto`, `-server`, `-client`.
**Primary Dependencies**: `x509-cert` 0.2.5 (`builder`+`hazmat`; parsing + `crl` module), `der` 0.7,
`spki` 0.7, `const-oid` 0.9.6 (`db` → rfc5280 OIDs), `rsa` 0.9, `p256` 0.13 / `p384` 0.13 / `ecdsa`
0.16, `sha2` 0.10. All already locked; **no new dependency**.
**Storage**: filesystem PKI store — `pki/{own,private,trusted,rejected}` today; this feature adds
`issuer/` (CA certs) and `trusted_crls/` + `issuer_crls/` (CRLs).
**Testing**: `cargo test` (unit + integration) + crafted PKI fixtures generated in-test via
`x509-cert`'s `builder` + the in-tree RSA/ECDSA keys; nightly fuzz target for cert/CRL/chain decode.
**Target Platform**: any Rust target incl. `aarch64-unknown-linux-musl` (pure-Rust path; no C).
**Project Type**: library (network-facing protocol stack).
**Performance Goals**: validation is per-handshake (not hot-path); bound chain depth and CRL size.
**Constraints**: pure-Rust (no OpenSSL/ring on this path); no panic on attacker certs/chains/CRLs;
fail-closed; existing self-signed-in-`trusted/` deployments unchanged; `None` policy byte-identical;
`clippy --all-targets --all-features` clean.
**Scale/Scope**: ~6 source files touched (`certificate_store.rs`, `x509.rs`, `ecc.rs` for DER-ECDSA,
`security_policy.rs`, server+client config), plus a new chain/CRL validation module.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

- **I. Correctness Over Completion** — ✅ This feature exists to close known correctness/security gaps
  in the trust path; success criteria require the full Table 100 step+status-code mapping verified by
  fixtures, not just a happy path.
- **II. Do It Right Once** — ✅ The DER-ECDSA verify primitive and X509 extension accessors are added
  as shared, reusable surface (not duplicated). Trust-list model preserved (no rework of existing
  store semantics).
- **III. Individual Task Discipline** — ✅ Decomposed into independently-verifiable user stories
  (US1 chain+sig, US2 usage, US3 revocation, US4 policy+suppression, US5 config); one task per codex
  dispatch; one commit per story.
- **IV. Security Is Paramount** — ✅ This IS security work (the cert trust path). Fail-closed defaults;
  no panic on attacker-supplied certs/CRLs (fuzzed); no new C/`ring` dependency (advisory-checked);
  no secret logging. Strongly aligned.
- **V. Leave It Better** — ✅ Replaces the comment-only "could be added here" stubs with real checks;
  adds the missing PKI dirs the store half-declares.

**Result: PASS — no violations.** No Complexity Tracking entries required.

## Project Structure

### Documentation (this feature)

```text
specs/013-certificate-validation/
├── plan.md              # This file
├── research.md          # Phase 0 — crate/primitive decisions (pinned)
├── data-model.md        # Phase 1 — entities (chain, CRL, validation policy, results)
├── quickstart.md        # Phase 1 — how to verify each user story
├── contracts/
│   └── api-surface.md   # Phase 1 — public API additions (additive)
└── tasks.md             # Phase 2 (/speckit-tasks)
```

### Source Code (repository root)

```text
async-opcua-crypto/src/
├── certificate_store.rs        # extend validate_application_instance_cert; add issuer/CRL dirs + loaders
├── x509.rs                     # new accessors: issuer, serial, sig + sig-alg, KeyUsage/EKU/BasicConstraints, AKI/SKI, tbs_der
├── ecc.rs                      # add DER-Ecdsa-Sig-Value verify (alongside the raw r‖s ecdsa_verify)
├── security_policy.rs          # cert signature-algorithm + min/max key-length conformance for the Security-Policy Check
└── cert_chain.rs (new)         # the chain walk + per-cert signature verify + CRL revocation (the Table 100 engine)

async-opcua-server/src/
├── config/server.rs            # extend CertificateValidation (enforcement/suppression/revocation policy)
├── server.rs                   # apply config -> store
└── session/{manager.rs,audit.rs} # pass context; AuditCertificate* reporting for suppressed/failed steps

async-opcua-client/src/
├── config.rs                   # extend client validation policy
└── session/{client.rs,services/session.rs} # apply config -> store; same validation on server certs
```

**Structure Decision**: The validation engine lives in `async-opcua-crypto` (a new `cert_chain.rs`
consumed by `CertificateStore`), so server and client share one implementation (FR-013). Config +
audit wiring is per-crate. The PKI directory layout extends the existing store.

## Complexity Tracking

> No Constitution Check violations — section intentionally empty.
