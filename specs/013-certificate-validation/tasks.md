---
description: "Task list for feature 013 — certificate validation conformance (Part 4 §6.1.3)"
---

# Tasks: Certificate Validation Conformance (OPC UA Part 4 §6.1.3)

**Input**: Design documents from `/specs/013-certificate-validation/`
**Prerequisites**: plan.md, spec.md, research.md (approach PINNED: hand-rolled chain/CRL over
x509-cert 0.2.5 + in-tree RustCrypto; one new primitive = DER-Ecdsa-Sig-Value verify),
data-model.md, contracts/api-surface.md, quickstart.md

**Tests**: INCLUDED — security-critical trust path; constitution I/IV require crafted-PKI-fixture
tests per §6.1.3 Table 100 step (each failing before the change, passing after) + negative/fuzz.

**Execution discipline**: one task per codex dispatch; verify the failing test first; **one commit
per user story** (the closing gate-&-commit task). Coding tasks → codex (implementation only, no
self-authored tests); **Claude authors and runs all tests** independently (crafted chains/CRLs +
exact §6.1.3 status-code mapping). codex no-git guardrail; verify branch after. Gate before each
per-story commit: `cargo fmt --all --check && cargo clippy --all-targets --all-features --locked -- -D warnings && cargo test --workspace`.

**Pinned (research.md):** signature material = `tbs.to_der()` + `cert.signature` + alg OID
(const-oid rfc5280); verify via in-tree `rsa` pkcs1v15/PSS + `p256`/`p384` ECDSA; ECDSA cert/CRL sigs
are **DER** (need `from_der`, NOT the raw-`r‖s` `ecc::ecdsa_verify`); typed extensions via
`x509_cert::tbs_certificate.get::<T>()`. PKI dirs added: `issuer/`, `trusted_crls/`, `issuer_crls/`.
Trust anchor preserved: self-signed leaf in `trusted/` stays valid. `None` policy byte-identical.

## Format: `[ID] [P?] [Story] Description`

---

## Phase 1: Setup

- [X] T001 Add the new PKI directories to `async-opcua-crypto/src/certificate_store.rs`: dir
  constants + accessors `issuer_certs_dir()`, `trusted_crls_dir()`, `issuer_crls_dir()`, created in
  `ensure_pki_path()`; loaders that read all certs/CRLs from those dirs (DER + PEM), skipping
  unreadable entries without panic. Capture the baseline gate. No validation-logic change yet.

## Phase 2: Foundational (Blocking Prerequisites)

- [X] T002 Add public X509 extension/field accessors in `async-opcua-crypto/src/x509.rs`
  (`issuer_name`, `serial_number`, `tbs_der`, `signature_and_algorithm`, `key_usage`,
  `extended_key_usage`, `basic_constraints` (is_ca + pathLen), `authority_key_identifier`,
  `subject_key_identifier`, `is_self_signed`) via `tbs_certificate.get::<T>()` with
  `x509_cert::ext::pkix::*`. All return `Option`/`Result`; **never panic** on malformed extensions.
- [X] T003 Add DER `Ecdsa-Sig-Value` verification in `async-opcua-crypto/src/ecc.rs`
  (`ecdsa_verify_der` using `p256/p384::ecdsa::Signature::from_der`), alongside the unchanged raw
  `ecdsa_verify`. Behind the `ecc` feature.
- [X] T004 Scaffold `async-opcua-crypto/src/cert_chain.rs` (new module): the public
  `ValidationOptions` (enforce chain/usage, revocation mode, per-step suppression set) and the
  internal Table-100 validation entry point signature returning `Result<(), Error>` with
  step-specific status codes — stubs/`unimplemented` so US1 tests compile and fail. Wire the module
  into `lib.rs`. No logic yet.
- [X] T005 Add the Security-Policy certificate checks surface in
  `async-opcua-crypto/src/security_policy.rs`: per-policy certificate signature-algorithm +
  min/max asymmetric key-length accessors used by the Security-Policy Check (reuse
  `is_valid_keylength`/`asymmetric_signature_algorithm`). No call-site change yet.

**Checkpoint**: PKI dirs + X509 accessors + DER-ECDSA + cert_chain API exist; stories can proceed.

---

## Phase 3: User Story 1 — CA chain build + signature verification (Priority: P1) 🎯 MVP

**Goal**: accept only certs whose signature chains to a trusted CA; reject unknown-issuer / forged
signature; self-signed-in-`trusted/` still valid.
**Independent Test**: crafted root→[intermediate→]leaf fixtures; missing link → ChainIncomplete;
tampered sig / malformed structure → Invalid; chain to untrusted root → Untrusted; expired leaf →
TimeInvalid, expired issuer → IssuerTimeInvalid; self-signed leaf trusted → valid.

- [ ] T006 [US1] Claude-authored failing tests in `async-opcua-crypto` (cert_chain tests): generate
  in-test PKI fixtures via `x509-cert` builder + in-tree RSA/ECDSA keys (root CA, intermediate CA,
  leaf, self-signed leaf, tampered-signature leaf, **expired leaf, expired intermediate/issuer**,
  truncated/malformed-structure leaf); assert chain build + per-cert signature verify + **per-chain-cert
  validity period** and the exact status codes (`Bad_CertificateChainIncomplete`, `Bad_CertificateInvalid`
  incl. malformed-structure, `Bad_CertificateUntrusted`, **`Bad_CertificateTimeInvalid` (leaf) /
  `Bad_CertificateIssuerTimeInvalid` (chain CA)**); self-signed leaf in trusted set validates.
  (FR-001/002/003/005/006)
- [ ] T007 [US1] Implement chain build + signature verification + **validity-period (FR-006)** in
  `cert_chain.rs`: walk leaf→root via issuer/subject (+ AKI/SKI cross-check) over trusted+issuer lists;
  verify each `tbs.to_der()` against issuer SPKI per alg OID (RSA pkcs1v15/PSS via `rsa`; ECDSA via the
  new DER verify); **check each cert's not-before/not-after — leaf failure → `Bad_CertificateTimeInvalid`,
  any chain-CA failure → `Bad_CertificateIssuerTimeInvalid` (suppressible; honoured by the US4
  suppression model)**; reject malformed structure → `Bad_CertificateInvalid`; bound depth + detect
  cycles; Trust-List anchor (leaf or a chain CA in trusted). (depends T006)
- [ ] T008 [US1] Wire `cert_chain` into `CertificateStore::validate_application_instance_cert`
  (`certificate_store.rs`) behind the validation policy, preserving the existing trusted/rejected/
  time/hostname/URI behavior and the self-signed-in-`trusted/` path; `None` policy byte-identical.
  (depends T007)
- [ ] T009 [US1] Gate; verify T006 passes; **commit US1**
  (`feat(013 US1): CA chain build + signature verification (Part 4 §6.1.3)`).

**Checkpoint**: certificates are chain-validated; the core trust gap is closed (MVP).

---

## Phase 4: User Story 2 — Certificate usage (KeyUsage / EKU) (Priority: P2)

**Goal**: reject certs not marked for the requested use; CA certs must be CAs.
**Independent Test**: app cert missing required KeyUsage/EKU → UseNotAllowed; chain CA lacking
keyCertSign/CA → IssuerUseNotAllowed.

- [ ] T010 [US2] Claude-authored failing tests (cert_chain tests): fixtures with correct, wrong, and
  missing KeyUsage/EKU and CA basicConstraints; assert `Bad_CertificateUseNotAllowed` /
  `Bad_CertificateIssuerUseNotAllowed`.
- [ ] T011 [US2] Implement the Certificate-Usage step in `cert_chain.rs` (leaf KeyUsage/EKU per
  application-cert requirements; each chain CA must have `basicConstraints CA` + `keyUsage
  keyCertSign`; honour mandatory-usage), mapped to the status codes. (depends T010)
- [ ] T012 [US2] Gate; verify T010 passes; **commit US2** (`feat(013 US2): certificate usage (KeyUsage/EKU) checks`).

**Checkpoint**: misused / non-CA-issuer certs rejected.

---

## Phase 5: User Story 3 — CRL revocation (Priority: P2)

**Goal**: reject revoked certs; flag revocation-unknown; honour per-CA disable.
**Independent Test**: CRL listing leaf serial → Revoked; CA serial on issuer CRL → IssuerRevoked;
required-but-no-CRL → RevocationUnknown; disabled-per-CA → no error.

- [ ] T013 [US3] Claude-authored failing tests (cert_chain tests): generate CA-signed CRLs via
  `x509-cert` crl + builder; assert `Bad_CertificateRevoked`, `Bad_CertificateIssuerRevoked`,
  `Bad_CertificateRevocationUnknown` (required, no CRL), and no-error when revocation disabled.
- [ ] T014 [US3] Implement Find-Revocation-List + Revocation-Check in `cert_chain.rs`: load CRLs from
  `trusted_crls`/`issuer_crls`, **verify each CRL signature** against its issuing CA SPKI, scan
  `revoked_certificates` by serial (RFC 5280 §6.3); revocation-mode (off/lenient/required) +
  per-CA disable. (depends T013)
- [ ] T015 [US3] Gate; verify T013 passes; **commit US3** (`feat(013 US3): CRL revocation checking`).

**Checkpoint**: revoked certificates rejected.

---

## Phase 6: User Story 4 — Security-policy check + suppression & audit (Priority: P3)

**Goal**: enforce cert sig-alg/key-length per SecurityPolicy; suppressible non-critical steps raise audit.
**Independent Test**: key length out of policy → PolicyCheckFailed; suppressed non-critical failure →
passes + audit event; critical steps never suppressible.

- [ ] T016 [US4] Claude-authored failing tests: a cert whose key length/sig-alg violates the
  negotiated policy → `Bad_CertificatePolicyCheckFailed`; with that step suppressed → validation
  passes AND an audit event is recorded; assert critical steps (structure/chain/signature/untrusted/
  URI) reject regardless of suppression. **Ordering/precedence (SC-001 "in order"): a fixture that
  fails two steps at once returns the *earlier* Table-100 step's status code (e.g. untrusted+expired →
  the chain/untrusted code, not the time code); halt is on the first non-suppressed failure.**
- [ ] T017 [US4] Implement the Security-Policy Check in `cert_chain.rs` (sig-alg + min/max key-length
  per policy from T005) and the suppression model (suppressible set vs critical set); **assemble the
  full ordered Table-100 pipeline (structure → build-chain → signature → security-policy → trust-list →
  validity → host-name → URI → usage → find-revocation → revocation), halting on the first
  non-suppressed failure so its status code wins**; on a suppressed failure, continue but report the
  step via the existing server audit surface (`async-opcua-server/src/session/audit.rs`) with the
  precise status code (typed `AuditCertificate*` event types deferred — research Decision 8). (depends T016)
- [ ] T018 [US4] Gate; verify T016 passes; **commit US4** (`feat(013 US4): security-policy check + suppression/audit`).

**Checkpoint**: full Table 100 step set enforced; suppression+audit per §6.1.3.

---

## Phase 7: User Story 5 — Configuration, rollout & backward compatibility (Priority: P3)

**Goal**: configurable validation policy on server + client; existing self-signed deployments unchanged.
**Independent Test**: self-signed-in-`trusted/` connects unchanged; toggling policy changes
enforcement; ECC + RSA loopback suites still green; `None` byte-identical.

- [ ] T019 [US5] Claude-authored failing/integration tests: mixed validation-policy config round-trip;
  an existing self-signed loopback (server↔client) still connects; a CA-issued-cert loopback with the
  CA in `issuer/` connects; an untrusted-issuer cert is rejected at CreateSession.
- [ ] T020 [US5] Wire the validation policy into server `CertificateValidation`
  (`async-opcua-server/src/config/server.rs` + `server.rs`) and client `ClientConfig`
  (`async-opcua-client/src/config.rs` + `session/client.rs`), applied to the `CertificateStore`;
  builder methods mirror the existing `trust_*_certs`/`check_time`. Default: chain/usage on, revocation
  lenient. (depends T019)
- [ ] T021 [US5] Add a sample/docs note (PKI `issuer/` + CRL dirs; the validation-policy toggles) in
  `docs/compatibility.md` / `docs/crypto.md`; ensure `--no-default-features` (pure-Rust) builds clean.
  (depends T019)
- [ ] T022 [US5] Gate; verify T019 passes; **commit US5** (`feat(013 US5): validation-policy config + rollout`).

**Checkpoint**: certificate-validation conformance usable and safe to ship.

---

## Phase 8: Polish & Cross-Cutting

- [ ] T023 [P] Fuzz the cert/CRL/chain decode + validation path: add `fuzz_cert_chain` (nightly) over
  malformed certs, CRLs, and cyclic/deep chains → zero aborts/panics.
- [ ] T024 [P] Update `docs/compatibility.md` "Current limitations" + release notes (CHANGELOG) for
  Part 4 §6.1.3 chain/usage/revocation; record the deferred items (OCSP, typed `AuditCertificate*`
  events) and the security-review note (trust-path change).
- [ ] T025 Final gate: `cargo fmt --all --check` + `cargo clippy --all-targets --all-features -- -D warnings`
  + `cargo test --workspace` + `verify-clean-codegen`; confirm `None`/RSA wire byte-identity and the
  self-signed-in-`trusted/` regression both pass.

---

## Dependencies & Execution Order

- **Setup (T001)** → no deps. **Foundational (T002–T005)** → after Setup; block all stories.
- **US1** (T006→T007→T008→T009) is the chain/signature foundation; **US2** (usage) and **US3**
  (revocation) depend on US1's chain; **US4** (policy+suppression/audit) depends on the chain + the
  T005 policy surface; **US5** (config) depends on US1 for the validation surface.
- Within a story: failing test → impl → gate-&-commit. One task per codex dispatch.
- **Polish (T023–T025)** after the stories.

## Implementation Strategy

**MVP = US1** (chain build + signature verification) — closes the biggest trust gap. Then US2 (usage),
US3 (revocation), US4 (policy/suppression/audit), US5 (config/rollout). Each story is an
independently-testable, single-commit increment. Approach is pinned (research.md), so each task is
"implement to the recorded approach + crafted fixtures", not "discover the design".

## Notes

- One task per codex dispatch; verify the failing (Claude-authored) test before implementing; codex
  no-git guardrail + verify branch after.
- One commit per user story; `None`/RSA byte-identical; self-signed-in-`trusted/` preserved.
- No generated-code edits; `verify-clean-codegen` stays green. Pure-Rust (no new C dep).
- Deferred (recorded): OCSP; typed `AuditCertificate*` event types; GDS/CA issuance; mixed RSA+ECC
  multi-cert server (feature 012); session-activation hardening (separate feature).
- Residual risk: third-party interop of the chain/CRL behavior — fixtures + §6.1.3 mapping prove
  conformance; a CTT run is the gold standard.
