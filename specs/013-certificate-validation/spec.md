# Feature Specification: Certificate Validation Conformance (OPC UA Part 4 §6.1.3)

**Feature Branch**: `013-certificate-validation`
**Created**: 2026-06-21
**Status**: Draft
**Input**: User description: bring X.509 ApplicationInstanceCertificate validation into conformance
with OPC UA Part 4 §6.1.3 (Table 100), on both server and client.

## User Scenarios & Testing *(mandatory)*

An OPC UA application (server or client) must decide whether the *other* application's
ApplicationInstanceCertificate is trusted before communicating. Today async-opcua only checks
trusted/rejected **folder membership** of the leaf certificate plus validity period, hostname, and
application URI. It never builds or verifies the CA **chain**, verifies **signatures** up the chain,
checks certificate **usage** (KeyUsage/ExtendedKeyUsage), or checks **revocation**. This lets
certificates that Part 4 §6.1.3 requires to be rejected (CA-signed by an untrusted/forged issuer,
wrong key usage, revoked) be accepted. This feature implements the missing Table 100 validation
steps, with the exact OPC UA status code per step, on both peers.

### User Story 1 — CA chain build + signature verification (Priority: P1) 🎯 MVP

As an administrator who trusts a Certificate Authority (places the CA in the issuer list), I want
the application to accept only certificates whose signature chains up to that trusted CA, and reject
certificates whose issuer is unknown or whose signature is forged/altered.

**Why this priority**: This is the core of §6.1.3 ("A Certificate is only trusted if its chain can
be validated") and the biggest current security gap — without it, an attacker-issued certificate is
accepted as long as someone dropped the leaf into `trusted/`. It is the foundation the other steps
build on.

**Independent Test**: Build a 2- and 3-level PKI (root CA → [intermediate CA →] leaf). With the
root/intermediate in the issuer list: a valid leaf validates; a leaf whose intermediate is missing
fails `Bad_CertificateChainIncomplete`; a leaf with a tampered signature fails `Bad_CertificateInvalid`;
a self-signed leaf in `trusted/` still validates (it is its own issuer).

**Acceptance Scenarios**:

1. **Given** a leaf cert signed by a CA present in the issuer list and reachable to a self-signed
   root, **When** the cert is validated, **Then** the chain builds and every signature verifies and
   the cert is accepted.
2. **Given** a leaf cert whose issuing CA is not available in the issuer/trusted lists nor supplied
   with the cert, **When** validated, **Then** it is rejected with `Bad_CertificateChainIncomplete`.
3. **Given** a cert whose signature does not verify against its issuer's public key, **When**
   validated, **Then** it is rejected with `Bad_CertificateInvalid`.
4. **Given** an administrator who placed a self-signed application cert directly in `trusted/`,
   **When** validated, **Then** it still validates (backward compatibility with the common
   self-signed deployment is preserved).

---

### User Story 2 — Certificate usage (KeyUsage / ExtendedKeyUsage) (Priority: P2)

As an administrator, I want certificates that are not marked for the use being requested
(application authentication vs CA signing) to be rejected, so a key issued for one purpose cannot be
misused for another.

**Why this priority**: Cheap to add once the chain exists; closes a real misuse gap (e.g. an
encryption-only or CA cert used as an application instance cert).

**Independent Test**: Validate certs with correct, wrong, and missing KeyUsage/EKU and confirm the
mapping: an application cert lacking the required usage → `Bad_CertificateUseNotAllowed`; a chain CA
lacking `keyCertSign` → `Bad_CertificateIssuerUseNotAllowed`.

**Acceptance Scenarios**:

1. **Given** an application instance cert without the KeyUsage/EKU required for application
   authentication, **When** validated, **Then** it is rejected with `Bad_CertificateUseNotAllowed`.
2. **Given** a chain CA certificate lacking CA key usage (`keyCertSign`/basicConstraints CA), **When**
   the chain is validated, **Then** it is rejected with `Bad_CertificateIssuerUseNotAllowed`.

---

### User Story 3 — Revocation checking via CRL (Priority: P2)

As an administrator, I want revoked certificates rejected (and missing revocation information
flagged), so a compromised key whose certificate has been revoked can no longer authenticate.

**Why this priority**: Real security value (revocation after key compromise), but more involved
(CRL parsing, the "revocation unknown" vs "disabled per-CA" semantics).

**Independent Test**: With a CRL listing a leaf's serial, the leaf → `Bad_CertificateRevoked`; a CA's
serial on the issuer CRL → `Bad_CertificateIssuerRevoked`; a CA with revocation enabled but no CRL
present → `Bad_CertificateRevocationUnknown`; the same CA with revocation disabled by the admin →
no error.

**Acceptance Scenarios**:

1. **Given** a CRL (in the trusted/issuer CRL store) that lists the leaf certificate's serial number,
   **When** the leaf is validated, **Then** it is rejected with `Bad_CertificateRevoked`.
2. **Given** a CA in the chain whose serial appears on its issuer's CRL, **When** validated, **Then**
   it is rejected with `Bad_CertificateIssuerRevoked`.
3. **Given** a CA for which revocation checking is enabled but no CRL is available, **When** validated,
   **Then** the result is `Bad_CertificateRevocationUnknown` (suppressible).
4. **Given** the administrator disabled revocation checking for a CA, **When** validated, **Then** the
   Find-Revocation-List step does not error.

---

### User Story 4 — Security-policy key checks + suppression & audit (Priority: P3)

As an administrator, I want the certificate's signature algorithm and key length to be checked
against the negotiated SecurityPolicy, and I want to be able to *suppress* non-critical validation
failures (with every suppression recorded in the audit log), per §6.1.3.

**Why this priority**: Completes Table 100 (Security Policy Check) and the spec's
suppressible/critical-error + audit model. Lower priority because the chain/usage/revocation checks
deliver most of the security value first.

**Independent Test**: A cert whose key length is below the policy minimum → `Bad_CertificatePolicyCheckFailed`;
with that error configured as suppressed, validation passes but an `AuditCertificateInvalid`-class
event is raised. Confirm the critical steps (structure, chain, signature, untrusted, URI) cannot be
suppressed.

**Acceptance Scenarios**:

1. **Given** a cert whose asymmetric key length is outside the min/max for the negotiated
   SecurityPolicy, **When** validated, **Then** it is rejected with `Bad_CertificatePolicyCheckFailed`.
2. **Given** an administrator suppression configured for a non-critical step that fails, **When**
   validated, **Then** validation passes AND a corresponding `AuditCertificate*` event is raised.
3. **Given** a failure in a critical step (structure / chain / signature / untrusted / URI), **When**
   validated, **Then** it is rejected regardless of suppression configuration.

---

### User Story 5 — Configuration, rollout & backward compatibility (Priority: P3)

As an operator of an existing deployment, I want the new validation to be configurable and to not
silently break my current setup, with a clear default and documentation.

**Why this priority**: Adoption/safety. Existing self-signed-in-`trusted/` deployments must keep
working; CA-based deployments gain the new behavior.

**Independent Test**: A server/client configured for the existing trust-list model with self-signed
certs connects exactly as before; toggling the validation policy changes enforcement as documented;
the `None` security policy path is unchanged.

**Acceptance Scenarios**:

1. **Given** an existing deployment using self-signed certs in `trusted/`, **When** upgraded, **Then**
   connections succeed unchanged.
2. **Given** the validation policy configuration, **When** an administrator adjusts which steps are
   enforced/suppressed and whether revocation is required, **Then** behavior matches the configuration.

### Edge Cases

- A certificate supplies its own issuer chain on the wire — chain building must use it but still
  anchor trust in the administrator's lists (an attacker-supplied chain to an untrusted root is
  rejected `Bad_CertificateUntrusted`).
- A malformed certificate or CRL (truncated, wrong DER, absurd field lengths) must be rejected with a
  protocol error and **never panic** (this input is attacker-controlled / fuzzable).
- A chain with a cycle, or excessive depth, must terminate and be rejected (no unbounded work).
- `basicConstraints` pathLen exceeded → chain invalid.
- A leaf that is BOTH self-signed and in `trusted/` validates without needing an external issuer.
- HostName check applies only to **server** application instance certs (skipped for client certs and
  CA certs); URI check applies to application instance certs and is not suppressible.

## Requirements *(mandatory)*

### Functional Requirements

Validation MUST follow OPC UA Part 4 §6.1.3 Table 100 steps, in order, repeated for each certificate
in the chain, halting on the first non-suppressed error.

- **FR-001**: The system MUST verify the certificate **structure**; a structurally invalid cert is
  rejected with `Bad_CertificateInvalid` (not suppressible). Malformed input MUST NOT panic.
- **FR-002**: The system MUST **build the certificate chain** from the leaf back to a self-signed root
  using the administrator's trusted-certificate and issuer-certificate (CA) lists (and any chain
  certs supplied with the certificate); an incomplete chain is rejected with
  `Bad_CertificateChainIncomplete` (not suppressible).
- **FR-003**: The system MUST **verify the signature** of each certificate against its issuer's public
  key (a self-signed certificate is its own issuer); an invalid signature is rejected with
  `Bad_CertificateInvalid` (not suppressible).
- **FR-004**: The system MUST perform the **Security Policy Check** — the certificate's signature
  algorithm and asymmetric key length conform to the negotiated SecurityPolicy's
  CertificateSignatureAlgorithm / Min / MaxAsymmetricKeyLength; failure → `Bad_CertificatePolicyCheckFailed`
  (suppressible).
- **FR-005**: The system MUST perform the **Trust List Check** — the certificate or at least one CA in
  its chain is in the trusted list; otherwise `Bad_CertificateUntrusted` (not suppressible).
- **FR-006**: The system MUST check the **validity period** of the certificate and its issuers
  (`Bad_CertificateTimeInvalid` / `Bad_CertificateIssuerTimeInvalid`, suppressible).
- **FR-007**: The system MUST check the **host name** for **server** application instance certificates
  only (skipped for client and CA certs) → `Bad_CertificateHostNameInvalid` (suppressible).
- **FR-008**: The system MUST check the application/product **URI** against the ApplicationDescription
  for application instance certs → `Bad_CertificateUriInvalid` (not suppressible).
- **FR-009**: The system MUST check **certificate usage** (KeyUsage / ExtendedKeyUsage, and CA
  basicConstraints for issuers) per the requested use (application vs CA) →
  `Bad_CertificateUseNotAllowed` / `Bad_CertificateIssuerUseNotAllowed` (suppressible unless the
  certificate marks the usage mandatory).
- **FR-010**: The system MUST **find the revocation list** for each CA (unless revocation is disabled
  for that CA by the administrator); if revocation is required but no CRL is available →
  `Bad_CertificateRevocationUnknown` / `Bad_CertificateIssuerRevocationUnknown` (suppressible).
- **FR-011**: The system MUST perform the **revocation check** against available CRLs per RFC 5280
  §6.3; a revoked certificate → `Bad_CertificateRevoked` / `Bad_CertificateIssuerRevoked`.
- **FR-012**: The system MUST support administrator **suppression** of the non-critical steps
  (security-policy, validity, host name, certificate usage, find-revocation-list); suppressed failures
  MUST still raise the corresponding `AuditCertificate*` event. The critical steps (structure,
  build-chain, signature, untrusted, URI) MUST NOT be suppressible.
- **FR-013**: The same validation MUST be applied by the **server** (validating client application
  certificates) and the **client** (validating server application certificates).
- **FR-014**: Existing **trust-list-only** deployments using self-signed application certificates
  placed in `trusted/` MUST continue to connect unchanged; the validation policy MUST be configurable
  with a safe, documented default, and the `None` security policy path MUST be byte-identical.
- **FR-015**: All validation MUST be **fail-closed** and panic-free on attacker-supplied certificates,
  chains, and CRLs, with bounded work (no unbounded chain depth / cycles).

### Key Entities *(include if feature involves data)*

- **Trusted certificate list**: administrator-controlled set of explicitly trusted certificates (may
  be leaf application certs or CA certs); the trust anchor.
- **Issuer (CA) certificate list**: CA certificates available for chain building that are not
  themselves directly trusted.
- **Certificate Revocation List (CRL)**: per-CA list of revoked serial numbers (trusted/issuer CRL
  stores), with the issuing CA, this-update/next-update, and revoked entries.
- **Certificate chain**: the ordered set leaf → … → self-signed root assembled during validation.
- **Validation policy / configuration**: which steps are enforced vs suppressed, whether revocation is
  required (globally / per-CA), and the overall enforcement mode.
- **Certificate audit event**: the `AuditCertificate*` event raised for failures (including
  suppressed ones).

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: All eleven Part 4 §6.1.3 Table 100 steps are enforced in order, each producing its exact
  OPC UA status code, verified by crafted-fixture tests (valid chain; missing intermediate; bad
  signature; expired leaf and expired issuer; wrong/missing KeyUsage and EKU; key length out of
  policy; revoked-via-CRL leaf and CA; revocation-unknown; untrusted root).
- **SC-002**: A certificate that should be rejected under §6.1.3 (untrusted-issuer, forged signature,
  wrong usage, revoked) is rejected — none are accepted — across the fixture suite.
- **SC-003**: Malformed certificates and CRLs are rejected without any panic (validated by negative
  and fuzz tests over the cert/CRL decode + chain-build paths).
- **SC-004**: Existing self-signed-in-`trusted/` deployments connect unchanged (regression test), and
  the `None`-policy wire path is byte-identical.
- **SC-005**: Suppression works — a configured-suppressed non-critical failure passes validation while
  raising the corresponding audit event; critical steps cannot be suppressed.
- **SC-006**: `cargo clippy --all-targets --all-features` is clean and the full unit + integration
  suites pass; no new C-toolchain dependency is introduced.

## Assumptions

- **Trust model preserved**: Trust is anchored in the administrator's trusted + issuer certificate
  lists (§6.1.3). Self-signed application certificates placed directly in `trusted/` remain trusted
  (a self-signed cert is its own issuer, so its chain validates).
- **Default enforcement** [DECISION — confirm at plan]: full chain + signature + usage validation is
  ON by default (it is the conformant behavior and self-signed deployments are unaffected); revocation
  is checked when CRLs are present / required and skipped when the administrator disables it or no CRL
  store is configured (lenient-by-default for revocation to avoid breaking CRL-less deployments).
- **Pure-Rust**: reuse the already-vendored `x509-cert` for certificate/CRL parsing and the existing
  RSA/ECDSA verification primitives; no OpenSSL / C-toolchain dependency is added.
- **CRL only** for revocation in this feature; **OCSP is out of scope** (deferred).
- **Out of scope / deferred**: GDS/CA certificate issuance; the mixed RSA+ECC multi-cert server (see
  feature 012 research.md); and the session-activation hardening TODOs (endpoint-URL vs server-cert
  hostname at CreateSession; binding the client certificate / user identity token to the secure
  channel) — tracked as a separate feature.
- **Verification division**: coding goes to codex (implementation only); Claude authors and runs all
  tests independently against crafted PKI fixtures and the exact §6.1.3 status-code mapping.
