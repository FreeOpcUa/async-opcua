# Implementation Plan: X.509 User Token Validation

**Branch**: `042-x509-user-token-validation` | **Date**: 2026-06-29 | **Spec**: [spec.md](./spec.md)  
**Input**: Feature specification from `/specs/042-x509-user-token-validation/spec.md`

## Summary

Close the OPC UA Part 4 gap where `X509IdentityToken` authentication verifies proof-of-possession and
then checks a configured thumbprint, but does not first validate the presented user certificate through
the trust-chain / validity / usage / revocation pipeline. The implementation will reuse the existing
certificate-chain validator, add an X.509 user-token validation path that returns suppressed findings for
audit emission, preserve valid X.509 authentication and signature-specific failures, and add focused
tests for rejected certificates, valid activation, bad signatures, and audit events.

## Technical Context

**Language/Version**: Rust 1.75+  
**Primary Dependencies**: Existing workspace crates; `async-opcua-crypto` certificate-chain validation; existing server authentication and audit modules  
**Storage**: Existing PKI trust/rejected/issuer/CRL directories; no new storage format  
**Testing**: `cargo test` against `async-opcua-server`, `async-opcua-crypto`, and targeted integration tests in `async-opcua`  
**Target Platform**: Linux CI and local developer environments  
**Project Type**: Rust workspace library/server implementation  
**Performance Goals**: No measurable throughput regression on non-X.509 authentication paths; certificate validation remains bounded by existing chain and input-size limits  
**Constraints**: Fail closed on authentication/certificate errors; no secret logging; no panics on malformed user certificate bytes; one task at a time  
**Scale/Scope**: X.509 user identity token activation only; application-instance certificate validation, username/password, issued-token, and anonymous authentication stay behaviorally unchanged except for regression coverage

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

- **Correctness Over Completion**: Pass. The feature is a correctness/security fix with explicit rejection, status-code, and audit evidence before completion.
- **Do It Right Once**: Pass. Reuses the existing certificate-chain validation path rather than adding a parallel trust shortcut.
- **Individual Task Discipline**: Pass. Tasks must be one-test/one-change oriented and independently verifiable.
- **Security Is Paramount**: Pass. The feature hardens authentication and certificate handling, and must fail closed.
- **Leave It Better Than You Found It**: Pass. The touched authentication/audit paths will gain regression tests and clearer validation boundaries.

## Project Structure

### Documentation (this feature)

```text
specs/042-x509-user-token-validation/
├── spec.md
├── plan.md
├── research.md
├── data-model.md
├── quickstart.md
├── contracts/
│   └── x509-user-token-validation.md
└── tasks.md
```

### Source Code (repository root)

```text
async-opcua-crypto/src/
├── cert_chain.rs
└── certificate_store.rs

async-opcua-server/src/
├── info.rs
├── authenticator.rs
├── session/
│   ├── audit.rs
│   └── manager.rs
└── config/
    └── server.rs

async-opcua-server/tests/
└── security_tests.rs

async-opcua/tests/
├── integration/
│   ├── adversarial.rs
│   └── conformance.rs
└── utils/
    └── tester.rs
```

**Structure Decision**: Keep the implementation inside the existing crypto, server authentication,
and audit modules. Add only focused tests to existing security/adversarial/conformance test locations
unless the first implementation task proves a dedicated integration file would be clearer.

## Complexity Tracking

> **Fill ONLY if Constitution Check has violations that must be justified**

| Violation | Why Needed | Simpler Alternative Rejected Because |
|-----------|------------|-------------------------------------|
| None | N/A | N/A |

## Phase 0 Research Summary

Research is captured in [research.md](./research.md). Key decisions:

- OPC UA Part 4 7.40.5 requires an X.509 identity token to carry a user-token signature.
- OPC UA Part 4 6.1.3 certificate validation applies before accepting a certificate-backed identity, and suppressed validation errors must still be audited.
- Use the existing certificate-chain validator and PKI store, adding a user-token-specific validation entry point that returns suppressed findings instead of only logging them.
- Preserve user-signature failures for trusted certificates with bad signatures; certificate validation failures take precedence when the certificate itself is not acceptable.

## Phase 1 Design Summary

Design artifacts:

- [data-model.md](./data-model.md) defines the X.509 identity token, validation result, configured mapping, and audit event entities.
- [contracts/x509-user-token-validation.md](./contracts/x509-user-token-validation.md) defines externally visible ActivateSession and audit behavior.
- [quickstart.md](./quickstart.md) lists targeted verification commands.

## Post-Design Constitution Check

- **Correctness Over Completion**: Pass. Contracts and tasks require negative, positive, malformed-input, and audit evidence.
- **Do It Right Once**: Pass. The plan avoids a second certificate validator and instead extends the existing chain-validation boundary.
- **Individual Task Discipline**: Pass. Task generation must keep each verification and implementation change individually scoped.
- **Security Is Paramount**: Pass. Authentication changes fail closed and preserve bounded parsing requirements.
- **Leave It Better Than You Found It**: Pass. The plan documents current behavior, desired contract, and testable closure of the audit backlog row.
