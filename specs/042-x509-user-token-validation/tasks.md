# Tasks: X.509 User Token Validation

**Input**: Design documents from `/specs/042-x509-user-token-validation/`
**Prerequisites**: [plan.md](./plan.md), [spec.md](./spec.md), [research.md](./research.md), [data-model.md](./data-model.md), [contracts/](./contracts/), [quickstart.md](./quickstart.md)

**Tests**: Required. This feature touches authentication, certificate validation, and audit behavior; regression tests must be written before implementation changes for each user story.

**Organization**: Tasks are grouped by user story to enable independently testable increments.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (US1, US2, US3)
- Include exact file paths in descriptions

## Phase 1: Setup (Shared Test Fixtures)

**Purpose**: Prepare reusable certificate/authentication fixture support without changing production behavior.

- [X] T001 Add reusable X.509 user-certificate fixture helpers for trusted, untrusted, expired, wrong-usage, incomplete-chain, and revoked credentials in `async-opcua-server/tests/security_tests.rs`
- [X] T002 [P] Add audit event capture/parsing helper coverage for certificate audit event fields in `async-opcua-server/src/session/audit.rs`

---

## Phase 2: Foundational (Certificate Validation Helper)

**Purpose**: Create the validation boundary every user story depends on.

- [X] T003 Add failing test that user identity certificate validation returns suppressed findings instead of logging only in `async-opcua-crypto/src/tests/cert_chain.rs`
- [X] T004 Implement a CertificateStore user-identity certificate validation entry point that returns suppressed findings in `async-opcua-crypto/src/certificate_store.rs`

**Checkpoint**: The crypto/store layer can validate a user identity certificate and surface suppressed findings without server authentication changes.

---

## Phase 3: User Story 1 - Reject Untrusted User Certificates (Priority: P1) - MVP

**Goal**: A configured X.509 thumbprint cannot authenticate if the presented user certificate fails certificate validation.

**Independent Test**: A server configured with the certificate thumbprint rejects ActivateSession when the presented X.509 user certificate is untrusted, expired, revoked, incomplete, or wrong-usage.

### Tests for User Story 1

- [X] T005 [US1] Add failing test `x509_user_token_untrusted_configured_thumbprint_is_rejected` in `async-opcua-server/tests/security_tests.rs`
- [X] T006 [P] [US1] Add failing test `x509_user_token_expired_configured_thumbprint_is_rejected` in `async-opcua-server/tests/security_tests.rs`
- [X] T007 [P] [US1] Add failing test `x509_user_token_wrong_usage_configured_thumbprint_is_rejected` in `async-opcua-server/tests/security_tests.rs`
- [X] T008 [P] [US1] Add failing test `x509_user_token_incomplete_or_revoked_chain_is_rejected` in `async-opcua-server/tests/security_tests.rs`
- [X] T009 [P] [US1] Add failing malformed-certificate rejection test for X.509 identity token parsing in `async-opcua-server/tests/security_tests.rs`

### Implementation for User Story 1

- [X] T010 [US1] Wire X.509 user identity authentication to validate the presented certificate before thumbprint mapping in `async-opcua-server/src/info.rs`
- [X] T011 [US1] Ensure failed X.509 user certificate validation does not assign or retain the rejected user identity in `async-opcua-server/src/session/manager.rs`

**Checkpoint**: US1 tests fail before T010/T011 and pass after them.

---

## Phase 4: User Story 2 - Preserve Valid X.509 Authentication (Priority: P2)

**Goal**: Valid X.509 user-token authentication still works, and invalid user-token signatures remain distinguishable from certificate-validation failures.

**Independent Test**: A trusted, configured X.509 user certificate with a valid signature activates successfully; the same certificate with a tampered signature fails with `BadUserSignatureInvalid`.

### Tests for User Story 2

- [X] T012 [US2] Tighten `tampered_x509_user_token_signature_is_rejected` to assert `BadUserSignatureInvalid` in `async-opcua/tests/integration/adversarial.rs`
- [X] T013 [P] [US2] Add valid trusted X.509 user-token activation regression coverage in `async-opcua/tests/integration/conformance.rs`
- [X] T014 [P] [US2] Add unsupported-endpoint X.509 identity rejection regression coverage in `async-opcua/tests/integration/core_tests.rs`

### Implementation for User Story 2

- [X] T015 [US2] Preserve exact status-code ordering for valid-certificate bad-signature and unsupported-policy paths in `async-opcua-server/src/info.rs`

**Checkpoint**: US2 tests fail before T015 where behavior is incomplete and pass after T015 without regressing US1.

---

## Phase 5: User Story 3 - Audit Certificate Validation Outcomes (Priority: P3)

**Goal**: Failed and suppressed X.509 user certificate validation findings emit matching `AuditCertificate*` events when audit monitoring is active.

**Independent Test**: Audit monitoring observes a matching certificate audit event for a hard validation failure and for each suppressed finding on a successful activation.

### Tests for User Story 3

- [X] T016 [US3] Add failing audit test for a hard X.509 user certificate validation failure in `async-opcua/tests/integration/adversarial.rs`
- [X] T017 [P] [US3] Add failing audit test for a suppressed X.509 user certificate validation finding on successful activation in `async-opcua/tests/integration/adversarial.rs`

### Implementation for User Story 3

- [X] T018 [US3] Return X.509 user certificate validation outcomes from endpoint authentication to the session layer in `async-opcua-server/src/info.rs`
- [X] T019 [US3] Dispatch `AuditCertificate*` events for hard X.509 user-token validation failures and suppressed findings in `async-opcua-server/src/session/manager.rs`
- [X] T020 [US3] Reuse or extend certificate audit event construction without secret leakage in `async-opcua-server/src/session/audit.rs`

**Checkpoint**: US3 audit tests fail before T018-T020 and pass after them without regressing US1/US2.

---

## Phase 6: Polish & Cross-Cutting Concerns

**Purpose**: Documentation, backlog closure, and full verification.

- [X] T021 Update P2-SEC-03/P2-SEC-04 status and notes in `specs/conformance-audit/FINDINGS.md`
- [X] T022 [P] Update X.509 user-token validation notes in `docs/crypto.md`
- [X] T023 Run the focused and full verification commands from `specs/042-x509-user-token-validation/quickstart.md`

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies.
- **Foundational (Phase 2)**: Depends on setup fixtures when tests need them; blocks all user stories.
- **US1 (Phase 3)**: Depends on the foundational validation helper.
- **US2 (Phase 4)**: Depends on US1 wiring so status-code ordering is tested against the new validation path.
- **US3 (Phase 5)**: Depends on foundational suppressed-findings support and US1/US2 authentication outcomes.
- **Polish (Phase 6)**: Depends on all desired user stories.

### User Story Dependencies

- **US1**: MVP; must land first because it closes the fail-closed authentication defect.
- **US2**: Follows US1 to prove valid X.509 authentication and signature errors still work.
- **US3**: Follows US1/US2 because it needs validation outcomes from the finalized authentication flow.

### Within Each User Story

- Write the named failing test first.
- Make the minimal production change needed for that test.
- Run the targeted test before starting the next task.

## Parallel Opportunities

- T002 can run in parallel with T001.
- T006, T007, T008, and T009 can run in parallel with T005 after fixture helpers exist.
- T013 and T014 can run in parallel with T012.
- T017 can run in parallel with T016.
- T022 can run in parallel with T021 after implementation is complete.

## Parallel Example: User Story 1

```bash
Task: "Add failing test x509_user_token_untrusted_configured_thumbprint_is_rejected in async-opcua-server/tests/security_tests.rs"
Task: "Add failing test x509_user_token_expired_configured_thumbprint_is_rejected in async-opcua-server/tests/security_tests.rs"
Task: "Add failing test x509_user_token_wrong_usage_configured_thumbprint_is_rejected in async-opcua-server/tests/security_tests.rs"
Task: "Add failing test x509_user_token_incomplete_or_revoked_chain_is_rejected in async-opcua-server/tests/security_tests.rs"
Task: "Add failing malformed-certificate rejection test for X.509 identity token parsing in async-opcua-server/tests/security_tests.rs"
```

## Implementation Strategy

### MVP First (US1 Only)

1. Complete setup and foundational validation helper tasks.
2. Add the failing untrusted, expired, wrong-usage, incomplete/revoked, and malformed certificate tests.
3. Wire validation into X.509 user identity authentication.
4. Stop and validate US1 before status-code polish or audit work.

### Incremental Delivery

1. US1: reject invalid certificates before user identity assignment.
2. US2: preserve valid activation and exact bad-signature behavior.
3. US3: surface hard and suppressed validation outcomes through audit events.
4. Polish: update audit backlog notes and docs, then run quickstart verification.

## Notes

- Do not batch T010/T011 with audit work; authentication correctness comes first.
- Do not emit audit events from `async-opcua-crypto`; return findings to the server layer.
- Keep certificate fixtures bounded and deterministic.
- Do not log private keys, passwords, decrypted token secrets, or raw signatures.
