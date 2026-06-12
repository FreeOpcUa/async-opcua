# Tasks: First-Class Legacy Crypto Support

**Input**: Design documents from `/specs/008-first-class-legacy/`
**Prerequisites**: plan.md, spec.md

## Format: `[ID] [P?] [Story] Description`

## Phase 1: Setup

- [X] T001 Flip feature defaults: `default = ["legacy-crypto"]` in `async-opcua-crypto/Cargo.toml`, add `legacy-crypto` to the umbrella default set in `async-opcua/Cargo.toml`; verify `cargo check` for default and `--no-default-features` builds.

## Phase 2: Foundational (Blocking Prerequisites)

- [X] T002 Ungate identity paths in `async-opcua-crypto/src/security_policy.rs`: `from_uri`/`from_str` recognize legacy URIs in all builds, `to_uri`/`to_str`/`as_str`/`is_deprecated` work without the feature (constants need no crypto), so legacy policies can be named in errors instead of mapping to `Unknown`.
- [X] T003 Remove reachable panics for legacy policies without the feature in `async-opcua-crypto`: Result-returning operations return `Err(BadSecurityPolicyRejected)` from the no-feature arm; remaining infallible crypto accessors are made unreachable by entry-point gating and documented as such.

## Phase 3: User Story 1 - Runtime control, compiled in by default (P1)

- [X] T004 [US1] Enforce `allow_legacy_crypto` in server config validation: `ServerEndpoint::validate` (endpoint policy and `password_security_policy`) gains the allow flag, `ServerConfig::validate` passes it, error messages name the switch (`async-opcua-server/src/config/endpoint.rs`, `config/server.rs`).
- [X] T005 [US1] Unit tests for config validation: legacy allowed, legacy rejected by default, feature-off message (`async-opcua-server/src/config/`).
- [X] T006 [US1] Update the umbrella `Tester` harness to set `allow_legacy_crypto(true)` so the existing legacy connect matrix passes on default features (`async-opcua/tests/utils/tester.rs`).

## Phase 4: User Story 2 - Server enforcement and filtering (P1)

- [ ] T007 [US2] Filter deprecated endpoints from `ServerInfo::new_endpoint_descriptions` and `endpoint_exists` when legacy is not allowed (`async-opcua-server/src/info.rs`).
- [ ] T008 [US2] Reject OpenSecureChannel with a legacy policy URI when not allowed: thread the allow flag into the server secure-channel acceptance path, respond `BadSecurityPolicyRejected` (`async-opcua-core/src/comms/secure_channel.rs`, `async-opcua-server/src/transport/`, `session/controller.rs` as needed).
- [ ] T009 [US2] Integration tests: legacy OSC rejected when disallowed / accepted when allowed; GetEndpoints filtering (`async-opcua/tests/integration/`).

## Phase 5: User Story 3 - Client opt-in and warnings (P2)

- [ ] T010 [US3] Add `ClientConfig.allow_legacy_crypto` (serde default false) + `ClientBuilder::allow_legacy_crypto` (`async-opcua-client/src/config.rs`, `builder.rs`).
- [ ] T011 [US3] Enforce the client switch before any network I/O: endpoint matching in `SessionBuilder`/`connect_to_*` and `AsyncSecureChannel::connect` (`async-opcua-client/src/session/connection.rs`, `transport/channel.rs`).
- [ ] T012 [US3] Log one `warn!` deprecation message per established connection using a legacy policy, on both client and server.
- [ ] T013 [US3] Integration tests: client refuses legacy endpoint without opt-in (error names the switch, no traffic); connects with opt-in (`async-opcua/tests/integration/`).

## Phase 6: User Story 4 - Documentation (P3)

- [ ] T014 [US4] Document the runtime-control story: feature flag, both switches, rejection status code, warnings (`docs/crypto.md`, `docs/compatibility.md`, `CHANGELOG.md`).
- [ ] T015 [US4] Update the dotnet harness to rely on default features + runtime opt-in (`dotnet-tests/external-tests/Cargo.toml`, fixture config).

## Phase 7: Polish & Cross-Cutting

- [ ] T016 Full verification: `cargo test --workspace` (default features), `cargo test --workspace --all-features`, all four CI clippy commands, `--no-default-features` check stays panic-free.
- [ ] T017 Cleanup: simplify now-redundant explicit `legacy-crypto` test plumbing where safe; confirm SC-004 (single warning per connection).

## Dependencies

- Phase 2 blocks all user stories. US1 (T004-T006) blocks US2 protocol tests
  (the harness change). US3 is independent of US2. Polish last.
