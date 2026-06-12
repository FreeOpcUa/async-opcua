# Feature Specification: First-Class Legacy Crypto Support

**Feature Branch**: `008-first-class-legacy`
**Created**: 2026-06-12
**Status**: Draft
**Input**: User description: "first class legacy crypto support"

## Context

The deprecated OPC UA security policies Basic128Rsa15 and Basic256 are fully
implemented in `async-opcua-crypto` but hidden behind the compile-time
`legacy-crypto` feature, which is off by default. The current state has four
defects that make legacy interop a second-class experience:

1. **Panics instead of errors**: without the feature, every method on
   `SecurityPolicy::Basic128Rsa15`/`Basic256` panics (`call_with_policy!`),
   so a server *config* naming a legacy endpoint takes the process down.
2. **`allow_legacy_crypto` is a dead switch**: the server config field and
   builder setter exist but are never read by any enforcement point.
3. **No client-side control**: a client cannot opt into or be warned about
   legacy endpoints; connecting to plant-floor gear that only offers
   Basic128Rsa15 requires a custom build.
4. **No observability**: `SecurityPolicy::is_deprecated()` exists but is
   never used to warn or filter anywhere.

Industrial reality (the motivating use case): brewery/dairy-floor equipment
and older PLC OPC UA servers frequently offer only Basic128Rsa15 or Basic256.
Talking to them must be a runtime decision with a visible audit trail, not a
rebuild.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Runtime-controlled legacy support, compiled in by default (Priority: P1)

As an integrator, I build the standard crates and decide **at runtime via
configuration** whether legacy security policies are available, with the
secure choice (disabled) as the default.

**Why this priority**: this is the core re-architecture: `legacy-crypto`
becomes a default-on feature of the crypto crate (and the umbrella), and
availability moves to runtime config. Everything else builds on it.

**Independent Test**: build with default features; a server configured with a
Basic256 endpoint and `allow_legacy_crypto: true` serves it; the same config
with `allow_legacy_crypto: false` (default) rejects it at config validation
with a clear error naming the switch — no panic in either case.

**Acceptance Scenarios**:

1. **Given** default-feature build, **When** a server endpoint uses
   Basic128Rsa15 and `allow_legacy_crypto` is true, **Then** the endpoint is
   served and clients can connect with Sign and SignAndEncrypt.
2. **Given** default-feature build, **When** a server endpoint uses a legacy
   policy and `allow_legacy_crypto` is false, **Then** config validation
   fails with an error that names `allow_legacy_crypto`, and the server does
   not start.
3. **Given** a build with the `legacy-crypto` feature disabled, **When** any
   code path touches a legacy policy, **Then** it receives an error result
   (config validation error or `BadSecurityPolicyRejected`), never a panic.

---

### User Story 2 - Server enforcement and endpoint filtering (Priority: P1)

As a server operator, legacy endpoints are invisible and unusable unless I
explicitly allowed them: GetEndpoints does not advertise them, and a secure
channel open targeting a legacy policy is rejected at the protocol level.

**Why this priority**: defense in depth — config validation alone does not
cover a client *asking* for a legacy policy against a non-legacy endpoint
list, and discovery must not advertise what the server will refuse.

**Independent Test**: with `allow_legacy_crypto: false`, GetEndpoints returns
no legacy endpoint descriptions and an OpenSecureChannel with a legacy policy
URI fails with `BadSecurityPolicyRejected`; flipping the switch makes both
work.

**Acceptance Scenarios**:

1. **Given** a running server with legacy disallowed, **When** a client sends
   OpenSecureChannel with the Basic128Rsa15 URI, **Then** the server responds
   with `BadSecurityPolicyRejected` and stays healthy.
2. **Given** a running server with legacy allowed, **When** GetEndpoints is
   called, **Then** legacy endpoint descriptions are included.

---

### User Story 3 - Client-side opt-in and deprecation warnings (Priority: P2)

As a client author, I opt into legacy policies via `ClientConfig`
(`allow_legacy_crypto`, default false) or the builder; connecting to or
selecting a legacy endpoint without opting in fails with a clear error, and
every legacy connection logs a deprecation warning.

**Why this priority**: clients are how legacy gear is reached in practice;
without client control the runtime story is server-only.

**Independent Test**: a client without the opt-in refuses to connect to a
legacy-only test server with an actionable error; with the opt-in it
connects and a `WARN` log records the deprecated policy use (on both client
and server).

**Acceptance Scenarios**:

1. **Given** a client with default config, **When** it attempts
   `connect_to_matching_endpoint` with a Basic256 policy, **Then** the
   connection attempt fails before any network traffic with an error naming
   `allow_legacy_crypto`.
2. **Given** a client with `allow_legacy_crypto: true`, **When** it connects
   to a Basic128Rsa15 endpoint, **Then** the connection succeeds and a
   deprecation warning is logged once per session.

---

### User Story 4 - Documentation and compliance story (Priority: P3)

As an evaluator, the docs tell me exactly how deprecated profiles are
handled: compiled in, disabled at runtime by default, how to enable them on
each side, and what gets logged.

**Independent Test**: docs/crypto.md (or compatibility.md) documents the
feature flag, both config switches, the rejection status code, and the
deprecation warnings.

**Acceptance Scenarios**:

1. **Given** the rendered docs, **When** searching for Basic128Rsa15,
   **Then** the runtime-control story is fully described.

---

### Edge Cases

- Config file written for an older version (no `allow_legacy_crypto` key):
  serde default (false) applies on both client and server.
- Build with `default-features = false` (no `legacy-crypto`): legacy URIs
  parse to `SecurityPolicy::Unknown` for remote input; config naming legacy
  policies fails validation with a message that says the build lacks the
  feature; nothing panics.
- A `password_security_policy` naming a legacy policy follows the same
  allow/deny rules as endpoint policies.
- Discovery clients listing a legacy-only server still see its endpoints
  (reading descriptions is not using the policy); only *use* is gated.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The `legacy-crypto` feature MUST be enabled by default on
  `async-opcua-crypto` and forwarded by default from the `async-opcua`
  umbrella, while remaining disableable via `default-features = false`.
- **FR-002**: No code path may panic because a legacy policy is referenced
  while the feature is disabled; all such paths MUST return errors
  (`EncodingResult`/`StatusCode::BadSecurityPolicyRejected`/config errors).
- **FR-003**: Server config validation MUST reject endpoints (including
  `password_security_policy`) using legacy policies unless
  `allow_legacy_crypto` is true, with an error naming the switch.
- **FR-004**: The server MUST NOT advertise legacy endpoints via
  GetEndpoints/CreateSession endpoint lists when `allow_legacy_crypto` is
  false, and MUST reject OpenSecureChannel requests for legacy policy URIs
  with `BadSecurityPolicyRejected` in that case.
- **FR-005**: `ClientConfig` MUST gain `allow_legacy_crypto: bool`
  (serde-default false) plus a `ClientBuilder::allow_legacy_crypto` setter;
  endpoint selection and connection establishment MUST reject legacy
  policies with a clear error when false.
- **FR-006**: Both client and server MUST log a `warn!`-level deprecation
  message when a connection actually uses a legacy policy.
- **FR-007**: `SecurityPolicy::is_deprecated()` MUST be the single source of
  truth for "is this policy legacy" in all new checks.
- **FR-008**: Existing tests MUST keep passing; tests that previously needed
  `--features legacy-crypto` to cover legacy policies SHOULD work with
  default features (the explicit feature plumbing added for CI may be
  simplified but MUST NOT break `default-features = false` builds, which CI
  MUST continue to lint).

### Key Entities

- **SecurityPolicy** (crypto): policy enum; `is_deprecated()` drives gating.
- **ServerConfig.allow_legacy_crypto** (existing, dead) → becomes enforced.
- **ClientConfig.allow_legacy_crypto** (new).

## Success Criteria *(mandatory)*

- **SC-001**: Default-feature build connects client↔server over
  Basic128Rsa15 and Basic256 (Sign and SignAndEncrypt) when both sides opt
  in at runtime; the dotnet cross-implementation matrix passes without
  feature flags.
- **SC-002**: With defaults (no opt-in), a legacy OpenSecureChannel attempt
  is rejected with `BadSecurityPolicyRejected` and the server process
  survives; fuzz/robustness behavior unchanged.
- **SC-003**: `cargo test --workspace` (default features) and
  `cargo clippy --no-default-features` variants stay green; no panic sites
  remain for legacy policies in any feature combination.
- **SC-004**: Deprecation warnings appear exactly once per
  connection/session using a legacy policy.

## Assumptions

- Compiling the legacy algorithms in by default is acceptable because
  availability is runtime-gated off by default (matches the upstream
  project's OpenSSL-era behavior and the needs of industrial users).
- `BadSecurityPolicyRejected` is the appropriate status code for refused
  legacy policy use at the protocol level.
- The `Unknown` policy panic (`call_with_policy!`) is out of scope except
  where reachable via legacy paths; it predates this feature.
