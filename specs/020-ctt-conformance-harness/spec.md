# Feature Specification: OPC UA Conformance Test Harness (CTT)

**Feature Branch**: `020-ctt-conformance-harness`
**Created**: 2026-06-22
**Status**: Draft
**Input**: Build a conformance test harness for async-opcua (user chose the full package): a runnable CI
conformance smoke, an extended demo-server (ECC profile), and a UACTT run guide + scripts.

## Context *(mandatory)*

The OPC Foundation Compliance Test Tool (UACTT) is the authoritative conformance suite, but it is a
proprietary **Windows GUI** tool (requires OPC Foundation membership) and **cannot run in this Linux/CI
environment**. This feature delivers a runnable **proxy** for it plus the setup material to run the real
thing:

1. A **CI conformance smoke** that drives our server with our client across the full matrix of security
   policy × security mode × identity-token type, performing representative conformance operations — a
   regression guard that actually runs here.
2. An **extended demo-server** so it can be a complete UACTT target, including a separate **ECC profile**.
3. A **run guide + scripts** for pointing the real UACTT at the demo-server, with an expected-results /
   known-gaps table.

**Hard constraint**: a server has a single ApplicationInstance certificate, and an RSA certificate cannot
perform ECDSA, so one server cannot serve both RSA and ECC policies. The deferred "mixed RSA+ECC
multi-cert server" (feature 012) **stays deferred**; ECC coverage is a **separate server profile** with
its own EC certificate.

## User Scenarios & Testing *(mandatory)*

### User Story 1 — CI conformance smoke across the full matrix (Priority: P1) 🎯 MVP

As a maintainer, I want an automated, CI-runnable test that connects to our server over **every**
supported (security policy × security mode × identity-token) combination and exercises the core services,
so conformance regressions are caught here without the Windows UACTT.

**Why this priority**: It is the only part that actually runs in this environment and guards against
regressions; it is the MVP value.

**Independent Test**: A single `cargo test` run brings up the server(s) and, for each matrix cell,
connects + activates, performs Read / Write / Browse (or TranslateBrowsePath) / a Subscription +
MonitoredItem data-change / clean disconnect, and asserts each operation succeeds (or fails with the
correct StatusCode where a combination is expected to be rejected). Any cell that does not work is
surfaced as a failure, not skipped.

**Acceptance Scenarios**:

1. **Given** the RSA-family endpoints (incl. `None`) with anonymous / user-password / x509 tokens, **When**
   the smoke runs, **Then** every valid combination connects, activates, and completes Read/Write/Browse/
   Subscribe successfully; bad credentials are rejected with the appropriate StatusCode.
2. **Given** the ECC endpoints (`ECC_nistP256`/`ECC_nistP384`, Sign + SignAndEncrypt) on the ECC server
   profile with anonymous / user-password / x509 tokens, **When** the smoke runs, **Then** every valid
   combination completes the same operations.
3. **Given** a combination that should be rejected (e.g. wrong password, or a `Sign`-only token policy
   mismatch), **When** attempted, **Then** it fails with the documented StatusCode (no panic, no hang).

---

### User Story 2 — Demo-server full coverage incl. a dedicated ECC profile (Priority: P2)

As someone running the real UACTT, I want the demo-server to expose the complete policy/mode/token matrix
the CTT exercises, including ECC, so I can run the full suite against it.

**Why this priority**: Required so the (manual) UACTT can exercise everything, and it backs the ECC half
of the CI smoke.

**Independent Test**: The demo-server's existing RSA profile advertises every security policy/mode with
anonymous + user-password + x509 tokens (incl. a `None` endpoint); a new **ECC profile**
(`sample.server.ecc.conf` + EC app-cert provisioning) advertises `ECC_nistP256`/`ECC_nistP384`
(Sign + SignAndEncrypt) with the same token types, selectable via an arg/env, and the default behavior is
unchanged (RSA profile remains default).

**Acceptance Scenarios**:

1. **Given** the demo-server with no extra args, **When** started, **Then** it serves the existing RSA
   profile exactly as today (no regression).
2. **Given** the ECC profile selected (arg/env), **When** started, **Then** it provisions an EC
   application certificate and serves the ECC endpoints with all token types.
3. **Given** the RSA profile, **When** inspected, **Then** every endpoint offers anonymous + user-password
   + x509 tokens and the policy/mode set covers what the CTT exercises (gaps filled).

---

### User Story 3 — UACTT run guide + launch/cert scripts (Priority: P2)

As a conformance tester with a Windows UACTT license, I want a guide and helper scripts to stand up the
demo-server, provision/cross-trust certificates, point UACTT at each endpoint, and know which failures
are expected, so a real CTT run is reproducible.

**Why this priority**: Turns the (manual) UACTT into a repeatable process and records which Tier 3 gaps
fail by design.

**Independent Test**: `docs/ctt-conformance.md` documents building/running both profiles, cert
provisioning + cross-trust, the UACTT endpoint/test-group setup, and an expected-results / known-gaps
table; a shell script boots a chosen profile with a clean PKI and prints the endpoint URLs + cert
thumbprints to trust.

**Acceptance Scenarios**:

1. **Given** the guide, **When** followed on Windows with a UACTT license, **Then** a tester can launch a
   profile, trust certs, and configure UACTT against the endpoints without guesswork.
2. **Given** the known-gaps table, **When** a UACTT run reports failures, **Then** the tester can tell
   which are expected (Tier 3 facets: NodeManagement read-only → `BadServiceUnsupported`; Query over
   CoreNodeManager; Discovery LDS stubs; Method Call / Audit partial) versus real defects.
3. **Given** the launch script, **When** run with a profile name, **Then** it starts the server with a
   clean PKI and prints the endpoint URLs + the server cert thumbprint to trust in UACTT.

---

### User Story 4 — Smoke coverage documentation (Priority: P3)

As a maintainer, I want the CI smoke to clearly document what it does and does **not** cover relative to
the real UACTT, so it isn't mistaken for an authoritative conformance pass.

**Independent Test**: The smoke (and/or the guide) states it uses our own client (not an independent
authority), is a regression/smoke proxy, and lists the service areas it exercises vs the UACTT groups it
does not.

**Acceptance Scenarios**:

1. **Given** the smoke harness, **When** read, **Then** it documents its proxy nature and coverage
   boundaries (our-client-not-independent; services exercised; UACTT-only areas).

### Edge Cases

- A matrix cell that is invalid by policy (e.g. token security-policy vs channel mismatch) → rejected with
  the correct StatusCode, surfaced (not silently skipped).
- ECC + RSA cannot coexist on one server cert → the smoke uses two server instances; the guide states this.
- The smoke must be reliable under the known integration-suite parallel-load flakiness → run isolated /
  single-threaded if needed (per project practice).
- The real UACTT cannot run in CI → the smoke is explicitly a proxy; the guide covers the manual run.

## Requirements *(mandatory)*

- **FR-001**: A CI-runnable conformance smoke MUST connect to our server over every supported (security
  policy × security mode × identity-token type) combination — including `None`, the RSA-family policies,
  and `ECC_nistP256`/`ECC_nistP384` — and for each valid cell perform connect+activate, Read, Write,
  Browse (or TranslateBrowsePath), a Subscription + MonitoredItem data-change, and a clean disconnect,
  asserting success.
- **FR-002**: The smoke MUST assert that invalid combinations (bad credentials, policy/token mismatch) are
  rejected with the documented StatusCode, and MUST surface (fail on) any combination that does not work
  — never silently skip.
- **FR-003**: The smoke MUST run in CI on Linux (no Windows/UACTT dependency), reusing the existing
  integration-test harness; it MUST be reliable under parallel-load flakiness (isolated/single-thread as
  needed).
- **FR-004**: The demo-server MUST gain a separate **ECC profile** (config + EC application-cert
  provisioning) advertising `ECC_nistP256`/`ECC_nistP384` (Sign + SignAndEncrypt) with anonymous +
  user-password + x509 tokens, selectable via arg/env, WITHOUT changing the default (RSA) behavior.
- **FR-005**: The demo-server RSA profile MUST expose the full policy/mode/token matrix the CTT exercises
  (every endpoint offering all three token types; a `None` endpoint present); small gaps filled.
- **FR-006**: `docs/ctt-conformance.md` MUST document running both profiles, cert provisioning +
  cross-trust, UACTT setup (endpoints + applicable test groups), and an expected-results / known-gaps
  table mapping the Tier 3 facets that fail by design.
- **FR-007**: A launch/cert-provisioning shell script MUST boot a chosen profile with a clean PKI and print
  the endpoint URLs + server cert thumbprint to trust.
- **FR-008**: No new library runtime dependency; the smoke is a test, the script is shell; the
  mixed-RSA+ECC single-cert server stays deferred; `cargo clippy --all-targets --all-features` clean;
  existing suites pass.

### Key Entities *(include if feature involves data)*

- **Conformance matrix cell**: (security policy, security mode, identity-token type) + expected outcome
  (accept / reject-with-StatusCode).
- **Server profile**: a (config, application certificate) pair — `rsa` (default, existing) and `ecc` (new,
  EC cert).
- **Known-gap entry**: a Tier 3 facet + the StatusCode/behavior the UACTT will see + why it is expected.

## Success Criteria *(mandatory)*

- **SC-001**: A single `cargo test` invocation runs the conformance smoke green across the full RSA + ECC
  matrix (every valid policy/mode/token cell exercises Read/Write/Browse/Subscribe), on Linux, with no
  UACTT/Windows dependency.
- **SC-002**: Invalid cells (bad credentials, policy/token mismatch) are rejected with the documented
  StatusCode; no matrix cell is silently skipped; no panic/hang.
- **SC-003**: The demo-server runs the existing RSA profile unchanged by default and a new ECC profile on
  request (EC cert, ECC endpoints, all token types).
- **SC-004**: `docs/ctt-conformance.md` + the launch script let a Windows UACTT user reproducibly stand up
  and target the server, with a known-gaps table distinguishing expected vs real failures.
- **SC-005**: `cargo clippy --all-targets --all-features` clean; no new library dependency; existing
  integration + unit suites pass.

## Assumptions

- **Smoke = in-process matrix** using the existing `Tester` harness (async-opcua/tests/utils) and the
  patterns in `tests/integration/*.rs` (e.g. `ecc.rs`, `core_tests.rs`), not spawning the demo-server
  binary — the runnable interpretation. The demo-server binary profiles (US2) are for the real UACTT.
- **ECC = separate server** (single-cert constraint). RSA and ECC are exercised as two server instances.
- **The real UACTT is out of CI** — proprietary + Windows; the smoke is a proxy and is documented as such
  (it uses our own client, so it is not an independent conformance authority).
- **Verification division**: the CI smoke IS the conformance test → Claude authors and runs it (anchored
  to real client↔server behavior across the matrix, surfacing any broken cell); codex may implement the
  demo-server ECC profile / profile-selection and the launch script (sample/production code).
- **Out of scope / deferred**: the mixed RSA+ECC multi-cert single-server (012 deferral remains); running
  the proprietary UACTT in CI; implementing the Tier 3 facets (they remain documented known-gaps).
- **Spec source**: OPC UA conformance is defined by the UACTT + Part 7 profiles; the known-gaps map to
  `specs/conformance-gap-backlog.md`.
