# Feature Specification: External Implementation Interop Checks

**Feature Branch**: `039-external-interop-targets`  
**Created**: 2026-06-29  
**Status**: Draft  
**Input**: User description: "Reuse the existing interop/compliance harness structure to check a different OPC UA implementation in pull request CI without editing the external repository."

## User Scenarios & Testing *(mandatory)*

<!--
  IMPORTANT: User stories should be PRIORITIZED as user journeys ordered by importance.
  Each user story/journey must be INDEPENDENTLY TESTABLE - meaning if you implement just ONE of them,
  you should still have a viable MVP (Minimum Viable Product) that delivers value.
  
  Assign priorities (P1, P2, P3, etc.) to each story, where P1 is the most critical.
  Think of each story as a standalone slice of functionality that can be:
  - Developed independently
  - Tested independently
  - Deployed independently
  - Demonstrated to users independently
-->

### User Story 1 - Check an External OPC UA Server (Priority: P1)

A maintainer can point the interop checks at an already-running OPC UA server and get a clear pass/fail result for portable server behavior without requiring that server to expose async-opcua demo nodes.

**Why this priority**: This is the minimum useful outcome for evaluating projects such as micro-opcua from the async-opcua compliance harness.

**Independent Test**: Start any reachable OPC UA server that supports anonymous sessions, provide its endpoint, run the external smoke checks, and verify that only standard OPC UA behavior is evaluated.

**Acceptance Scenarios**:

1. **Given** an external server endpoint, **When** the maintainer runs the external checks, **Then** the checks connect to that endpoint and do not start the async-opcua demo server.
2. **Given** an external server that implements the portable OPC UA behaviors, **When** the maintainer runs the external checks, **Then** the result is a zero-failure pass summary.
3. **Given** an external server that rejects or mishandles a portable behavior, **When** the maintainer runs the external checks, **Then** the result identifies the failed check and exits unsuccessfully.

---

### User Story 2 - Preserve Demo-Server Interop Coverage (Priority: P2)

The existing demo-server interop checks remain the default signal for async-opcua changes, including the richer demo namespace, methods, writes, subscriptions, history, and security matrix.

**Why this priority**: The external checks must not dilute the conformance signal already used for async-opcua itself.

**Independent Test**: Run the existing interop commands without an external endpoint and verify they still launch the demo server and complete the full demo-server suite.

**Acceptance Scenarios**:

1. **Given** no external endpoint, **When** the normal interop workflow runs, **Then** it starts the async-opcua demo server and executes the existing full checks.
2. **Given** an external endpoint, **When** the maintainer requests external checks, **Then** the portable profile is used unless the maintainer explicitly chooses otherwise.

---

### User Story 3 - Reuse the Checks in Pull Request CI (Priority: P3)

A maintainer can trigger the interop checks from CI by supplying an endpoint for a separately built implementation, while the target implementation's repository remains untouched.

**Why this priority**: This makes cross-project regression checks repeatable during review while keeping the async-opcua repository the single owner of the harness.

**Independent Test**: Invoke the reusable workflow with an external endpoint and verify that the external checks run; invoke it without an endpoint and verify the external portion is skipped.

**Acceptance Scenarios**:

1. **Given** a pull request workflow without an external endpoint, **When** CI runs, **Then** no live external dependency is required.
2. **Given** a pull request workflow with an external endpoint, **When** CI runs, **Then** multiple independent client implementations exercise the same portable external profile.
3. **Given** a separately built target implementation, **When** CI runs the external profile, **Then** the checks do not write files into that implementation's source tree.

---

### Edge Cases

- The external endpoint is unreachable or the server exits before checks begin.
- The external server advertises only unsecured endpoints, only secured endpoints, or several security modes.
- The external server does not allow anonymous sessions.
- The external server implements the base address space but returns a non-good status for a required standard node.
- The external server lacks async-opcua demo-specific namespace entries; external checks must not treat that alone as a failure.
- No external endpoint is supplied in CI; the workflow must remain self-contained.

## Requirements *(mandatory)*

<!--
  ACTION REQUIRED: The content in this section represents placeholders.
  Fill them out with the right functional requirements.
-->

### Functional Requirements

- **FR-001**: The normal interop workflow MUST remain self-contained and MUST run the existing async-opcua demo-server checks when no external endpoint is supplied.
- **FR-002**: Maintainers MUST be able to supply an external OPC UA endpoint and run checks against that endpoint without launching the async-opcua demo server.
- **FR-003**: The external profile MUST limit required behavior to portable OPC UA server capabilities: endpoint discovery, anonymous session activation, standard server-status reads, browsing the Objects folder, and an unknown-node status result.
- **FR-004**: The external profile MUST report named check results, total pass/fail counts, and a failing process status when any required check fails.
- **FR-005**: Maintainers MUST be able to choose unsecured-only, strongest-advertised secured endpoint, or automatic endpoint selection for external checks.
- **FR-006**: The reusable pull request workflow MUST accept an optional external endpoint and MUST skip external live-server checks when that endpoint is absent.
- **FR-007**: The external workflow MUST support multiple independent client implementations exercising the same portable profile.
- **FR-008**: Documentation MUST distinguish the portable external profile from the full async-opcua demo-server profile and from official certification tooling.
- **FR-009**: External checks MUST NOT require source edits, committed generated files, or repository-local state in the implementation being checked.
- **FR-010**: External checks MUST NOT require stored credentials; anonymous access is the only required identity mode for the portable profile.

### Key Entities *(include if feature involves data)*

- **External Target**: A reachable OPC UA server implementation outside the async-opcua demo-server process.
- **Portable Profile**: The bounded set of standard OPC UA checks that should apply across compliant server implementations.
- **Client Implementation**: An independent OPC UA client stack used to exercise the portable profile.
- **Interop Result**: The named pass/fail outcome for each portable check and the aggregate status returned to the caller.
- **Workflow Invocation**: A local or CI-triggered run that may or may not include an external endpoint.

## Success Criteria *(mandatory)*

<!--
  ACTION REQUIRED: Define measurable success criteria.
  These must be technology-agnostic and measurable.
-->

### Measurable Outcomes

- **SC-001**: A maintainer can run the external profile against a reachable endpoint with one endpoint value and no source changes in the target implementation.
- **SC-002**: The existing self-contained interop workflow still completes successfully without any external endpoint.
- **SC-003**: Any failed external check names the failing behavior and returns a non-zero status to local callers and CI.
- **SC-004**: Documentation lets a maintainer determine in under five minutes whether a pass means portable smoke-test success, full demo-server conformance, or official certification.
- **SC-005**: A local async-opcua demo-server endpoint passes the portable external profile, proving the profile can be validated without third-party infrastructure.

## Assumptions

<!--
  ACTION REQUIRED: The content in this section represents placeholders.
  Fill them out with the right assumptions based on reasonable defaults
  chosen when the feature description did not specify certain details.
-->

- External implementation builds and process management remain outside this feature; the harness consumes a reachable OPC UA endpoint.
- Portable external checks intentionally do not require demo namespace nodes, custom methods, writable demo variables, subscriptions, or historical data.
- Anonymous sessions are the baseline identity mode for the portable profile because credentials and user databases are implementation-specific.
- Official certification remains out of scope; this feature provides repeatable engineering signal, not a certification claim.
