# Feature Specification: StatusCode Conformance Test Matrix

**Feature Branch**: `038-statuscode-test-matrix`  
**Created**: 2026-06-28  
**Status**: Draft  
**Input**: User description: "Be sure async-opcua tests the happy path and negative path for everything implemented. Provoke all deterministic error codes we can, ground each test in the implemented OPC UA standard sections, keep tasks atomic, and make each task implement one test."

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Prove Core Service Status Codes (Priority: P1)

A maintainer needs exact tests for deterministic Part 4 service and Part 6 transport/encoding StatusCodes that async-opcua already produces, so regressions are caught before a CTT run or downstream client finds them.

**Why this priority**: Part 4 services and Part 6 mappings are the baseline server/client contract. Wrong error codes break interoperability even when the operation fails safely.

**Independent Test**: Implement any one listed service or transport test task. The task is complete only when that one test asserts the exact StatusCode and any required no-mutation/no-partial-result behavior.

**Acceptance Scenarios**:

1. **Given** an implemented service path with a deterministic invalid input, **When** a single test drives that input, **Then** the test asserts the exact OPC UA StatusCode named by the relevant Part 4 or Part 6 section.
2. **Given** an implemented successful operation paired with the negative path, **When** the test needs a baseline, **Then** the baseline assertions stay inside the same test and no additional test function is introduced.

---

### User Story 2 - Prove Implemented Information-Model and Companion Surfaces (Priority: P2)

A maintainer needs one-test-per-gap coverage for implemented Address Space, Server Object, DataAccess, Alarms & Conditions, Historical Access, Aggregates, PubSub, RBAC, and UAFX behavior.

**Why this priority**: These areas were recently completed through focused features. Their tests should prove the implemented standard surfaces fail with the expected StatusCodes, not merely that they avoid panics.

**Independent Test**: Implement any one listed model or companion-surface task. The task is complete only when exactly one test function is added and it cites the implemented standard section in a comment.

**Acceptance Scenarios**:

1. **Given** an implemented optional or companion surface, **When** invalid input is deterministic and reachable, **Then** one test asserts the expected StatusCode and leaves existing state unchanged where the standard requires no operation.
2. **Given** a status path that depends on OS, network timing, cryptographic randomness, or external CTT infrastructure, **When** it cannot be provoked deterministically, **Then** the matrix classifies it as injectable/environmental instead of creating a flaky test task.

---

### User Story 3 - Maintain a Spec-Grounded Coverage Matrix (Priority: P3)

A maintainer needs a living matrix that maps implemented standard sections to existing coverage, missing deterministic tests, and intentionally deferred environmental paths.

**Why this priority**: The test plan spans many crates and OPC UA Parts. A matrix prevents duplicate work and keeps future task generation tied to standard sections instead of ad hoc code search.

**Independent Test**: The matrix is complete when each planned test row has one task ID, one StatusCode or happy-path assertion target, one file path, and one OPC UA reference.

**Acceptance Scenarios**:

1. **Given** a StatusCode produced by production code, **When** the matrix classifies it as "tasked", **Then** exactly one task references that row and implements exactly one test.
2. **Given** an already-covered StatusCode path, **When** the matrix classifies it as "covered", **Then** it names an existing test file or crate-level test area instead of generating redundant work.

### Edge Cases

- StatusCodes defined only as generated constants are not behavior paths and must not receive test tasks.
- Multiple code paths may produce the same StatusCode; the matrix may choose one representative deterministic path per implemented standard section unless a section has materially different semantics.
- A task may include minimal production changes required to make its one test pass, but it must not add a second test function.
- Open conformance gaps from `specs/conformance-audit/FINDINGS.md` may receive red tests, but only when the implemented surface is reachable without CTT-only infrastructure.
- Environmental failures such as real socket exhaustion, network partition, clock failure, live OCSP fetching, or third-party PubSub interop must be marked as injectable/deferred unless a deterministic local fixture exists.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The matrix MUST enumerate implemented standard surfaces from OPC UA Parts 2, 3, 4, 5, 6, 8, 9, 11, 12, 13, 14, 18, 80, 81, and 83 when the repository has implemented behavior for that surface.
- **FR-002**: Each matrix row MUST include an OPC UA reference, the intended StatusCode or happy-path result, the implementation area, the coverage classification, and the task ID when additional coverage is required.
- **FR-003**: Each implementation task MUST add exactly one test function in exactly one test file.
- **FR-004**: Each negative-path test MUST assert the exact StatusCode and any standard-required state preservation, result-array shape, or no-mutation behavior.
- **FR-005**: Each happy-path test MUST assert the successful operation result and at least one observable standard-defined effect.
- **FR-006**: The plan MUST prefer deterministic unit or integration fixtures over flaky timing, host-network, external CTT, or third-party dependency failures.
- **FR-007**: The plan MUST avoid generating implementation tasks for unimplemented OPC UA standard surfaces; those remain backlog or conformance-gap items.
- **FR-008**: The tasks MUST include enough traceability for an implementer to find the target production code, target test file, expected StatusCode, and spec section without asking follow-up questions.
- **FR-009**: The three analysis passes MUST separately check task atomicity, spec-reference coverage, and cross-artifact consistency.

### Key Entities *(include if feature involves data)*

- **Implemented Standard Section**: An OPC UA Part and section for behavior already implemented in async-opcua.
- **StatusCode Path**: A deterministic happy or negative behavior path that returns, embeds, or observes a specific StatusCode.
- **Coverage Classification**: One of covered, tasked, environmental, generated-only, or unimplemented.
- **Test Task**: A single atomic task that adds exactly one named test function for one StatusCode path or happy-path behavior.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: 100% of tasked matrix rows have exactly one task ID and exactly one planned test function name.
- **SC-002**: 100% of tasks include an OPC UA spec reference and a repository test file path.
- **SC-003**: The atomicity analysis pass reports no task that adds more than one test.
- **SC-004**: The spec-reference analysis pass reports no task without an OPC UA Part/section citation.
- **SC-005**: The consistency analysis pass reports no high or critical cross-artifact issues before implementation starts.
- **SC-006**: No task requires live upstream repositories, third-party CTT infrastructure, or nondeterministic host-network failure to pass.

## Assumptions

- Existing tests that already assert exact StatusCodes are treated as covered and are not duplicated.
- A single representative deterministic test can cover a StatusCode for a standard section unless the same StatusCode has materially different semantics in another implemented section.
- Red tests for open conformance gaps are allowed because the feature is about locking standards behavior; implementation fixes can be made within the same one-test task if needed.
- "No PRs to upstream" remains in effect for any later implementation work.
