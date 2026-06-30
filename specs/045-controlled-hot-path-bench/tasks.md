# Tasks: Controlled Hot Path Benchmark Harness

**Input**: Design documents from `/specs/045-controlled-hot-path-bench/`  
**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/cli-contract.md, quickstart.md

**Tests**: TDD is required for this feature. Each user-story phase starts with a RED command that must fail for the expected reason before implementation.

**Organization**: Tasks are grouped by user story to keep each benchmark capability independently testable.

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Establish the in-repo benchmark package entry point.

- [x] T001 Confirm the RED missing-package check with `cargo run -p async-opcua-localhost-bench -- --help` before adding `tools/opcua-localhost-bench/Cargo.toml`
- [x] T002 Create the `async-opcua-localhost-bench` package manifest in `tools/opcua-localhost-bench/Cargo.toml` and add it to the workspace member list in `Cargo.toml`
- [x] T003 Create the initial CLI entry point with help output and mode dispatch stubs in `tools/opcua-localhost-bench/src/main.rs`

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Add shared data structures and argument validation used by every benchmark mode.

**CRITICAL**: No user story work can begin until this phase is complete.

- [x] T004 Define benchmark operation, target, timing, and sample result structures in `tools/opcua-localhost-bench/src/main.rs`
- [x] T005 Implement argument parsing and validation for shared operation, endpoint, port, namespace, node, warmup, and measurement options in `tools/opcua-localhost-bench/src/main.rs`
- [x] T006 Implement JSON sample serialization with the fields required by `specs/045-controlled-hot-path-bench/contracts/cli-contract.md` in `tools/opcua-localhost-bench/src/main.rs`

**Checkpoint**: CLI skeleton builds and shared options reject invalid values before any server/client behavior is added.

---

## Phase 3: User Story 1 - Run A Controlled Local Throughput Sample (Priority: P1) MVP

**Goal**: Run one self-contained localhost Read or Write sample and report throughput/correctness JSON.

**Independent Test**: Short read and write one-shot commands produce JSON with `ok > 0`, `bad == 0`, positive elapsed seconds, and positive operations per second.

### Tests for User Story 1

- [x] T007 [US1] Confirm the RED one-shot read command fails because run mode is not implemented: `cargo run -p async-opcua-localhost-bench -- run --op read --port 4840 --warmup 0.1 --measure 0.2` against `tools/opcua-localhost-bench/src/main.rs`

### Implementation for User Story 1

- [x] T008 [US1] Implement the deterministic benchmark server value node in `tools/opcua-localhost-bench/src/main.rs` using OPC-10000-4 4.1 Attribute Service Set grounding
- [x] T009 [US1] Implement the OPC UA Read/Write measurement loop in `tools/opcua-localhost-bench/src/main.rs` using OPC-10000-4 5.11.2 and 5.11.4 service behavior
- [x] T010 [US1] Implement one-shot `run` mode server startup, readiness wait, client sample execution, JSON output, and cleanup in `tools/opcua-localhost-bench/src/main.rs`
- [x] T011 [US1] Verify short read and write one-shot samples from `specs/045-controlled-hot-path-bench/quickstart.md` against `tools/opcua-localhost-bench/src/main.rs`

**Checkpoint**: User Story 1 is fully functional and testable independently.

---

## Phase 4: User Story 2 - Profile Server And Client Separately (Priority: P2)

**Goal**: Run the benchmark server and client as separate processes for server-only profiling.

**Independent Test**: Start standalone server mode, run standalone read and write client commands against it, then stop the server cleanly.

### Tests for User Story 2

- [x] T012 [US2] Confirm the RED standalone server command fails because server mode is not implemented: `cargo run -p async-opcua-localhost-bench -- server --port 4840` against `tools/opcua-localhost-bench/src/main.rs`

### Implementation for User Story 2

- [x] T013 [US2] Implement standalone `server` mode with localhost bind and the existing benchmark value node helper in `tools/opcua-localhost-bench/src/main.rs`
- [x] T014 [US2] Implement Ctrl-C shutdown and clear bind-error reporting for standalone `server` mode in `tools/opcua-localhost-bench/src/main.rs`
- [x] T015 [US2] Implement standalone `client` mode that reuses the OPC UA Read/Write measurement loop against a supplied endpoint in `tools/opcua-localhost-bench/src/main.rs`
- [x] T016 [US2] Verify standalone server/client read and write samples from `specs/045-controlled-hot-path-bench/quickstart.md` against `tools/opcua-localhost-bench/src/main.rs`

**Checkpoint**: User Stories 1 and 2 both work independently.

---

## Phase 5: User Story 3 - Preserve Comparable Benchmark Metadata (Priority: P3)

**Goal**: Keep result fields stable and document artifact policy for repeatable comparisons.

**Independent Test**: Parse a read sample and a write sample as JSON and verify all required fields exist with expected types.

### Tests for User Story 3

- [x] T017 [US3] Validate JSON field output by parsing one read sample against `specs/045-controlled-hot-path-bench/contracts/cli-contract.md` requirements and `tools/opcua-localhost-bench/src/main.rs`

### Implementation for User Story 3

- [x] T018 [US3] Stabilize JSON field names, numeric types, first-failure formatting, and nonzero exit behavior in `tools/opcua-localhost-bench/src/main.rs`
- [x] T019 [P] [US3] Add user-facing harness documentation in `tools/opcua-localhost-bench/README.md`
- [x] T020 [P] [US3] Add generated benchmark/profiler artifact ignore patterns to `.gitignore` if existing patterns do not already cover them

**Checkpoint**: All user stories are independently functional.

---

## Phase 6: Polish & Cross-Cutting Concerns

**Purpose**: Final validation and cleanup.

- [x] T021 Run `cargo fmt --check` for the workspace after implementing `tools/opcua-localhost-bench/src/main.rs`
- [x] T022 Run `cargo run -p async-opcua-localhost-bench -- --help` and short read/write one-shot samples from `specs/045-controlled-hot-path-bench/quickstart.md`
- [x] T023 Run `git status --short` and remove any generated benchmark artifacts under `tools/opcua-localhost-bench/` before completion

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies.
- **Foundational (Phase 2)**: Depends on Setup completion and blocks all user stories.
- **User Story 1 (Phase 3)**: Depends on Foundational; delivers MVP.
- **User Story 2 (Phase 4)**: Depends on User Story 1 measurement/server helpers.
- **User Story 3 (Phase 5)**: Depends on User Stories 1 and 2 producing samples.
- **Polish (Phase 6)**: Depends on all desired user stories being complete.

### User Story Dependencies

- **US1**: Starts after Foundational; no dependency on other stories.
- **US2**: Starts after US1 because standalone client/server modes reuse the same benchmark server and measurement loop.
- **US3**: Starts after US1/US2 so it can validate real output from both execution shapes.

### Parallel Opportunities

- T019 and T020 can run in parallel after JSON output is stable.
- Final formatting and generated-artifact cleanup must run after implementation tasks.

## Implementation Strategy

### MVP First

1. Complete Phase 1 and Phase 2.
2. Complete Phase 3 only.
3. Validate one-shot read and write samples.
4. Stop if the project only needs a controlled local sample.

### Incremental Delivery

1. Add one-shot run mode for controlled quick samples.
2. Add standalone server/client mode for profiler workflows.
3. Stabilize metadata and documentation for repeatable comparisons.

## Notes

- Tasks that implement OPC UA Read/Write behavior cite OPC-10000-4 4.1, 5.11.2, and 5.11.4 in the task description.
- Do not add hard throughput gates in this feature.
- Do not commit generated profiler data or scratch run outputs.
