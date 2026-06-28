# Implementation Plan: StatusCode Conformance Test Matrix

**Branch**: `038-statuscode-test-matrix` | **Date**: 2026-06-28 | **Spec**: [spec.md](./spec.md)  
**Input**: Feature specification from `/specs/038-statuscode-test-matrix/spec.md`

## Summary

Create a spec-grounded test plan for deterministic StatusCode and happy-path coverage across the OPC UA standard sections already implemented by async-opcua. The plan produces a coverage matrix and one-test-per-task implementation queue. It does not add tests yet; each later task must add exactly one named test function and may include only the minimal production changes required to make that one test pass.

## Technical Context

**Language/Version**: Rust 1.75+  
**Primary Dependencies**: Existing workspace crates, tokio test runtime, bytes, existing async-opcua test fixtures  
**Storage**: N/A  
**Testing**: `cargo test` with crate-focused filters, plus exact StatusCode assertions inside unit or integration tests  
**Target Platform**: Linux server/library CI and local developer environments  
**Project Type**: Rust workspace library and integration-test suite  
**Performance Goals**: No test task may introduce nondeterministic sleeps, live network dependencies, or external CTT requirements; each test should run inside the existing crate/integration test budget  
**Constraints**: One task equals one test function; all tests cite an OPC UA Part/section; tests cover implemented behavior only; environmental failures require injected fixtures or remain deferred  
**Scale/Scope**: Initial matrix covers implemented Parts 2, 3, 4, 5, 6, 8, 9, 11, 12, 13, 14, 18, 80, 81, and 83 surfaces present in the repository

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

- **Correctness over completion**: Pass. Tasks are driven by official OPC UA section references and exact StatusCode assertions, not by broad "more tests" goals.
- **Individual task discipline**: Pass. Each task is constrained to exactly one named test function in one file.
- **Security paramount**: Pass. Security-related StatusCode paths remain in scope, but tests must be deterministic and must not weaken existing fail-closed behavior.
- **Leave it better than you found it**: Pass. The matrix documents covered, tasked, environmental, generated-only, and unimplemented paths so future work can update it intentionally.
- **No panic network decode**: Pass. Transport/PubSub malformed-input tasks include exact status/no-panic expectations and avoid nondeterministic network failure.

## Project Structure

### Documentation (this feature)

```text
specs/038-statuscode-test-matrix/
├── spec.md
├── plan.md
├── research.md
├── data-model.md
├── quickstart.md
├── checklists/
│   └── requirements.md
├── contracts/
│   └── statuscode-test-matrix.md
└── tasks.md
```

### Source Code (repository root)

```text
async-opcua-core/src/tests/
async-opcua-types/src/tests/
async-opcua-crypto/src/tests/
async-opcua-pubsub/tests/
async-opcua-fx/tests/
async-opcua-history-sqlite/tests/
async-opcua-server/tests/
async-opcua/tests/integration/
```

**Structure Decision**: This feature creates planning artifacts only. Later implementation tasks add one test at a time to existing crate or integration test files, matching the crate that owns the behavior under test.

## Phase 0 Research Summary

Research is captured in [research.md](./research.md). Key decisions:

- Use official OPC UA references from the MCP where available and the repository conformance register where MCP indexing is sparse.
- Classify every candidate path before tasking it.
- Generate tasks only for deterministic implemented behavior.
- Keep red tests allowed, because some planned tasks intentionally lock open conformance gaps before fixing them.

## Phase 1 Design Summary

Design artifacts:

- [data-model.md](./data-model.md) defines ImplementedStandardSection, StatusCodePath, CoverageClassification, and TestTask.
- [contracts/statuscode-test-matrix.md](./contracts/statuscode-test-matrix.md) is the authoritative matrix for task generation.
- [quickstart.md](./quickstart.md) describes how to implement and verify a single one-test task.

## Complexity Tracking

No constitution violations to track.
