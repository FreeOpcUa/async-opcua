# Tasks: External Implementation Interop Checks

**Input**: Design documents from `/specs/039-external-interop-targets/`  
**Prerequisites**: [plan.md](./plan.md), [spec.md](./spec.md), [research.md](./research.md), [data-model.md](./data-model.md), [contracts/](./contracts/), [quickstart.md](./quickstart.md)  
**Tests**: Required for every user story. Local harness validation is the acceptance test because this feature is interop/CI tooling.
**Format**: `[ID] [P?] [Story] Description with file path`

## Phase 1: Setup

**Purpose**: Confirm the active Spec Kit feature and baseline interop structure.

- [X] T001 Confirm active Spec Kit context points to `specs/039-external-interop-targets/plan.md` in `AGENTS.md`
- [X] T002 [P] Confirm existing interop wrapper entry points in `samples/demo-server/interop/dotnet/run-dotnet.sh` and `samples/demo-server/interop/asyncua/run-asyncua.sh`

---

## Phase 2: Foundational

**Purpose**: Preserve the portable-profile contract before adding another client and workflow path.

- [X] T003 [P] Document the local and CI external interop contracts in `specs/039-external-interop-targets/contracts/external-interop.md`
- [X] T004 [P] Document validation commands in `specs/039-external-interop-targets/quickstart.md`

---

## Phase 3: User Story 1 - Check an External OPC UA Server (Priority: P1) MVP

**Goal**: Run portable checks against an already-running OPC UA server without depending on async-opcua demo nodes.

**Independent Test**: Start the async-opcua demo server manually and run both portable clients with `--external opc.tcp://127.0.0.1:4855`; each exits `0`.

- [X] T005 [US1] Verify the .NET portable profile and security selector in `samples/demo-server/interop/dotnet/Program.cs`
- [X] T006 [US1] Verify the .NET external wrapper mode in `samples/demo-server/interop/dotnet/run-dotnet.sh`
- [X] T007 [P] [US1] Add asyncua portable external profile in `samples/demo-server/interop/asyncua/portable-test.py`
- [X] T008 [US1] Add asyncua external wrapper mode in `samples/demo-server/interop/asyncua/run-asyncua.sh`
- [X] T009 [US1] Validate both portable external clients against a manually started local demo server using `samples/demo-server/interop/dotnet/run-dotnet.sh` and `samples/demo-server/interop/asyncua/run-asyncua.sh`

---

## Phase 4: User Story 2 - Preserve Demo-Server Interop Coverage (Priority: P2)

**Goal**: Keep existing demo-server interop commands as the default self-contained conformance signal.

**Independent Test**: Run the default .NET and asyncua wrappers without `--external`; each launches the demo server and exits `0`.

- [X] T010 [US2] Validate default .NET demo-server interop remains full-suite behavior in `samples/demo-server/interop/dotnet/run-dotnet.sh`
- [X] T011 [US2] Validate default asyncua demo-server interop remains full-suite behavior in `samples/demo-server/interop/asyncua/run-asyncua.sh`
- [X] T012 [US2] Update interop documentation in `samples/demo-server/interop/README.md`

---

## Phase 5: User Story 3 - Reuse the Checks in Pull Request CI (Priority: P3)

**Goal**: Allow CI callers to opt into external portable checks while default CI remains self-contained.

**Independent Test**: Review the reusable workflow with no endpoint to confirm external steps are skipped and with an endpoint to confirm the external job receives `OPCUA_EXTERNAL_ENDPOINT`.

- [X] T013 [US3] Add optional external endpoint input and skipped-by-default external job in `.github/workflows/ci_interop.yml`
- [X] T014 [US3] Document reusable workflow invocation in `samples/demo-server/interop/README.md`
- [X] T015 [US3] Validate workflow references and shell syntax for `.github/workflows/ci_interop.yml`

---

## Phase 6: Polish & Cross-Cutting Concerns

**Purpose**: Final verification and cleanup.

- [X] T016 Run final syntax/build validation for modified interop scripts and clients
- [X] T017 Confirm no files were edited in the external implementation repository and inspect final git status in `/home/quackdcs/async-opcua`

**Status note**: No write commands were run in `/home/quackdcs/micro-opcua` during this implementation. Its final status is not clean (`.specify/feature.json`, `specs/014-node-management/`), so those changes are external to this task and were left untouched.

---

## Dependencies & Execution Order

- **Setup (Phase 1)**: No dependencies.
- **Foundational (Phase 2)**: Depends on Setup and records the contract used by implementation tasks.
- **US1 (Phase 3)**: Depends on Foundational; delivers the MVP.
- **US2 (Phase 4)**: Can run after US1 wrapper behavior is stable.
- **US3 (Phase 5)**: Depends on US1 commands existing.
- **Polish (Phase 6)**: Depends on selected user stories being complete.

## Parallel Opportunities

- T002, T003, and T004 touch different files and can be reviewed in parallel.
- T007 can be implemented while T005/T006 are being verified because it creates a new asyncua file.
- T012 and T014 both edit `README.md` and must be serialized.

## Implementation Strategy

### MVP First

1. Complete T001 through T004.
2. Complete T005 through T009.
3. Stop and verify both portable external clients against the local demo server.

### Incremental Delivery

1. Preserve default demo-server behavior with T010 through T012.
2. Add CI opt-in with T013 through T015.
3. Run final validation and status checks with T016 through T017.
