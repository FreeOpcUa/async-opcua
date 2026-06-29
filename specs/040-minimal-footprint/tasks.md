# Tasks: Minimal Deployment Footprint

**Input**: Design documents from `/specs/040-minimal-footprint/`  
**Prerequisites**: [plan.md](./plan.md), [spec.md](./spec.md), [research.md](./research.md), [data-model.md](./data-model.md), [contracts/](./contracts/), [quickstart.md](./quickstart.md)  
**Tests**: Required as build and dependency-tree validation because this feature is Cargo feature/CI behavior.
**Format**: `[ID] [P?] [Story] Description with file path`

## Phase 1: Setup

**Purpose**: Confirm active feature context and existing footprint-related documentation.

- [X] T001 Confirm active SpecKit context points to `specs/040-minimal-footprint/plan.md` in `AGENTS.md`
- [X] T002 [P] Review existing umbrella features in `async-opcua/Cargo.toml` and server feature defaults in `async-opcua-server/Cargo.toml`
- [X] T003 [P] Review existing embedded profile guidance in `docs/setup.md`

---

## Phase 2: Foundational

**Purpose**: Establish the minimal sample target before validating facade behavior.

- [X] T004 [P] Add minimal server sample manifest in `samples/minimal-server/Cargo.toml`
- [X] T005 [P] Add minimal server sample entry point in `samples/minimal-server/src/main.rs`

---

## Phase 3: User Story 1 - Build a Minimal Server Through the Facade (Priority: P1) MVP

**Goal**: A consumer can use `async-opcua` with `base-server` and import `opcua::server` without generated namespace code.

**Independent Test**: `cargo build --locked -p async-opcua-minimal-server` succeeds and `cargo tree --locked -p async-opcua-minimal-server -e normal` contains no `async-opcua-core-namespace`.

- [X] T006 [US1] Update public facade cfg gates in `async-opcua/src/lib.rs`
- [X] T007 [US1] Validate release-profile minimal sample build with `cargo build --locked -p async-opcua-minimal-server`
- [X] T008 [US1] Validate generated namespace absence with `cargo tree --locked -p async-opcua-minimal-server -e normal`
- [X] T009 [US1] Validate existing no-default umbrella build with `cargo check --locked -p async-opcua --no-default-features`
- [X] T010 [US1] Validate full server feature still includes generated namespace with `cargo tree --locked -p async-opcua --no-default-features --features server -e normal`

---

## Phase 4: User Story 2 - Verify Footprint Builds in CI (Priority: P2)

**Goal**: Pull request CI builds the minimal embedded sample and prints its binary size.

**Independent Test**: The footprint workflow commands build the embedded profile and print a byte-size line for `target/embedded/async-opcua-minimal-server`.

- [X] T011 [US2] Add reusable footprint workflow in `.github/workflows/ci_footprint.yml`
- [X] T012 [US2] Add footprint workflow invocation to `.github/workflows/main.yml`
- [X] T013 [US2] Validate embedded-profile minimal sample build with `cargo build --locked --profile embedded -p async-opcua-minimal-server`
- [X] T014 [US2] Validate local size report for `target/embedded/async-opcua-minimal-server`
- [X] T015 [US2] Validate minimal embedded binary is at least 25% smaller than the release-profile simple-server audit baseline

---

## Phase 5: User Story 3 - Document the Supported Footprint Path (Priority: P3)

**Goal**: Developers can find and understand the minimal build path and its compliance tradeoff.

**Independent Test**: Documentation includes build commands for the minimal sample, explains that full `server` keeps the generated namespace, and notes that `base-server` omits it.

- [X] T016 [US3] Update embedded deployment guidance in `docs/setup.md`
- [X] T017 [US3] Update umbrella feature descriptions in `async-opcua/README.md`
- [X] T018 [US3] Validate documentation commands against `specs/040-minimal-footprint/quickstart.md`

---

## Phase 6: Polish & Cross-Cutting Concerns

**Purpose**: Final verification and cleanup.

- [X] T019 Run `cargo fmt --all`
- [X] T020 Run focused clippy for the minimal sample with `cargo clippy --locked -p async-opcua-minimal-server -- -D warnings`
- [X] T021 Confirm all tasks are marked complete in `specs/040-minimal-footprint/tasks.md` and inspect final git status

---

## Dependencies & Execution Order

- **Setup (Phase 1)**: No dependencies.
- **Foundational (Phase 2)**: Depends on Setup; creates the sample target needed by later validation.
- **US1 (Phase 3)**: Depends on the sample target; delivers the MVP.
- **US2 (Phase 4)**: Depends on US1 build behavior.
- **US3 (Phase 5)**: Can proceed after US1 behavior is known.
- **Polish (Phase 6)**: Depends on all selected user stories.

## Parallel Opportunities

- T002 and T003 can run in parallel during setup.
- T004 and T005 touch different sample files and can be prepared in parallel.
- Documentation updates in T016 and T017 can proceed in parallel after implementation behavior is confirmed.

## Implementation Strategy

### MVP First

1. Complete setup and sample creation.
2. Fix the facade export gate.
3. Build the minimal sample and prove generated namespace is absent.
4. Stop and validate before adding CI/docs.

### Incremental Delivery

1. US1 makes the feature path work locally.
2. US2 makes CI guard it.
3. US3 makes it discoverable and explains the tradeoff.
