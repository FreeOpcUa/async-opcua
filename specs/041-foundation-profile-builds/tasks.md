# Tasks: OPC Foundation Profile Benchmark Builds

**Input**: Design documents from `/specs/041-foundation-profile-builds/`  
**Prerequisites**: [plan.md](./plan.md), [spec.md](./spec.md), [research.md](./research.md), [data-model.md](./data-model.md), [contracts/](./contracts/), [quickstart.md](./quickstart.md)  
**Tests**: Required because this feature changes Cargo package selection, CI build coverage, benchmark dependency boundaries, and documentation claims.
**Format**: `[ID] [P?] [Story] Description with file path`

## Phase 1: Setup

**Purpose**: Confirm active context and existing profile/footprint structure.

- [X] T001 Confirm active SpecKit context points to `specs/041-foundation-profile-builds/plan.md` in `AGENTS.md`
- [X] T002 [P] Review server builder and server-info capability flow in `async-opcua-server/src/builder.rs` and `async-opcua-server/src/server.rs`
- [X] T003 [P] Review existing footprint workflow in `.github/workflows/ci_footprint.yml`
- [X] T004 [P] Review existing profile/embedded docs in `docs/setup.md` and `docs/opc_ua_overview.md`
- [X] T005 [P] Ground profile/conformance wording against OPC Foundation reference sections in `specs/041-foundation-profile-builds/research.md`

---

## Phase 2: Foundational

**Purpose**: Remove the incorrect runtime conformance-claim hook from this benchmark feature.

- [X] T006 Remove benchmark-driven profile URI storage and setter from `async-opcua-server/src/builder.rs`
- [X] T007 Restore default server capabilities construction in `async-opcua-server/src/server.rs`
- [X] T008 Remove profile URI builder tests from `async-opcua-server/src/builder.rs`

---

## Phase 3: User Story 1 - Build Named Profile Benchmark Variants (Priority: P1) MVP

**Goal**: Maintainers can build Nano, Micro, and Embedded profile benchmark variants and each variant targets exactly one URI without advertising profile conformance.

**Independent Test**: `cargo test --locked -p async-opcua-foundation-profile-<profile>-server` passes for `nano`, `micro`, and `embedded`.

- [X] T009 [US1] Add profile benchmark manifests using `base-server` in `samples/foundation-profile-*-server/Cargo.toml`
- [X] T010 [US1] Add profile benchmark implementations in `samples/foundation-profile-*-server/src/main.rs`
- [X] T011 [US1] Validate Nano benchmark tests with `cargo test --locked -p async-opcua-foundation-profile-nano-server`
- [X] T012 [US1] Validate Micro benchmark tests with `cargo test --locked -p async-opcua-foundation-profile-micro-server`
- [X] T013 [US1] Validate Embedded benchmark tests with `cargo test --locked -p async-opcua-foundation-profile-embedded-server`
- [X] T014 [US1] Validate workspace builds include profile benchmark packages with `cargo build --locked --workspace`
- [X] T015 [US1] Validate generated namespace absence for all profile packages with `cargo tree --locked -p async-opcua-foundation-profile-<profile>-server -e normal`

---

## Phase 4: User Story 2 - Verify Benchmark Builds in CI (Priority: P2)

**Goal**: Pull request CI builds every benchmark variant under the embedded profile, rejects generated namespace dependencies, and prints binary sizes.

**Independent Test**: The footprint workflow commands build Nano, Micro, and Embedded variants and print one size line per profile.

- [X] T016 [US2] Extend `.github/workflows/ci_footprint.yml` with a Foundation profile benchmark matrix
- [X] T017 [US2] Validate Nano embedded build with `cargo build --locked --profile embedded -p async-opcua-foundation-profile-nano-server`
- [X] T018 [US2] Validate Micro embedded build with `cargo build --locked --profile embedded -p async-opcua-foundation-profile-micro-server`
- [X] T019 [US2] Validate Embedded embedded build with `cargo build --locked --profile embedded -p async-opcua-foundation-profile-embedded-server`
- [X] T020 [US2] Validate local size reporting for `target/embedded/async-opcua-foundation-profile-<profile>-server`

---

## Phase 5: User Story 3 - Document Benchmark Scope and Claims (Priority: P3)

**Goal**: Developers can distinguish profile benchmarks from official certification and from full generated-namespace server builds.

**Independent Test**: Documentation includes build commands, target profile URIs, generated-namespace absence, and non-certification scope.

- [X] T021 [US3] Update embedded/profile benchmark guidance in `docs/setup.md`
- [X] T022 [US3] Update profile overview in `docs/opc_ua_overview.md`
- [X] T023 [US3] Update foundation profile sample listing in `async-opcua/README.md`
- [X] T024 [US3] Validate documentation commands against `specs/041-foundation-profile-builds/quickstart.md`

---

## Phase 6: Polish & Cross-Cutting Concerns

**Purpose**: Final formatting, linting, and status verification.

- [X] T025 Run `cargo fmt --all`
- [X] T026 Run focused clippy for profile benchmark sample with `cargo clippy --locked -p async-opcua-foundation-profile-embedded-server -- -D warnings`
- [X] T027 Run `git diff --check`
- [X] T028 Confirm all tasks are marked complete in `specs/041-foundation-profile-builds/tasks.md` and inspect final git status

---

## Dependencies & Execution Order

- **Setup (Phase 1)**: No dependencies.
- **Foundational (Phase 2)**: Depends on Setup; removes the incorrect runtime profile claim path.
- **US1 (Phase 3)**: Depends on Foundational.
- **US2 (Phase 4)**: Depends on profile benchmark sample builds.
- **US3 (Phase 5)**: Can proceed after profile benchmark commands are known.
- **Polish (Phase 6)**: Depends on all selected user stories.

## Parallel Opportunities

- T002, T003, T004, and T005 can run in parallel during setup.
- T011, T012, and T013 validate different package selections and can run independently after T010.
- T017, T018, and T019 validate different CI matrix rows and can run independently after T016.
- T021, T022, and T023 touch different documentation files and can proceed in parallel after benchmark behavior is confirmed.

## Implementation Strategy

### MVP First

1. Remove the profile URI advertising hook from this benchmark feature.
2. Add separate profile benchmark packages that use the `base-server` feature surface.
3. Prove all three variants select the right target URI, leave advertised profiles empty, build in workspace modes, and omit generated namespace.

### Incremental Delivery

1. US1 makes profile benchmarks real locally.
2. US2 makes profile benchmarks visible in CI with size reporting.
3. US3 documents scope and prevents certification confusion.
