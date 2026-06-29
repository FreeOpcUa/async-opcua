# Feature Specification: OPC Foundation Profile Benchmark Builds

**Feature Branch**: `041-foundation-profile-builds`  
**Created**: 2026-06-29  
**Status**: Draft  
**Input**: User description: "Make builds for the nano, micro and embedded profiles from the OPC Foundation."  
**Clarification**: Profile builds are benchmark configurations. They show the size of using the library for a profile-oriented surface; they do not advertise OPC Foundation conformance by themselves.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Build Named Profile Benchmark Variants (Priority: P1)

A maintainer can build distinct Nano, Micro, and Embedded benchmark variants that are named after OPC Foundation server profiles and use the smallest available async-opcua server feature surface for those benchmarks.

**Why this priority**: This gives maintainers concrete profile-oriented size numbers without confusing benchmark configuration with official profile conformance.

**Independent Test**: Build and test each profile benchmark independently and verify the benchmark names the intended OPC Foundation profile URI while leaving server profile conformance claims empty.

**Acceptance Scenarios**:

1. **Given** the Nano benchmark variant is selected, **When** the sample is built and inspected, **Then** it targets only the Nano OPC Foundation profile URI for reporting and does not advertise profile conformance.
2. **Given** the Micro benchmark variant is selected, **When** the sample is built and inspected, **Then** it targets only the Micro OPC Foundation profile URI for reporting and does not advertise profile conformance.
3. **Given** the Embedded benchmark variant is selected, **When** the sample is built and inspected, **Then** it targets only the Embedded OPC Foundation profile URI for reporting and does not advertise profile conformance.

---

### User Story 2 - Verify Benchmark Footprints in CI (Priority: P2)

A reviewer can see in pull request CI that all three benchmark variants still compile, avoid accidental full-namespace growth, and report binary size under the embedded build profile.

**Why this priority**: Profile benchmark variants will decay unless CI exercises them directly and guards the dependency boundary that controls binary size.

**Independent Test**: Run the reusable footprint workflow and confirm it builds Nano, Micro, and Embedded benchmark variants, rejects generated namespace dependencies, and prints a size line for each.

**Acceptance Scenarios**:

1. **Given** a pull request changes server features or sample dependencies, **When** CI runs, **Then** each benchmark variant builds or fails by profile name.
2. **Given** a benchmark variant accidentally pulls in the generated core namespace, **When** CI checks the dependency tree, **Then** the benchmark row fails before reporting a misleading size.
3. **Given** CI completes the benchmark matrix, **When** a reviewer reads the logs, **Then** the binary size for each benchmark variant is visible.

---

### User Story 3 - Document Benchmark Scope and Claims (Priority: P3)

A developer can tell the difference between profile benchmark builds, official OPC Foundation certification, and the full server feature.

**Why this priority**: Profile names can be mistaken for official conformance certification unless the repository documents the scope precisely.

**Independent Test**: Read the documentation and verify it names the benchmark build commands, target profile URIs, dependency-surface expectation, and the fact that these builds are not official certification evidence.

**Acceptance Scenarios**:

1. **Given** a developer is choosing a benchmark build, **When** they read the documentation, **Then** they can find the Nano, Micro, and Embedded build commands.
2. **Given** a developer reads the profile guidance, **When** they compare it with certification needs, **Then** they understand that official certification still requires OPC Foundation tooling and profile-specific conformance testing.
3. **Given** a developer wants the generated standard namespace or a certified profile claim, **When** they read the benchmark guidance, **Then** they understand that the benchmark sample is intentionally not that claim.

---

### Edge Cases

- Selecting no profile or multiple profile features must fail at compile time for the benchmark sample.
- Benchmark builds must not accidentally use the full generated core namespace path.
- The Embedded benchmark may need stronger crypto features than Nano and Micro; that must be explicit in the selected build target.
- CI must not require third-party certification tools.
- Binary size reporting must not fail solely because one benchmark is larger than another benchmark.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The repository MUST provide buildable Nano, Micro, and Embedded OPC Foundation server profile benchmark variants.
- **FR-002**: Each benchmark variant MUST select exactly one OPC Foundation target profile URI at compile time for reporting.
- **FR-003**: Each benchmark variant MUST use the smallest available server feature surface and MUST NOT depend on the generated core namespace.
- **FR-004**: Benchmark variants MUST NOT populate `ServerCapabilities.ServerProfileArray` merely because a benchmark feature was selected.
- **FR-005**: Tests MUST verify that each benchmark variant selects the expected target URI and leaves profile conformance claims empty.
- **FR-006**: CI MUST build all three benchmark variants under the embedded build profile.
- **FR-007**: CI MUST fail a benchmark variant that pulls in the generated core namespace.
- **FR-008**: CI MUST print a binary-size line for each benchmark variant.
- **FR-009**: Documentation MUST list the benchmark build commands, target profile URIs, dependency-surface expectation, and non-certification scope.

### Key Entities

- **Foundation Profile Benchmark Variant**: A named build target for measuring a profile-oriented server surface.
- **Target Profile URI**: The OPC Foundation URI used to label the benchmark target, not an advertised conformance claim.
- **Benchmark Build Matrix**: The CI matrix that builds all supported benchmark variants and reports sizes.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Three benchmark variants build successfully with one command per profile.
- **SC-002**: Tests verify all three target URI selections and empty advertised profile claims in under one minute on a warmed developer machine.
- **SC-003**: CI prints exactly one size line for each of Nano, Micro, and Embedded benchmark variants.
- **SC-004**: The benchmark sample dependency tree omits the generated core namespace for every profile variant.
- **SC-005**: Documentation lets a maintainer distinguish benchmark builds from official certification within five minutes.

## Assumptions

- The first increment targets the OPC Foundation 2017 Nano, Micro, and Embedded server profile URI family because it aligns with the project’s existing CTT-oriented terminology.
- These builds are benchmark targets and CI guards, not official OPC Foundation certification results.
- The existing embedded Cargo profile remains the size-reporting profile for CI.
- The library does not yet expose fine-grained service-set Cargo gates; this feature uses the smallest existing server surface and records service-set gating as follow-up work.
