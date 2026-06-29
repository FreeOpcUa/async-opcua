# Feature Specification: Minimal Deployment Footprint

**Feature Branch**: `040-minimal-footprint`  
**Created**: 2026-06-29  
**Status**: Draft  
**Input**: User description: "Use the performance audit findings to do the minimal deployment footprint work: expose a generated-namespace-free base-server path through the facade, add a minimal server sample and CI size guard, and document/verify the feature-minimal embedded build."

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Build a Minimal Server Through the Facade (Priority: P1)

A developer building an embedded or constrained deployment can depend on the public umbrella crate and enable a base server without also pulling the generated OPC UA core namespace.

**Why this priority**: The performance audit found that generated namespace code is the largest binary-size bucket, and the current facade makes the intended `base-server` path hard to use.

**Independent Test**: Build a sample that imports the server API through the umbrella crate with only the base server feature enabled and verify the generated namespace crate is absent from the normal dependency graph.

**Acceptance Scenarios**:

1. **Given** a consumer enables the base server feature only, **When** the consumer imports the server API through the umbrella crate, **Then** the import works without enabling the full server feature.
2. **Given** a consumer builds the minimal server sample, **When** dependencies are inspected, **Then** the generated core namespace crate is not part of the sample's normal dependency tree.
3. **Given** existing users enable the full server feature, **When** they build as before, **Then** generated core namespace behavior remains unchanged.

---

### User Story 2 - Verify Footprint Builds in CI (Priority: P2)

A maintainer can see whether the minimal deployment profile still builds in pull request CI, so accidental feature regressions are caught before merge.

**Why this priority**: A documented footprint path decays quickly unless CI exercises it.

**Independent Test**: Run the footprint CI build locally or in GitHub Actions and verify it builds the minimal sample with the embedded profile and no default umbrella features.

**Acceptance Scenarios**:

1. **Given** a pull request changes feature flags or server dependencies, **When** CI runs, **Then** the minimal footprint build compiles successfully or fails with a clear build error.
2. **Given** the CI workflow runs on the default branch, **When** the footprint job completes, **Then** it reports the resulting binary size for reviewer visibility.

---

### User Story 3 - Document the Supported Footprint Path (Priority: P3)

A developer can follow documentation to choose between full OPC UA namespace compliance and a smaller base-server build without reading Cargo feature internals.

**Why this priority**: The code path is useful only if users can discover the compliance and footprint tradeoff.

**Independent Test**: Follow the documentation commands and verify they point to the minimal sample, explain the namespace compliance tradeoff, and use the embedded profile.

**Acceptance Scenarios**:

1. **Given** a developer reads the setup documentation, **When** they look for embedded or minimal server guidance, **Then** they find a command that builds the minimal sample through the umbrella crate.
2. **Given** a developer compares minimal and full server builds, **When** they read the feature descriptions, **Then** they understand that omitting the generated namespace reduces footprint but does not produce a fully standards-complete server by itself.

---

### Edge Cases

- Existing `server` feature builds must continue to include `generated-address-space` by default.
- `base-server` must not accidentally enable default crypto or generated namespace features through the umbrella crate.
- The minimal sample should avoid requiring local certificates, PKI directories, or generated address-space nodes.
- CI should not require third-party tools beyond the Rust toolchain and standard Linux utilities.
- Size reporting must not fail the build solely because the host formats sizes differently.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The umbrella crate MUST expose the server API when the base server feature is enabled without the full server feature.
- **FR-002**: The umbrella crate MUST preserve the current full server feature behavior, including generated core namespace inclusion.
- **FR-003**: The repository MUST include a minimal server sample that depends on the umbrella crate with no default features and only the base server path needed for compilation.
- **FR-004**: The minimal server sample MUST be buildable with the release and embedded profiles without requiring generated namespace code.
- **FR-005**: CI MUST include a footprint build check that compiles the minimal server sample with the embedded profile.
- **FR-006**: CI MUST report the produced minimal server binary size as a reviewer-visible line item.
- **FR-007**: Documentation MUST describe when to use the base server path, when to use the full server path, and the compliance tradeoff of omitting the generated core namespace.
- **FR-008**: Validation MUST include a dependency-tree check demonstrating that the minimal sample does not pull the generated core namespace on normal dependencies.

### Key Entities

- **Facade Feature Set**: The user-facing umbrella crate features that decide which server APIs and dependencies are available.
- **Minimal Server Sample**: A small executable proving the base server path works through the umbrella crate.
- **Footprint Build Check**: The CI job and local command sequence that compile and report the minimal sample footprint.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: A minimal server executable builds successfully using the umbrella crate with only the base server feature enabled.
- **SC-002**: The minimal server dependency tree contains no generated core namespace crate on normal dependencies.
- **SC-003**: The embedded-profile minimal server binary is at least 25% smaller than the release-profile simple server measured in the audit.
- **SC-004**: Existing full server and no-default-feature library builds continue to compile.
- **SC-005**: A new or updated CI job displays the minimal binary size without adding external service dependencies.

## Assumptions

- The target deployment class is embedded Linux or small gateway systems, not bare-metal `no_std` systems.
- Omitting the generated core namespace is an explicit footprint tradeoff and may require the application to provide its own compliant address space.
- The current embedded profile remains the supported size-optimized profile for this work.
- CI size reporting is informational in this increment; hard numeric thresholds can be added after multiple stable baseline runs.
