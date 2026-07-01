# Feature Specification: Facade Exposure of PubSub and SQLite History

**Feature Branch**: `047-facade-pubsub-history`  
**Created**: 2026-07-01  
**Status**: Draft  
**Input**: User description: "Expose async-opcua-pubsub and async-opcua-history-sqlite as optional, default-OFF facade dependencies of the async-opcua umbrella crate, with re-exports so consumers can use them through the umbrella crate instead of depending on the sub-crates directly."

## Context

The `async-opcua` umbrella crate is a facade that re-exports the workspace's sub-crates behind
features (`client` → `opcua::client`, `server`/`base-server` → `opcua::server` + `opcua::nodes`,
`xml` → `opcua::xml`, `generated-address-space` → `opcua::core_namespace`). Two sub-crates are the
exception: `async-opcua-pubsub` and `async-opcua-history-sqlite` are present **only as
dev-dependencies** of the umbrella crate (used by its own integration tests) and are **not exposed to
consumers at all**.

A prior YAGNI-audit backlog item ("native") claimed the opposite — that these two crates were
non-optional dependencies forced onto every consumer. That premise was verified **false** (`cargo tree
-p async-opcua -e no-dev` shows zero pubsub/history/sqlite/AMQP/MQTT/WebSocket in a downstream build;
the audit misread the `[dev-dependencies]` section as `[dependencies]`). The real, opposite gap is a
facade-completeness hole: a consumer who wants OPC UA PubSub or SQLite historical storage **through the
umbrella crate** cannot, and must instead depend on the internal sub-crates directly — coupling their
build to internal crate names and versions the facade is meant to hide.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Use PubSub Through the Umbrella Crate (Priority: P1)

A developer building an OPC UA application depends on `async-opcua` and wants OPC UA Part 14 PubSub
publish/subscribe functionality without adding a second, internal-named crate to their manifest.

**Why this priority**: PubSub is the larger and more visible of the two missing subsystems, and the
facade-consistency gap is most surprising here (client/server are re-exported, PubSub is not).

**Independent Test**: In a manifest enabling only the umbrella crate's PubSub feature, reference the
PubSub API through the umbrella crate path and confirm it compiles and resolves to the same public API
the sub-crate provides.

**Acceptance Scenarios**:

1. **Given** a consumer enables the umbrella crate's PubSub feature, **When** they reference PubSub
   types through the umbrella crate namespace, **Then** the code compiles and exposes the same PubSub
   public API as depending on the sub-crate directly.
2. **Given** a consumer does **not** enable the PubSub feature, **When** they build, **Then** the
   PubSub namespace is absent from the umbrella crate and no PubSub-related dependencies are compiled.

---

### User Story 2 - Use SQLite Historical Storage Through the Umbrella Crate (Priority: P2)

A developer wants the reference SQLite-backed historical data/event storage backend available through
`async-opcua` to wire into their server's Historical Access, without depending on the internal
history sub-crate directly.

**Why this priority**: Symmetric to US1 but a smaller, more specialized subsystem; still a real
facade-completeness gap for anyone building a history-enabled server through the umbrella crate.

**Independent Test**: In a manifest enabling only the umbrella crate's history feature, reference the
SQLite history backend through the umbrella crate path and confirm it compiles and resolves to the
sub-crate's public API.

**Acceptance Scenarios**:

1. **Given** a consumer enables the umbrella crate's history feature, **When** they reference the
   SQLite history backend through the umbrella crate namespace, **Then** the code compiles and exposes
   the same public API as the sub-crate.
2. **Given** a consumer does **not** enable the history feature, **When** they build, **Then** the
   history namespace is absent and no SQLite/native-library dependencies are compiled.

---

### User Story 3 - Footprint and Existing Builds Are Unaffected (Priority: P3)

A maintainer needs assurance that adding these opt-in features does not enlarge the default footprint
(preserving the feature-040 minimal-footprint guarantee) and does not break any existing feature
combination or the umbrella crate's own test suite.

**Why this priority**: Guardrail. The value of the new features is undermined if they leak into default
builds or destabilize existing ones.

**Independent Test**: Build the umbrella crate with default features and confirm the non-dev dependency
graph still contains no PubSub/history/SQLite dependency; build the previously-supported feature
combinations and run the test suite and confirm they are unchanged.

**Acceptance Scenarios**:

1. **Given** the new features exist, **When** the umbrella crate is built with default features,
   **Then** the non-development dependency graph contains no PubSub, history, SQLite, AMQP, MQTT, or
   WebSocket dependency.
2. **Given** existing consumers on any previously-supported feature combination, **When** they build
   after this change, **Then** their build behaves exactly as before (no new required features, no
   removed items).
3. **Given** the umbrella crate's own test suite (which exercises PubSub and history), **When** it is
   run after this change, **Then** all tests pass.

### Edge Cases

- A consumer enables the PubSub or history feature but none of the crypto-backend features — the
  subsystem must still build with a coherent default crypto backend, consistent with how the rest of
  the facade behaves.
- A consumer enables a crypto/policy feature (e.g. the constant-time backend, legacy policies, ECC) at
  the umbrella level — that selection must reach the newly-exposed subsystems where they share those
  features, so a single facade-level choice is not silently inconsistent across subsystems.
- The umbrella crate's own tests currently reach these subsystems via direct dev-dependencies — after
  exposure they must remain buildable and unambiguous (no duplicate/conflicting dependency surface).
- A consumer enables the subsystem feature together with `no-default-features` — exposure must not
  implicitly force the default crypto backend or any other default the consumer opted out of.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The umbrella crate MUST provide an opt-in feature that makes the PubSub subsystem
  available as an optional dependency and re-exports its public API through the umbrella crate.
- **FR-002**: The umbrella crate MUST provide an opt-in feature that makes the SQLite historical
  storage subsystem available as an optional dependency and re-exports its public API through the
  umbrella crate.
- **FR-003**: Neither new feature MAY be a member of the umbrella crate's `default` feature set.
- **FR-004**: When a new feature is disabled, its re-exported namespace and all of its unique
  transitive dependencies MUST be absent from the consumer's build.
- **FR-005**: The re-export surface for each subsystem MUST expose the same public API as depending on
  the corresponding sub-crate directly (a re-export, not a curated subset).
- **FR-006**: Umbrella-level feature selections that the subsystems also understand (crypto backend
  such as the default constant-time backend, legacy policies, ECC) MUST forward to the newly-exposed
  subsystems, consistent with how those features forward to client/server today.
- **FR-007**: All previously-supported umbrella feature combinations MUST continue to build with
  unchanged externally visible behavior; no existing feature may be removed or gain a new mandatory
  member.
- **FR-008**: The umbrella crate's existing test suite MUST continue to pass, reaching the PubSub and
  history subsystems through a single, unambiguous dependency surface.
- **FR-009**: Documentation MUST describe the two new opt-in features and how to reach each subsystem
  through the umbrella crate, alongside the existing footprint/compliance guidance.

### Key Entities

- **Facade Feature**: A user-facing umbrella feature (`pubsub`, `history`) that toggles both an
  optional dependency and its re-export.
- **Optional Subsystem Dependency**: The PubSub / SQLite-history sub-crate, pulled only when its
  facade feature is enabled.
- **Re-export Namespace**: The umbrella-crate path (e.g. `opcua::pubsub`, `opcua::history`) through
  which the subsystem's public API becomes reachable.
- **Feature-Forwarding Set**: The umbrella features (crypto backend, legacy, ecc) that must propagate
  to the newly-exposed subsystems.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: A consumer can compile a program that uses the PubSub subsystem while depending only on
  the umbrella crate with its PubSub feature enabled (no direct sub-crate dependency).
- **SC-002**: A consumer can compile a program that uses the SQLite history subsystem while depending
  only on the umbrella crate with its history feature enabled (no direct sub-crate dependency).
- **SC-003**: A default-feature build of the umbrella crate has a non-development dependency graph with
  zero PubSub, history, SQLite, AMQP, MQTT, or WebSocket entries (verifiable with a dependency-graph
  inspection that excludes dev-dependencies).
- **SC-004**: Every previously-supported umbrella feature combination and the umbrella crate's test
  suite build and pass unchanged after the feature is added.
- **SC-005**: Enabling only a subsystem feature (with no explicit crypto-backend feature) produces a
  build that uses the same default crypto backend as the rest of the facade.

## Assumptions

- Re-export names follow the existing facade convention (`opcua::<subsystem>`); `opcua::pubsub` and
  `opcua::history` are the intended paths for PubSub and SQLite-history respectively.
- The umbrella crate's own integration tests will reach these subsystems through the new features
  (enabled in the crate's own dev/test configuration) rather than through separate direct
  dev-dependencies, to keep a single dependency surface — provided this does not change test behavior.
- Feature forwarding mirrors the existing `?`-guarded optional-forwarding style already used for
  client/server so that enabling a subsystem feature does not itself force unrelated defaults.
- PubSub and SQLite-history public APIs and behavior are unchanged; this feature is purely facade
  packaging.
- The target consumers are library users who prefer a single `async-opcua` dependency surface over
  wiring internal sub-crates directly.

## Out of Scope

- Any change to PubSub or SQLite-history behavior, public API, or internal structure.
- Adding either feature to the `default` feature set.
- Exposing other workspace crates not named here; the multi-cert mixed-server work.
- Non-SQLite history backends (the in-memory backend lives in the server crate and is already reachable).
