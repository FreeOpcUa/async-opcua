# Feature Specification: Instance-Scoped Server State

**Feature Branch**: `049-instance-scoped-state`  
**Created**: 2026-07-01  
**Status**: Draft  
**Input**: User description: "Relocate process-global mutable statics in async-opcua-server onto their owning instances so multiple Server instances can run in one process without cross-instance coupling or key collision, and so test isolation is clean."

## Context

The 2026-07-01 lock/concurrency audit (and a deeper follow-up scan) found the server keeps a few
**process-global `static` mutable maps/counters**. These do **not** limit per-server request
parallelism — requests already run as concurrent spawned tasks on a multi-thread runtime — but they
couple otherwise-independent `Server` instances that share one process: cross-instance data collision,
no per-server reset, and awkward test isolation. This feature relocates the genuinely-instance state
onto its owning instance, and documents the statics that are deliberately global.

Two of the three targets are **correctness** issues (state keyed by data that is not globally unique);
the third is **isolation/hygiene** (globally-unique keys today, but still shared mutable state).

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Two servers do not cross-contaminate node-keyed state (Priority: P1)

As someone embedding two independent OPC UA `Server` instances in one process, node-scoped server state
of one server must never be visible to or overwritten by the other, even when both use the same
`NodeId` values (which are not unique across servers).

**Why this priority**: This is a real correctness defect today. Two node-keyed global maps —
FOTA cleanup resources and the per-node localized-text variant side-table — collide when two servers
share a `NodeId`, causing one server to read/evict the other's data.

**Independent Test**: Stand up two servers in one process that both register the same `NodeId`, exercise
the FOTA-cleanup path and the localized-text remember/read path on each, and confirm each server sees
only its own data.

**Acceptance Scenarios**:

1. **Given** two servers with a shared `NodeId`, **When** server A records FOTA cleanup resources for
   that node, **Then** server B's view of that node's cleanup resources is unaffected.
2. **Given** two servers with a shared `NodeId`, **When** server A remembers a written LocalizedText
   variant for that node/attribute, **Then** server B reads its own remembered variants, not A's, and
   neither server's clear/remove affects the other.

---

### User Story 2 - Each server has its own session-id space and locale map (Priority: P2)

As someone running multiple servers in one process, each server should manage its own session
identifiers and per-session locale state independently, so behavior and diagnostics are not entangled
across servers.

**Why this priority**: No data collision today (a global counter keeps numeric session ids unique
across servers), but the shared counter and shared locale map are unnecessary global coupling: a server
cannot reset its own session-id space, and test isolation is harder. Lower priority because it is
hygiene, not a correctness bug.

**Independent Test**: Create two servers, open sessions on each, set locales, and confirm each server's
session-id allocation and locale state are independent; closing one server does not affect the other's
session/locale state.

**Acceptance Scenarios**:

1. **Given** two servers, **When** each opens sessions, **Then** each server allocates session
   identifiers from its own space and its per-session locale state is isolated.
2. **Given** a session is closed/expired/terminated on one server, **When** its locale state is cleared,
   **Then** only that server's state changes (existing cleanup-on-teardown behavior preserved).

---

### User Story 3 - Deliberately-global state is documented and unchanged (Priority: P3)

As a maintainer, I want the statics that are *correctly* process-global to be explicitly documented as
such, so a future audit does not re-flag them and no one relocates them by mistake.

**Why this priority**: Prevents churn and re-litigation; low effort.

**Independent Test**: Read the code/docs and confirm each intentionally-global static carries a
one-line rationale, and none of them changed behavior.

**Acceptance Scenarios**:

1. **Given** the intentionally-global statics (process-wide config, uniqueness counters, per-thread
   scratch, immutable caches), **When** reviewed, **Then** each has a documented reason to stay global
   and is left unchanged.

### Edge Cases

- Two servers register the same `NodeId`; node-keyed state must stay isolated (US1).
- A single-server deployment (the normal case) must behave exactly as before — no observable change.
- Session teardown (close, expiry, terminate) must still clear per-session locale state, now per-server.
- The localized-text side-table's remove/replace-on-empty-locale behavior must be preserved per server.
- State ownership refactor must not alter request concurrency (already concurrent) or introduce a new
  hot-path lock or a guard held across `.await`.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: FOTA cleanup-resource state MUST be owned per `Server` instance so two servers sharing a
  `NodeId` never read, overwrite, or evict each other's cleanup resources.
- **FR-002**: The per-node written-LocalizedText variant side-table (used for locale negotiation on
  Read of DisplayName/Description/InverseName) MUST be owned per `Server` instance, preserving its
  remember, locale-match-replace, and clear-on-empty-locale behavior per server.
- **FR-003**: Numeric session-identifier allocation and per-session locale state MUST be owned per
  server (per `SessionManager`), so each server has an independent session-id space and locale map,
  while preserving the existing clear-on-close/expiry/terminate behavior.
- **FR-004**: Single-`Server` behavior MUST be unchanged; all existing tests MUST pass without
  modification (beyond mechanical wiring), and session-locale (Part 4 §5.4) and FOTA cleanup semantics
  MUST be preserved.
- **FR-005**: Each relocated item MUST be covered by a test that stands up two independent
  server/manager instances and proves their state is isolated (no cross-instance visibility).
- **FR-006**: The refactor MUST NOT change request-processing concurrency and MUST NOT introduce a new
  hot-path lock or a lock guard held across `.await` (verified by the existing await-holding lints).
- **FR-007**: Statics that are intentionally process-global MUST be documented with a one-line rationale
  and left unchanged: `SERIALIZATION_METRICS` (public API; relocation is a separate breaking
  observability decision), process-wide config (`TRACE_LOCKS_STATE`, `ENV_LOCK`), global-uniqueness
  counters (`TEMP_FILE_COUNTER`), per-thread scratch (secure-channel buffers, counting allocator), and
  immutable regex caches. Client-side session-id counter is out of scope (server-only feature).

### Key Entities

- **FOTA Cleanup Registry**: per-node cleanup resources; must become per-server owned.
- **Localized-Text Variant Side-Table**: `(NodeId, AttributeId) → written LocalizedText variants`; must
  become per-server owned.
- **Session Identity State**: session-id allocator + per-session locale map; must become per-server
  (per `SessionManager`) owned.
- **Intentionally-Global Static**: a process-wide static that is correct to share and is documented as
  such.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Two `Server` instances in one process that share `NodeId`s have fully isolated FOTA-cleanup
  and localized-text-variant state (demonstrated by tests that fail before the change and pass after).
- **SC-002**: Two servers allocate session identifiers from independent spaces and keep isolated
  per-session locale state; teardown on one does not affect the other.
- **SC-003**: A single-server deployment behaves identically to before; the full existing server test
  suite passes unchanged.
- **SC-004**: The await-holding lints remain clean and no new hot-path lock is introduced.
- **SC-005**: Every static that remains process-global carries a documented rationale.

## Assumptions

- The relocated state has a natural per-server owner reachable from its call sites (the server/handle,
  the address space, and the `SessionManager`); wiring the state through that owner is an internal
  change, not a public-API redesign, except where a public constructor must now carry the state.
- `NodeId` values are not unique across independent servers; numeric session ids are unique today only
  because of the shared global counter being relocated (so FR-003 relocates the counter and the map
  together to keep ids unique *within* a server).
- Single-server-per-process is and remains the dominant deployment; multi-server-per-process is the
  capability being unblocked.
- The localized-text side-table is a legitimate per-node server-side record (not derivable from the node
  attribute alone, since it remembers all written locale variants) and therefore belongs to the server's
  address-space-scoped state.
- **Intentional public API change (accepted 2026-07-01):** the public FOTA cleanup helpers
  (`fota::cleanup::register_session_file` / `register_session_file_path` / `cleanup_session`) change
  signature to carry the per-server owner (`&ServerInfo`). This is a breaking change, acceptable on the
  `0.x` (0.19.0) release, and required to fix the cross-server collision; callers already hold the owner.

## Out of Scope

- Changing request-processing concurrency (already concurrent) or any throughput/contention work — that
  is a separate, measurement-gated follow-up.
- Relocating `SERIALIZATION_METRICS` (public API; separate breaking observability decision).
- Client-side global session-id counter.
- Any change to the correctly-global process-wide statics beyond adding documentation.
