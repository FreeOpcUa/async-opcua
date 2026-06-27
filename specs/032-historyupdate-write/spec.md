# Feature Specification: Historical Access write — full HistoryUpdate service

**Feature Branch**: `032-historyupdate-write`
**Created**: 2026-06-27
**Status**: Draft
**Input**: Complete the OPC UA Part 11 Historical Access *write* surface (HistoryUpdate service, Part 4 §11.7) in `async-opcua-server` and `async-opcua-history-sqlite`, reusing the existing dispatch/RBAC framework.

## User Scenarios & Testing *(mandatory)*

A "user" here is a client application performing historical-access writes against an async-opcua
server, or a server integrator wiring a historized node manager. The protocol layer (service
decode, per-node dispatch, RBAC permission gating) already exists; the deliverable is the storage
behaviour behind it so that HistoryUpdate operations actually persist and return spec-correct
per-operation results instead of `Bad_HistoryOperationUnsupported`.

### User Story 1 - Insert/Replace/Update/Remove historical data values (Priority: P1)

A client writes raw historical data values into a historized variable's history using HistoryUpdate
`UpdateData` with each of the four update modes, and receives a per-value result that reflects what
happened.

**Why this priority**: `UpdateData` is the foundational and most-used HistoryUpdate operation; every
other data operation builds on the same storage. Without it the write side is unusable.

**Independent Test**: Against the reference persistence backend, issue `UpdateData` with Insert,
Replace, Update, and Remove modes and assert the per-value operation results and the resulting
HistoryRead contents.

**Acceptance Scenarios**:

1. **Given** a historized variable with no value at timestamp T, **When** `UpdateData(Insert)` writes a value at T, **Then** the per-value result is `Good_EntryInserted` and a subsequent HistoryRead returns it.
2. **Given** a value already exists at T, **When** `UpdateData(Insert)` writes at T, **Then** the per-value result is `Bad_EntryExists` and the stored value is unchanged.
3. **Given** a value exists at T, **When** `UpdateData(Replace)` writes at T, **Then** the result is `Good_EntryReplaced` and HistoryRead returns the new value.
4. **Given** no value exists at T, **When** `UpdateData(Replace)` writes at T, **Then** the result is `Bad_NoEntryExists` and nothing is stored.
5. **Given** any state at T, **When** `UpdateData(Update)` writes at T, **Then** the value is inserted-or-replaced and the result is `Good_EntryInserted` (newly created) or `Good_EntryReplaced` (overwritten).
6. **Given** a value exists at T, **When** `UpdateData(Remove)` is applied at T, **Then** the value is deleted and the result is `Good` (`Bad_NoEntryExists` if absent).

### User Story 2 - In-memory historical-data store for the default node managers (Priority: P1)

A server integrator using the in-memory `InMemoryNodeManager`/`SimpleNodeManager` can enable history
on a variable and have HistoryRead (raw) and HistoryUpdate `UpdateData` work without an external
database, mirroring the existing in-memory event-history pattern.

**Why this priority**: the default server has no historical-data store today; without it HistoryUpdate
can only be demonstrated with the optional sqlite crate, and the default-path integration tests
cannot exercise the service.

**Independent Test**: Configure a historized variable on the default in-memory manager, perform
`UpdateData` writes, and read them back via HistoryRead — no sqlite involved.

**Acceptance Scenarios**:

1. **Given** the in-memory store enabled on a variable, **When** `UpdateData(Insert)` writes N values, **Then** HistoryRead raw returns the N values in time order.
2. **Given** the in-memory store, **When** the same Insert/Replace/Update/Remove matrix from US1 is applied, **Then** the per-value results and read-back contents match US1's spec semantics.
3. **Given** a manager with no history store, **When** HistoryUpdate is called, **Then** it still returns `Bad_HistoryOperationUnsupported` (backwards compatible).

### User Story 3 - Delete historical data by range and by timestamp (Priority: P2)

A client deletes historical data either over a time range (`DeleteRawModified`) or at an explicit list
of timestamps (`DeleteAtTime`).

**Why this priority**: deletion completes data lifecycle management; it depends on the storage from
US1/US2 but is independent of update.

**Independent Test**: Populate history, issue `DeleteRawModified` over a range and `DeleteAtTime` for
specific timestamps, and assert the deletions and per-entry results.

**Acceptance Scenarios**:

1. **Given** raw values spanning [start, end), **When** `DeleteRawModified(isDeleteModified=false)` is applied, **Then** all raw values in the range are removed.
2. **Given** no values in the requested range, **When** `DeleteRawModified` is applied, **Then** the operation result is `Bad_NoData`.
3. **Given** modified-history entries in a range, **When** `DeleteRawModified(isDeleteModified=true)` is applied, **Then** the modified entries are removed and raw values are untouched.
4. **Given** values at timestamps [T1, T2, T3], **When** `DeleteAtTime([T1, T3, T_absent])` is applied, **Then** T1 and T3 are removed and the per-timestamp results are `Good, Good, Bad_NoEntryExists`.

### User Story 4 - Modified-history tracking for replaced/deleted values (Priority: P2)

When a value is replaced, updated-over, or deleted, the prior value is retained as a modified-history
entry so that HistoryRead with `isReadModified` returns the superseded values with their update type
and modification metadata.

**Why this priority**: Part 11 §6.5 requires modified values to be queryable after a Replace/Delete;
auditing and undo depend on it. It layers on top of US1–US3 storage.

**Independent Test**: Replace and delete values, then HistoryRead modified and assert the prior values
appear with the correct update type and modification timestamp/user.

**Acceptance Scenarios**:

1. **Given** a value V1 at T, **When** it is replaced by V2, **Then** HistoryRead modified at T returns V1 tagged with update type Replace and a modification time/user.
2. **Given** a value at T, **When** it is deleted, **Then** HistoryRead modified at T returns the deleted value tagged with update type Delete.
3. **Given** a value never modified, **When** HistoryRead modified is requested, **Then** no modified entry is returned for it.

### User Story 5 - Annotation history write (Priority: P2)

A client annotates history by writing `Annotation` values via `UpdateStructureData`
(insert/replace/update/remove an annotation at a timestamp).

**Why this priority**: annotations are a distinct structured-history type; the read side already
exists, so completing the write side closes the annotation loop.

**Independent Test**: Write annotations via `UpdateStructureData` and read them back via the
annotation HistoryRead path.

**Acceptance Scenarios**:

1. **Given** no annotation at T, **When** `UpdateStructureData(Insert)` writes an Annotation at T, **Then** the result is `Good_EntryInserted` and the annotation read path returns it.
2. **Given** an annotation at T, **When** `UpdateStructureData(Replace)` is applied, **Then** the annotation is replaced (`Good_EntryReplaced`).
3. **Given** an annotation at T, **When** `UpdateStructureData(Remove)` is applied, **Then** it is deleted.

### User Story 6 - Event history write (Priority: P3)

A client writes events into event history (`UpdateEvent`) and deletes events by EventId
(`DeleteEvent`), filtered/shaped by the supplied event filter.

**Why this priority**: event history write is the lowest-frequency operation and depends on the event
filter/field machinery; it completes the service surface.

**Independent Test**: Insert events via `UpdateEvent`, read them via the event HistoryRead path, then
delete by EventId via `DeleteEvent` and confirm removal.

**Acceptance Scenarios**:

1. **Given** an event source with event history, **When** `UpdateEvent(Insert)` adds an event, **Then** the event HistoryRead path returns it and the result is `Good_EntryInserted`.
2. **Given** an existing event at a key, **When** `UpdateEvent(Replace)` is applied, **Then** it is replaced.
3. **Given** stored events, **When** `DeleteEvent([eventId1, eventId_absent])` is applied, **Then** event 1 is removed and the per-id results are `Good, Bad_NoEntryExists`.

### User Story 7 - End-to-end server + client wiring (Priority: P3)

A server exposes a historized variable and an event source that accept HistoryUpdate, and a client
can drive the full write surface through the client API.

**Why this priority**: turns the building blocks into a usable, demonstrable feature and provides the
end-to-end conformance path.

**Independent Test**: Run the demo/integration server, issue each HistoryUpdate operation from the
client, and assert results round-trip through HistoryRead.

**Acceptance Scenarios**:

1. **Given** a running server with a historized variable, **When** a client issues `UpdateData` and then HistoryRead, **Then** the written values are returned.
2. **Given** the client API, **When** `history_update` is called for each operation type, **Then** the typed request/response round-trips without manual ExtensionObject handling.

### Edge Cases

- HistoryUpdate targeting a non-historized node returns `Bad_HistoryOperationUnsupported` (or `Bad_NotSupported`) per node, not a whole-request failure.
- A request mixing valid and invalid entries returns per-entry results; the overall `HistoryUpdateResult.statusCode` reflects the operation, with `operationResults[]` sized to the entries.
- Duplicate timestamps within a single `UpdateData(Insert)` batch resolve deterministically (the later entry yields `Bad_EntryExists`).
- A session lacking the required history permission (InsertHistory/ModifyHistory/DeleteHistory) is denied per the existing RBAC gating — unchanged by this feature.
- Time ranges with start > end, empty timestamp lists, and empty value arrays are handled without panic and return the appropriate per-operation status.
- Values written with only a source timestamp vs. both source/server timestamps round-trip consistently.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The system MUST implement `UpdateData` for all four `PerformUpdateType` modes (Insert, Replace, Update, Remove) with Part 4 §11.7 per-value operation results (`Good_EntryInserted`, `Good_EntryReplaced`, `Bad_EntryExists`, `Bad_NoEntryExists`).
- **FR-002**: The system MUST implement `DeleteRawModified` (delete raw OR modified values over a [start, end) range honoring `isDeleteModified`), returning `Bad_NoData` when the range is empty.
- **FR-003**: The system MUST implement `DeleteAtTime` (delete values at an explicit timestamp list) with per-timestamp operation results (`Bad_NoEntryExists` where absent).
- **FR-004**: The system MUST implement `UpdateStructureData` for `Annotation` history (insert/replace/update/remove) with the same per-entry result semantics.
- **FR-005**: The system MUST implement `UpdateEvent` (insert/replace/update events) and `DeleteEvent` (delete by EventId) with per-entry operation results.
- **FR-006**: The system MUST record modified-history entries when a value is replaced, updated-over, or deleted, so HistoryRead with `isReadModified` returns the superseded value tagged with its update type and modification metadata (Part 11 §6.5).
- **FR-007**: The system MUST size `HistoryUpdateResult.operationResults[]` to the number of entries in each details object and set `HistoryUpdateResult.statusCode` per the Part 4 §11.7 result tables.
- **FR-008**: The `async-opcua-history-sqlite` reference backend MUST persist all six HistoryUpdate operations to its store.
- **FR-009**: The system MUST provide an in-memory historical-data store usable by the default `InMemoryNodeManager`/`SimpleNodeManager` that supports HistoryRead (raw + modified) and all HistoryUpdate operations, requiring no external database.
- **FR-010**: The system MUST continue to enforce the existing RBAC history permissions (InsertHistory/ModifyHistory/DeleteHistory) via the existing `HistoryUpdateDetails::required_permission()` gating, unchanged.
- **FR-011**: Node managers that do not provide a history store MUST continue to return `Bad_HistoryOperationUnsupported`, preserving backwards compatibility.
- **FR-012**: The client API MUST expose typed `history_update` coverage for each operation type, and a server example MUST expose a historized variable and event source that accept HistoryUpdate end-to-end.
- **FR-013**: All HistoryUpdate handling MUST return per-node/per-entry results rather than failing the whole request, and MUST NOT panic on malformed input (empty arrays, inverted ranges, absent timestamps).
- **FR-014**: The feature MUST build and pass under both `--no-default-features` and `--all-features` (the sqlite backend lives in `async-opcua-history-sqlite`; the in-memory store lives in `async-opcua-server`).
- **FR-015**: The existing `HistoryUpdateDetails` framework, dispatch path, and `HistoryUpdateNode` result API MUST be reused, not rebuilt.

### Key Entities *(include if feature involves data)*

- **HistoryUpdateDetails** (existing): the six-variant union describing one update operation (UpdateData, UpdateStructureData, UpdateEvent, DeleteRawModified, DeleteAtTime, DeleteEvent).
- **Historical data entry**: a stored `(source timestamp, server timestamp, value, status code)` tuple for a node, plus an update-type/modification tag distinguishing raw vs. modified entries.
- **Modified-history entry**: a superseded raw entry retained on Replace/Update/Delete, carrying the `HistoryUpdateType` and modification metadata (time, user).
- **Annotation history entry**: an `Annotation` value (message, user, annotation time) keyed by timestamp.
- **Event history entry**: a recorded event (its field values per a known event filter) keyed by EventId/time.
- **HistoryUpdateResult** (existing types): `statusCode` + `operationResults[]` + optional diagnostics returned per details object.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: All six HistoryUpdate operations (UpdateData, UpdateStructureData, DeleteRawModified, DeleteAtTime, UpdateEvent, DeleteEvent) return spec-correct results instead of `Bad_HistoryOperationUnsupported` on both the sqlite backend and the in-memory store.
- **SC-002**: 100% of the Part 4 §11.7 per-operation result codes exercised in scope (`Good_EntryInserted`, `Good_EntryReplaced`, `Bad_EntryExists`, `Bad_NoEntryExists`, `Bad_NoData`) are produced under the matching preconditions, verified by tests.
- **SC-003**: A value replaced or deleted is retrievable via HistoryRead modified with the correct update type — verified end-to-end.
- **SC-004**: A client can perform every HistoryUpdate operation against a running server and observe the effect via HistoryRead, with no manual ExtensionObject construction.
- **SC-005**: Existing behaviour is unchanged for managers without a history store (still `Bad_HistoryOperationUnsupported`) and for HistoryRead/HistoryUpdate already shipped — no regressions in the full test suite.
- **SC-006**: The workspace builds and tests pass under `--no-default-features` and `--all-features`, with `clippy` and `fmt` clean.

## Assumptions

- The existing `HistoryUpdateDetails` parsing, per-node dispatch, and `required_permission()` RBAC mapping in `async-opcua-server/src/node_manager/history.rs` are correct and are reused as-is.
- The `async-opcua-history-sqlite` schema may be extended (additional columns/tables for modified-history, annotations, events) but remains the reference persistence backend.
- Modified-history metadata uses the requesting session's identity and the server time at the moment of update; exact "user" representation follows what HistoryRead modified already expects.
- Event-history write reuses the event field/filter machinery already used by the A&C `InMemoryEventHistory` and the sqlite `read_events` path.
- "Reasonable defaults" for unspecified result-code edges follow the Part 4 §11.7 / Part 11 §6 tables; where the spec leaves a case implementation-defined, the in-memory store and sqlite backend behave identically.

## Spec Traceability

| Requirement | OPC UA reference |
|---|---|
| FR-001 UpdateData modes | Part 11 §6.8.2; Part 4 §11.7.2 (UpdateDataDetails) |
| FR-002 DeleteRawModified | Part 11 §6.9.2; Part 4 §11.7.6 |
| FR-003 DeleteAtTime | Part 11 §6.9.3; Part 4 §11.7.7 |
| FR-004 UpdateStructureData / Annotations | Part 11 §6.8.3; Part 4 §11.7.3 |
| FR-005 UpdateEvent / DeleteEvent | Part 11 §6.8.4 / §6.9.4; Part 4 §11.7.4 / §11.7.8 |
| FR-006 Modified history | Part 11 §6.5 (modified values); §3.1 HistoryUpdateType |
| FR-007 Result semantics | Part 4 §11.7 (HistoryUpdate service, result tables) |
| FR-010 History permissions | Part 3 §8.55 (InsertHistory/ModifyHistory/DeleteHistory) |
