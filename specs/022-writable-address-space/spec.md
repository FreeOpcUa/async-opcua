# Feature Specification: Writable Address Space (NodeManagement)

**Feature Branch**: `022-writable-address-space`
**Created**: 2026-06-22
**Status**: Draft
**Input**: Implement the OPC UA NodeManagement service set (AddNodes / DeleteNodes / AddReferences /
DeleteReferences) for the in-memory node manager — Tier 3 facet #6 from the conformance backlog
(currently read-only by design → `BadServiceUnsupported`).

## Context *(mandatory)*

OPC UA servers may let clients modify the address space at runtime via the NodeManagement service set:
create nodes (AddNodes), remove nodes (DeleteNodes), and add/remove references between nodes
(AddReferences / DeleteReferences). In async-opcua the NodeManagement service is fully wired end-to-end
(request handling, per-item processing, the operational batch limit, and the node-manager extension
points), **but the in-memory node manager rejects every operation** with "service unsupported," so the
standard server cannot be made writable.

This feature implements those four operations for the in-memory node manager so a server can opt in to a
**writable address space**. It is **opt-in and off by default**: the existing read-only behavior is
preserved unless the operator explicitly enables client modification. Writing *values* to existing nodes
is a separate, already-supported concern; this feature is about **structural** mutation (nodes and
references).

Because NodeManagement is remotely reachable and operates on attacker-controllable input, correctness
and safety are paramount: every operation is validated, returns the precise OPC UA Part 4 §5.7 status
code, and never crashes the server.

## User Scenarios & Testing *(mandatory)*

### User Story 1 — Create and remove nodes at runtime (Priority: P1) 🎯 MVP

As an operator of a server that has enabled address-space modification, I want clients to add and delete
nodes at runtime so the address space can grow and shrink to reflect a changing system.

**Why this priority**: AddNodes/DeleteNodes is the core writable-address-space capability and is
independently useful and testable on its own.

**Independent Test**: With modification enabled, a client adds a node under an existing parent, then
Browses/Reads it successfully; deletes it, then Browse no longer finds it. Invalid attempts (duplicate
id, missing parent, unknown delete target) each return the documented status without affecting the rest.

**Acceptance Scenarios**:

1. **Given** modification is enabled and a valid parent node, **When** a client adds a node, **Then** the
   node is created with a reference from the parent, the result is success with the assigned node
   identifier, and a subsequent Browse/Read of that node succeeds.
2. **Given** an add request whose requested node identifier is already in use, **When** processed, **Then**
   it is rejected as "node id exists" and no node is created.
3. **Given** an add request whose parent/reference target does not exist, **When** processed, **Then** it
   is rejected as "parent node id invalid" (and reference-type/node-class/type-definition problems are
   rejected with their respective status), with no node created.
4. **Given** an existing node, **When** a client deletes it, **Then** it is removed (with its references
   per the delete options) and a subsequent Browse no longer finds it.
5. **Given** a delete request for a node that does not exist, **When** processed, **Then** it is rejected
   as "node id unknown."
6. **Given** a batch containing both valid and invalid items, **When** processed, **Then** each item gets
   its own correct status (valid ones applied, invalid ones rejected) and the server does not crash.

---

### User Story 2 — Add and remove references (Priority: P2)

As an operator with modification enabled, I want clients to add and remove references between nodes so
relationships in the address space can be maintained at runtime.

**Why this priority**: Completes the NodeManagement set; depends on the same plumbing as US1 but is
separable.

**Independent Test**: With modification enabled, a client adds a reference between two existing nodes,
then Browse from the source shows the new reference; removes it, then Browse no longer shows it. Invalid
references return the documented status.

**Acceptance Scenarios**:

1. **Given** two existing nodes and a valid reference type, **When** a client adds a reference between
   them, **Then** it succeeds and a subsequent Browse from the source reflects it (respecting direction).
2. **Given** an add-reference request with an invalid source, target, or reference type, **When**
   processed, **Then** it is rejected with the corresponding status (source/target/reference-type
   invalid).
3. **Given** an existing reference, **When** a client removes it, **Then** it succeeds and a subsequent
   Browse no longer shows it.

---

### User Story 3 — Demonstrate, gate, and validate edges (Priority: P3)

As a developer and as an operator, I want the writable address space demonstrated and the safety gate
proven, so the feature is usable and clearly off-by-default.

**Why this priority**: Demonstration + edge/gating hardening; depends on US1/US2.

**Independent Test**: The sample server shows a writable node manager (or a documented switch). With the
gate disabled, every NodeManagement operation is refused with the documented status. Edge cases (delete a
node with children, duplicate add, add under missing parent, oversized batch) all return documented
statuses with no crash.

**Acceptance Scenarios**:

1. **Given** modification is **disabled** (default), **When** any AddNodes/DeleteNodes/AddReferences/
   DeleteReferences request is made, **Then** it is refused with the documented status and the address
   space is unchanged.
2. **Given** the sample server with modification enabled, **When** a client performs the operations,
   **Then** they behave as in US1/US2.
3. **Given** edge inputs (delete a node that has children/references, duplicate add, missing parent, a
   batch at/over the operational limit), **When** processed, **Then** each returns the documented status
   and the server never crashes.

---

### Edge Cases

- **Gate off (default)**: every NodeManagement operation refused with the documented status; address
  space untouched.
- **Duplicate node id** on add → "node id exists"; **missing parent / reference target** → "parent node
  id invalid"; **invalid reference type / node class / type definition** → the respective status.
- **Delete unknown node** → "node id unknown"; **delete a node with children/references** → handled per
  the delete options (target references cleaned up as requested), no dangling-reference crash.
- **Add/remove reference with invalid source/target/reference-type** → respective status.
- **Oversized batch** → bounded by the existing operational limit; **crafted/malformed items** → rejected
  per-item, never a panic or server crash.
- **Mixed valid/invalid batch** → per-item statuses, partial success.

## Requirements *(mandatory)*

- **FR-001**: The in-memory node manager MUST implement AddNodes: on success, create the node, link it
  from the specified parent via the specified reference, and return success with the node's identifier;
  a subsequent Browse/Read MUST reflect the new node.
- **FR-002**: The in-memory node manager MUST implement DeleteNodes: remove the node and its references
  (honoring the "delete target references" option); a subsequent Browse MUST NOT find it.
- **FR-003**: The in-memory node manager MUST implement AddReferences and DeleteReferences: add/remove a
  reference between nodes (honoring direction and source/target ownership), reflected by a subsequent
  Browse.
- **FR-004**: All four operations MUST return the OPC UA Part 4 §5.7 per-operation status codes —
  including (at least) node-id-exists, parent-node-id-invalid, node-id-unknown, reference-type-invalid,
  source/target-node-id-invalid, node-class-invalid, type-definition-invalid — and MUST process each item
  in a batch independently (partial success), with no silent success on invalid input.
- **FR-005**: The capability MUST be **opt-in**, gated by the server's existing "clients can modify
  address space" configuration; when disabled (the default), every operation is refused with the
  documented status and the address space is unchanged (no behavior change vs today).
- **FR-006**: The feature MUST be **additive / non-breaking**: existing node managers and the in-memory
  node-manager extension surface remain source-compatible (no downstream impl is forced to change), and
  existing read-only servers behave exactly as before.
- **FR-007** (Security): Every operation MUST be safe on attacker-controlled input — validity/bounds
  checked, never panicking or crashing the server on malformed/duplicate/cyclic/oversized input (the
  batch size is already capped by the operational limit). The mutated address space MUST remain
  internally consistent (no dangling references after a delete).
- **FR-008**: The mutated address space MUST stay consistent for reads/browse/subscriptions: an added
  node is immediately browsable/readable; a deleted node and its references are gone.
- **FR-009**: The sample server MUST demonstrate the writable address space (a node manager with
  modification enabled, or a documented config switch), without changing the default (read-only) behavior
  of the existing sample configuration.
- **FR-010**: No new runtime dependency; the workspace MUST build and lint clean (`clippy --all-targets
  --all-features` plus the no-default-features / json-off legs under `-D warnings`); existing suites pass.

### Key Entities *(include if feature involves data)*

- **Add-node request item**: parent node, reference type linking parent→new node, requested node
  identifier (or "let the server assign"), node class, browse name, type definition, and node attributes
  → outcome (assigned identifier + status).
- **Delete-node request item**: target node + whether to also delete references that point at it →
  outcome status.
- **Add/Delete-reference request item**: source node, reference type, direction, target node + (for add)
  target node class → outcome status.
- **Modification gate**: the server configuration flag that enables/disables client address-space
  modification.

## Success Criteria *(mandatory)*

- **SC-001**: With modification enabled, a client can add a node and then Browse/Read it, and delete a
  node and then confirm it is gone — verified end-to-end through the service.
- **SC-002**: With modification enabled, a client can add a reference (reflected by Browse) and remove it
  (no longer in Browse).
- **SC-003**: Every invalid operation (duplicate id, missing parent, unknown delete, invalid
  source/target/reference-type) returns the documented Part 4 §5.7 status; batches yield per-item
  statuses; no operation ever panics or crashes the server.
- **SC-004**: With modification disabled (default), every NodeManagement operation is refused with the
  documented status and the address space is unchanged — existing servers are unaffected.
- **SC-005**: `clippy --all-targets --all-features` + the no-default-features / json-off legs are clean
  under `-D warnings`; no new runtime dependency; existing unit and integration suites pass.

## Assumptions

- **Scope = the in-memory node manager** (the one backing the standard/sample server). Other node
  managers opt into writability themselves; this feature does not make them writable.
- **Gate** = the "clients can modify address space" server config flag; default OFF. NOTE: this flag is
  currently only present in the sample config file and is not yet a wired configuration field, so this
  feature adds/wires it (additive, default OFF). When OFF, the operations return the same
  "unsupported/not-allowed" status they do today (no behavior change).
- **Node identifier assignment**: a client requests a specific (free) identifier in a namespace the
  in-memory manager owns; duplicate requested identifiers are rejected (`BadNodeIdExists`). NOTE:
  fully **server-assigned** (null) identifiers route only to a manager that opts in via the existing
  `handle_new_node` extension point (the `TestNodeManager` demonstrates this); the standard in-memory
  default does not claim null-id adds (to avoid intercepting other managers' namespaces), so a client
  specifies the new id. This is a refinement of the original "or server-assigned" intent.
- **Verification division** (established): the production mutation logic + config gating + demo wiring may
  be implemented by the code-generation assistant; ALL tests are authored and run independently, anchored
  to OPC UA Part 4 §5.7 status-code semantics and real address-space round-trips (add→browse/read,
  delete→browse-absent, reference add/remove→browse), including end-to-end through the service and a
  no-panic pass on crafted input.
- **Out of scope / deferred**: model-change event emission (`GeneralModelChangeEventType`); persisting the
  mutated address space across restarts; AddNodes for complex typed instances beyond what the address
  space + type tree already support; writability for node managers other than the in-memory one.
