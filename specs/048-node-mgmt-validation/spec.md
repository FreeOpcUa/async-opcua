# Feature Specification: Node-Management Validation Hardening

**Feature Branch**: `048-node-mgmt-validation`  
**Created**: 2026-07-01  
**Status**: Draft  
**Input**: User description: "Complete the AddNodes/AddReferences validation surface on the server's opt-in writable address space (memory NodeManager, gated by `clients_can_modify_address_space`, default OFF), closing conformance-audit findings P4-NODEMGMT-01, P3-03, P3-05, P3-06, P3-07."

## Context

The server's memory NodeManager supports client-driven NodeManagement (AddNodes/AddReferences/
DeleteNodes/DeleteReferences) behind an opt-in flag (`clients_can_modify_address_space`, default OFF).
The 2026-07-01 conformance reconciliation ([`specs/conformance-audit/FINDINGS.md`](../conformance-audit/FINDINGS.md))
confirmed that several validations required by OPC UA Part 3 / Part 4 are still missing or partial on
that path. Standard nodeset loading already produces correct nodes; these gaps are reachable by a
client performing AddNodes/AddReferences (or by programmatic node construction). This feature closes the
cluster. It changes **only** the opt-in writable path — the default read-only behavior is unchanged.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Reject AddReferences with a mismatched target NodeClass (Priority: P1)

As a client using the writable address space, when I add a reference whose declared `targetNodeClass`
does not match the actual NodeClass of the target node, the server rejects that operation with the
spec-defined status rather than silently accepting it.

**Why this priority**: The `targetNodeClass` is already carried on the request and used only for audit
events; validating it is a small, self-contained, high-value correctness win with a clear status code.

**Independent Test**: Enable the writable address space, AddReferences with a `targetNodeClass` that
disagrees with the real target node's class, and confirm a per-operation Bad status; confirm a matching
`targetNodeClass` (and the sentinel "unspecified" value) still succeeds.

**Acceptance Scenarios**:

1. **Given** a target node of a known NodeClass, **When** AddReferences declares a different
   `targetNodeClass`, **Then** that operation returns the spec-defined mismatch status and no reference
   is created.
2. **Given** a target node, **When** AddReferences declares the matching `targetNodeClass` or leaves it
   unspecified, **Then** the reference is created as before.

---

### User Story 2 - Reject instantiation of an abstract type definition (Priority: P1)

As a client using the writable address space, when I AddNodes with a `typeDefinition` that is an
abstract ObjectType/VariableType, the server rejects it — including abstract **standard** types that
exist only in the type metadata (not as full nodes in the address space).

**Why this priority**: Instantiating an abstract type is a Part 3 violation and the current check has a
hole: abstract standard base types (e.g. the abstract roots) pass because abstractness isn't queryable
for type-metadata-only types. Closing it is a conformance + integrity fix.

**Independent Test**: AddNodes with an abstract standard type as `typeDefinition` and confirm rejection
with the spec-defined status; confirm a concrete type still succeeds; confirm abstract types already
present as full nodes are still rejected (no regression).

**Acceptance Scenarios**:

1. **Given** an abstract type definition (whether a full node or type-metadata-only), **When** AddNodes
   references it as the new node's `typeDefinition`, **Then** the operation returns the spec-defined
   status and no node is created.
2. **Given** a concrete (non-abstract) type definition, **When** AddNodes uses it, **Then** the node is
   created as before.

---

### User Story 3 - Enforce hierarchical-reference structural rules (Priority: P2)

As a client using the writable address space, when I add a hierarchical reference between nodes whose
NodeClasses are not valid for that reference type, the server rejects it — not only the single
`HasProperty→Variable` case checked today, but the general structural constraint.

**Why this priority**: Broadens an existing partial check into the general rule; medium risk because
"valid NodeClass combinations per hierarchical reference type" must be defined carefully to avoid
rejecting legitimate models.

**Independent Test**: Attempt hierarchical references with invalid source/target NodeClass combinations
(e.g. a Property target that isn't a Variable, an Organizes to a disallowed class) and confirm
rejection; confirm all combinations the standard nodeset uses still succeed.

**Acceptance Scenarios**:

1. **Given** a hierarchical reference type with defined NodeClass constraints, **When** AddReferences
   connects NodeClasses that violate them, **Then** the operation returns the spec-defined status.
2. **Given** any source/target combination used by the standard core nodeset, **When** it is added,
   **Then** it succeeds (no false rejections).

---

### User Story 4 - Enforce HasTypeDefinition [1..1] cardinality (Priority: P2)

As a client using the writable address space, when I add a second `HasTypeDefinition` reference (to a
different target) from an Object or Variable that already has one, the server rejects it, preserving the
"exactly one type definition" cardinality.

**Why this priority**: Prevents a node from ending up with two type definitions; today only a duplicate
to the *same* target is blocked.

**Independent Test**: On an Object/Variable that already has a HasTypeDefinition, AddReferences a second
HasTypeDefinition to a different target and confirm rejection; confirm adding the first one still works.

**Acceptance Scenarios**:

1. **Given** an Object/Variable that already has a HasTypeDefinition, **When** a second
   HasTypeDefinition to a different target is added, **Then** the operation returns the spec-defined
   status and no second reference is created.
2. **Given** an Object/Variable with no HasTypeDefinition, **When** the first is added, **Then** it
   succeeds.

---

### User Story 5 - Prohibit InverseName on a symmetric ReferenceType (Priority: P3)

As someone defining a custom ReferenceType (via AddNodes of a ReferenceType node or the node setters),
when the ReferenceType is symmetric, the server does not allow a non-null InverseName, per the spec.

**Why this priority**: Narrow, affects only custom ReferenceType definitions; standard nodes are already
correct.

**Scope note**: Unlike the other stories, this is a **node-level invariant** enforced whenever a
ReferenceType node is constructed (node setters / AddNodes build path), NOT gated by
`clients_can_modify_address_space` — a symmetric ReferenceType with an InverseName is malformed
regardless of entry point. It must not reject any standard/generated node (they are InverseName-free).

**Independent Test**: Create/define a symmetric ReferenceType with a non-null InverseName and confirm it
is rejected/omitted per the spec; confirm a symmetric ReferenceType without InverseName and a
non-symmetric ReferenceType with InverseName both remain valid.

**Acceptance Scenarios**:

1. **Given** a ReferenceType marked symmetric, **When** a non-null InverseName is set/added, **Then** the
   operation is rejected (or the InverseName is not accepted) per the spec constraint.
2. **Given** a non-symmetric ReferenceType, **When** an InverseName is set, **Then** it remains valid.

---

### User Story 6 - Enforce type-refinement subtype rules (Priority: P3)

As a client defining a VariableType (or DataType) subtype, when its DataType or ValueRank would *widen*
rather than further-restrict the supertype's, the server rejects it, per the type-refinement rules.

**Why this priority**: The most semantically involved and lowest-frequency; must be scoped to the
concrete, checkable cases (DataType subtype-of and ValueRank restriction) to avoid over-reach.

**Independent Test**: Create a VariableType subtype whose DataType is not a subtype of the supertype's,
or whose ValueRank is less restrictive, and confirm rejection; confirm a properly-restricting subtype
succeeds.

**Acceptance Scenarios**:

1. **Given** a supertype with a defined DataType/ValueRank, **When** a subtype declares a DataType that
   is not a subtype of it, or a ValueRank that widens it, **Then** the operation returns the spec-defined
   status.
2. **Given** a subtype that further-restricts (or matches) the supertype's DataType/ValueRank, **When**
   it is created, **Then** it succeeds.

### Edge Cases

- `targetNodeClass` sentinel/unspecified value must be treated as "no assertion" and not cause rejection.
- Abstract-type check must work identically whether the type definition is a full node or exists only in
  the type metadata.
- Hierarchical-rule enforcement must not reject any source/target combination present in the standard
  core nodeset (verify against the loaded nodeset).
- A node with no existing HasTypeDefinition must still accept its first one; DeleteReferences then
  AddReferences of a different type definition must be allowed.
- Symmetric-ReferenceType rule applies to custom types only; standard symmetric types (already
  InverseName-free) must be unaffected.
- Subtype-refinement rules apply only where the supertype constraint is defined; an undefined/Any
  supertype ValueRank must not spuriously reject a subtype.
- All validations are reachable ONLY when `clients_can_modify_address_space` is enabled; with it disabled
  (default), AddNodes/AddReferences remain unsupported exactly as today.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: On the writable path, AddReferences MUST reject an operation whose declared
  `targetNodeClass` does not match the actual target node's NodeClass, with the spec-defined status,
  while treating the unspecified/sentinel value as no assertion.
- **FR-002**: On the writable path, AddNodes MUST reject a `typeDefinition` that is an abstract
  ObjectType/VariableType, including abstract types represented only in type metadata (not full nodes),
  with the spec-defined status.
- **FR-003**: On the writable path, AddReferences MUST enforce the NodeClass structural constraints of
  hierarchical reference types (generalizing the current single `HasProperty→Variable` check), rejecting
  invalid combinations with the spec-defined status, and MUST NOT reject any combination used by the
  standard core nodeset.
- **FR-004**: On the writable path, AddReferences MUST reject a second `HasTypeDefinition` reference from
  an Object/Variable that already has one (to a different target), preserving [1..1] cardinality.
- **FR-005**: The system MUST prohibit a non-null InverseName on a symmetric ReferenceType, per Part 3
  §5.3.2, applied where a ReferenceType is defined/modified.
- **FR-006**: On the writable path, creation of a VariableType (and, where checkable, DataType) subtype
  MUST reject a DataType or ValueRank that widens rather than restricts the supertype's, with the
  spec-defined status.
- **FR-007**: The AddNodes/AddReferences validations (FR-001–FR-004, FR-006) MUST be reachable only when
  `clients_can_modify_address_space` is enabled; the default read-only behavior and all currently-passing
  validations (browsename-duplicate, typeDefinition existence, duplicate-reference, per-node RBAC
  privilege) MUST be preserved unchanged. The symmetric-ReferenceType invariant (FR-005) is an EXCEPTION:
  it is a node-level invariant enforced whenever a ReferenceType node is constructed (not only via the
  gated AddNodes path), because it is a property of a well-formed ReferenceType node; it MUST NOT reject
  any node the standard/generated nodeset produces (standard symmetric ReferenceTypes are already
  InverseName-free).
- **FR-008**: Loading the standard/generated core nodeset MUST continue to succeed with no new
  validation failures.
- **FR-009**: Each new validation MUST return the OPC UA status code the spec prescribes for that
  failure, and MUST be covered by an independent test that fails before the change and passes after.

### Key Entities

- **AddReferenceItem**: a requested reference (source, reference type, target, `targetNodeClass`,
  direction) validated before insertion.
- **AddNodeItem**: a requested node (node class, `typeDefinition`, attributes) validated before creation.
- **Type metadata (TypeTree)**: the server's type hierarchy view; must expose abstractness for
  type-only entries so FR-002 can be enforced.
- **ReferenceType node**: carries `symmetric` and `inverseName`; subject to FR-005.
- **Hierarchical reference NodeClass rules**: the mapping from a hierarchical reference type to the
  source/target NodeClasses it may connect (FR-003).

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: With the writable address space enabled, each of the six validation gaps (targetNodeClass,
  abstract typeDefinition incl. type-metadata-only, hierarchical NodeClass rules, HasTypeDefinition
  cardinality, symmetric-InverseName, subtype refinement) rejects its invalid case with the spec-defined
  status and accepts the corresponding valid case — demonstrated by red-first tests.
- **SC-002**: A server with the writable address space **disabled** (default) behaves exactly as before
  this feature (no new rejections, AddNodes/AddReferences still unsupported).
- **SC-003**: The standard/generated core nodeset loads with zero new validation failures, and the
  existing NodeManagement integration tests continue to pass.
- **SC-004**: Every already-implemented validation (browsename-duplicate, typeDefinition existence,
  duplicate-reference, per-node RBAC privilege) still holds (no regression).

## Assumptions

- The writable-address-space feature (`clients_can_modify_address_space`) is the sole entry point being
  hardened; per-node-manager overrides (e.g. TestNodeManager) may bypass these as they do today.
- "Spec-defined status" resolves to the specific Bad_ status each OPC UA clause prescribes
  (e.g. `Bad_NodeClassInvalid`, `Bad_TypeDefinitionInvalid`, `Bad_ReferenceNotAllowed`,
  `Bad_BrowseNameDuplicated`/cardinality-appropriate code) — the exact code per gap is fixed during
  planning against the cited spec sections and the existing status-code conventions in the codebase.
- Type-refinement (FR-006) is scoped to the concrete, decidable checks (DataType subtype-of, ValueRank
  restriction); broader semantic refinement is out of scope.
- The generated standard nodeset is authoritative and correct; where a new rule and the nodeset appear
  to conflict, the nodeset wins and the rule is narrowed.

## Out of Scope

- `GeneralModelChangeEventType` emission, persistence, and full 9-node-class AddNodes semantics beyond
  what already exists.
- Any change to the default read-only address-space behavior.
- Validation on node-manager implementations that deliberately override the memory manager's
  NodeManagement (they remain responsible for their own validation).
