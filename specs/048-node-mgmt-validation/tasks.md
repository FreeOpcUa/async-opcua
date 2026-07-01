# Tasks: Node-Management Validation Hardening

**Feature**: `048-node-mgmt-validation` | **Spec**: [spec.md](./spec.md) | **Plan**: [plan.md](./plan.md)
**Contract**: [contracts/validation-contract.md](./contracts/validation-contract.md)

> Red-first per gap (spec FR-009). All new rules apply only when `clients_can_modify_address_space` is
> enabled. Most impl tasks touch `async-opcua-server/src/node_manager/memory/memory_mgr_impl.rs`, so
> those stories are sequential (no cross-story `[P]`); US5 (`reference_type.rs`) is the exception.
> Each task is one indivisible, independently verifiable job (Constitution III).

## Phase 1: Setup

- [x] T001 Baseline: run `cargo test -p async-opcua-server` and confirm green (standard nodeset loads in test setup); record the pre-change state. No file change.

## Phase 2: Foundational — TypeTree abstractness (blocks US2)

- [x] T002 [P] Red-first test in `async-opcua-nodes/src/type_tree.rs`: assert `TypeTree::is_abstract(id)` returns `Some(true)` for an abstract type node, `Some(false)` for a concrete type, `None` for a non-type id. (Fails: method/field absent.)
- [x] T003 Implement TypeTree abstractness in `async-opcua-nodes/src/type_tree.rs`: store `is_abstract` alongside `NodeClass` in `DefaultTypeTree.nodes`; add `TypeTree::is_abstract(&NodeId) -> Option<bool>`; add an `is_abstract: bool` param to `add_type_node`; update ALL call sites (`async-opcua-server/src/address_space/mod.rs:107`, `session/services/node_management.rs:485`, `node_manager/memory/mod.rs:1405`, `memory_mgr_impl.rs:1847/1905` pass the node's real `is_abstract()`; `async-opcua-nodes/src/events/{validation,evaluate}.rs` + `async-opcua-server/src/services/subscription/filter.rs` pass `false`). Make T002 pass. `get()` semantics unchanged. _Standard: OPC 10000-3 §5.5.2 (ObjectType IsAbstract) + §5.6.5 (VariableType IsAbstract) — "the type cannot be directly instantiated"._

## Phase 3: User Story 1 — targetNodeClass match (P1, P4-NODEMGMT-01b)

**Independent test**: writable AS; AddReferences with wrong `targetNodeClass` → `BadNodeClassInvalid`; matching/unspecified → good.

- [x] T004 [US1] Red-first test in `memory_mgr_impl.rs` (tests): AddReferences with `targetNodeClass` ≠ actual target NodeClass → `BadNodeClassInvalid`; matching value and the unspecified sentinel → good.
- [x] T005 [US1] Implement in `memory_mgr_impl.rs` AddReferences validation: compare `item.target_node_class()` to the resolved target node's NodeClass; reject mismatch with `BadNodeClassInvalid`, treat unspecified as no assertion. _Standard: OPC 10000-4 §5.8.3 (AddReferences; operation-level StatusCodes §5.8.3.4, Table 27)._

## Phase 4: User Story 2 — reject abstract typeDefinition (P1, P3-03) — depends on Phase 2

**Independent test**: AddNodes with an abstract type-metadata-only typeDefinition → `BadTypeDefinitionInvalid`; concrete → good; abstract full-node still rejected.

- [x] T006 [US2] Red-first test in `memory_mgr_impl.rs` (tests): AddNodes whose `typeDefinition` is an abstract standard type present only in the type metadata → `BadTypeDefinitionInvalid`; a concrete type → good; an abstract full node → still `BadTypeDefinitionInvalid` (no regression).
- [x] T007 [US2] Implement in `memory_mgr_impl.rs` `validate_type_definition`: in the type-metadata branch, reject when `type_tree.is_abstract(type_definition_id) == Some(true)`. _Standard: OPC 10000-3 §5.5.2 (ObjectType) / §5.6.5 (VariableType) — abstract types not instantiable._

## Phase 5: User Story 3 — hierarchical structural rules (P2, P4-NODEMGMT-01a)

**Independent test**: invalid hierarchical NodeClass combinations rejected → `BadReferenceNotAllowed`; every combination the standard nodeset uses still accepted.

- [x] T008 [US3] Red-first test in `memory_mgr_impl.rs` (tests): a hierarchical reference connecting a forbidden NodeClass combination → `BadReferenceNotAllowed`; a representative set of standard-nodeset-valid combinations → good.
- [x] T009 [US3] Implement in `memory_mgr_impl.rs`: generalize `reference_is_structurally_allowed` from the single `HasProperty→Variable` case to a rule table (hierarchical reference type → allowed source/target NodeClasses), conservatively rejecting only clearly-forbidden combinations; verify against the standard nodeset (must not reject any). _Standard: OPC 10000-4 §5.8.3 (AddReferences) + OPC 10000-3 §5.3 (ReferenceTypes) / §7 (standard hierarchical ReferenceTypes)._

## Phase 6: User Story 4 — HasTypeDefinition [1..1] cardinality (P2, P3-06)

**Independent test**: a 2nd HasTypeDefinition (different target) on a node that already has one → `BadReferenceNotAllowed`; the first → good.

- [x] T010 [US4] Red-first test in `memory_mgr_impl.rs` (tests): on an Object/Variable with an existing HasTypeDefinition, AddReferences a second HasTypeDefinition to a different target → `BadReferenceNotAllowed`; adding the first HasTypeDefinition → good.
- [x] T011 [US4] Implement in `memory_mgr_impl.rs` AddReferences: when `reference_type_id == HasTypeDefinition`, reject if the source already has any HasTypeDefinition reference (not just the same target). _Standard: OPC 10000-3 §5.5.1 (Object: "SourceNode of exactly one HasTypeDefinition Reference") / §5.6.2 (Variable equivalent)._

## Phase 7: User Story 5 — symmetric ReferenceType prohibits InverseName (P3, P3-05)

**Independent test**: symmetric ReferenceType + non-null InverseName rejected; symmetric-without-inverse and non-symmetric-with-inverse both valid.

- [x] T012 [US5] Red-first test in `async-opcua-nodes/src/reference_type.rs` (tests): defining a symmetric ReferenceType with a non-null InverseName is rejected/omitted; the two valid cases hold.
- [x] T013 [US5] Implement at the SINGLE ReferenceType node boundary in `async-opcua-nodes/src/reference_type.rs` (the build/attribute path AddNodes also routes through): reject a non-null InverseName when `symmetric == true` with `BadNodeAttributesInvalid`. This is a node-level invariant — always-on (NOT gated by `clients_can_modify_address_space`), per FR-007's exception; it must not reject any standard/generated node (they are InverseName-free — verify via the nodeset load in T016). _Standard: OPC 10000-3 §5.3.2 (ReferenceType Attributes — "If the ReferenceType is non-symmetric the InverseName Attribute shall be set"; symmetric ⇒ InverseName omitted). [verified exact]_

## Phase 8: User Story 6 — subtype DataType/ValueRank refinement (P3, P3-07)

**Independent test**: a VariableType subtype widening DataType or ValueRank rejected → `BadNodeAttributesInvalid`; a restricting/matching subtype accepted.

- [x] T014 [US6] Red-first test in `memory_mgr_impl.rs` (tests): AddNodes of a VariableType subtype whose `DataType` is not a subtype of the supertype's, or whose `ValueRank` widens it → `BadNodeAttributesInvalid`; a properly-restricting subtype → good.
- [x] T015 [US6] Implement in `memory_mgr_impl.rs` AddNodes (VariableType, and DataType where applicable): reject when subtype `DataType` is not `is_subtype_of` the supertype's, or subtype `ValueRank` is less restrictive; skip when the supertype constraint is Any/undefined. _Standard: OPC 10000-3 §5.6.5 (VariableType — subtypes inherit/restrict) → general subtyping rules Clause 6 (§6.3)._

## Phase 9: Polish & Cross-Cutting

- [ ] T016 Full verification: `cargo test -p async-opcua-server` (ALL binaries) + `cargo test -p async-opcua --test integration_tests -- node_management` + `cargo build -p async-opcua` (default features, SC-002/SC-003 — standard nodeset loads, default behavior unchanged).
- [ ] T017 [P] Lint: `cargo clippy -p async-opcua-server -p async-opcua-nodes --all-targets -- -D warnings`.
- [ ] T018 [P] Update `specs/conformance-audit/FINDINGS.md` rows P4-NODEMGMT-01, P3-03, P3-05, P3-06, P3-07 → FIXED (feature 048) with evidence; note in `specs/SESSION-HANDOFF.md`.

## Dependencies & Execution Order

- **T001** first.
- **Phase 2 (T002→T003)** blocks **US2 (T006→T007)** — US2 consumes `TypeTree::is_abstract`.
- **US1, US3, US4, US6** all edit `memory_mgr_impl.rs` → sequential among themselves (do in priority order US1→US2→US3→US4→US6). **US5** edits `reference_type.rs` → can proceed in parallel with the memory_mgr work.
- **Polish (T016–T018)** after all stories; T017/T018 are `[P]` (lint vs docs).
- Within each story: the test task precedes its implementation task (red-first).

## Implementation Strategy

- **MVP = US1 + US2** (the two P1 gaps: targetNodeClass + abstract typeDefinition). US2 needs the Phase-2 TypeTree prerequisite.
- Then US3/US4 (P2), then US5/US6 (P3). Each story is independently shippable and independently verifiable.
- One task at a time; the red test must fail before its impl and pass after (Constitution I/III).

## Parallel Opportunities

- **T002** (TypeTree test) is `[P]` (different crate/file from any story).
- **US5** (`reference_type.rs`) is `[P]` relative to the `memory_mgr_impl.rs` stories.
- **T017** (clippy) and **T018** (docs) are `[P]`.
- Everything else is sequential (shared `memory_mgr_impl.rs`).
