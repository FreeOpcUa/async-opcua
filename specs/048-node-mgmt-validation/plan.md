# Implementation Plan: Node-Management Validation Hardening

**Branch**: `048-node-mgmt-validation` | **Date**: 2026-07-01 | **Spec**: [spec.md](./spec.md)
**Input**: Feature specification from `/specs/048-node-mgmt-validation/spec.md`

## Summary

Close six conformance-audit gaps in the memory NodeManager's AddNodes/AddReferences validation, all on
the opt-in writable address-space path (`clients_can_modify_address_space`, default OFF). Each gap is a
targeted validation returning a spec-correct Bad status, red-first tested. The one structural change is
extending the `TypeTree` to record `IsAbstract` (today it stores only `NodeClass`), so abstract
type-metadata-only types can be rejected (P3-03). All other gaps are localized checks in
`memory_mgr_impl.rs` (AddNodes/AddReferences) or the node setters. Default read-only behavior is
untouched; standard nodeset loading must remain green.

## Technical Context

**Language/Version**: Rust 1.75+ workspace
**Primary Dependencies**: `async-opcua-server` (memory node manager), `async-opcua-nodes` (TypeTree,
node types), `async-opcua-types` (status codes, NodeClass). No new external dependency.
**Storage**: In-memory address space + TypeTree; SQLite/history untouched.
**Testing**: `cargo test -p async-opcua-server` (all binaries — `node_management` unit tests live in
`memory_mgr_impl.rs`) + the `async-opcua` NodeManagement integration tests; red-first per gap.
**Target Platform**: Linux CI + dev
**Project Type**: Rust workspace OPC UA server library
**Performance Goals**: N/A (validation on a per-request, opt-in, admin path); checks must stay O(1)/O(depth)
and not regress AddNodes/AddReferences latency meaningfully.
**Constraints**: MUST NOT change default read-only behavior; MUST NOT reject any node/reference the
standard core nodeset produces; MUST preserve the four already-passing validations; each new reject uses
the spec-prescribed Bad status.
**Scale/Scope**: Six validation slices. One shared prerequisite (TypeTree `is_abstract`). Files:
`async-opcua-nodes/src/type_tree.rs`, `async-opcua-server/src/node_manager/memory/memory_mgr_impl.rs`,
`async-opcua-nodes/src/reference_type.rs` (+ `variable_type.rs`), and the ~8 `add_type_node` call sites.

## OPC UA Standard Grounding

Grounded via the reference MCP during tasks; the spec sections per gap:

(Section numbers verified against the reference MCP 2026-07-01; see tasks.md for the exact per-task cite.)

- **P4-NODEMGMT-01 — Part 4 §5.8.3 (AddReferences; op-level StatusCodes §5.8.3.4)**: `targetNodeClass`
  validated against the target's actual NodeClass → `Bad_NodeClassInvalid`; references must be permitted
  between the given NodeClasses → `Bad_ReferenceNotAllowed` (Part 3 §5.3 / §7).
- **P3-03 — Part 3 §5.5.2 (ObjectType) / §5.6.5 (VariableType)**: an abstract type "cannot be directly
  instantiated" → `Bad_TypeDefinitionInvalid`.
- **P3-05 — Part 3 §5.3.2**: "If the ReferenceType is non-symmetric the InverseName Attribute shall be
  set" ⇒ symmetric omits InverseName → `Bad_NodeAttributesInvalid`.
- **P3-06 — Part 3 §5.5.1 (Object) / §5.6.2 (Variable)**: SourceNode of "exactly one HasTypeDefinition
  Reference" → second one `Bad_ReferenceNotAllowed`.
- **P3-07 — Part 3 §5.6.5 → general subtyping rules Clause 6 (§6.3)**: a subtype's DataType/ValueRank may
  only further-restrict the supertype's → `Bad_NodeAttributesInvalid` when widened.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

- **I. Correctness Over Completion**: PASS. Every slice is a spec-cited validation with a red-first proof
  test and an explicit "valid case still accepted" test; "done" = green + no standard-nodeset regression.
- **II. Do It Right Once**: PASS. P3-03 is fixed at the root (TypeTree records abstractness) rather than a
  fragile hardcoded abstract-id list; the existing partial checks are generalized, not duplicated.
- **III. Individual Task Discipline**: PASS. One validation per task (test + impl split where non-trivial);
  the TypeTree `is_abstract` prerequisite is its own task before P3-03's consumer.
- **IV. Security Is Paramount**: PASS. This ADDS validation on a client-reachable (when enabled) mutation
  path — strictly hardening. No decode/crypto/network change; no panics on attacker input (validations
  return Bad status, never unwrap). The path is opt-in and RBAC-gated already.
- **V. Leave It Better Than You Found It**: PASS. Generalizes `reference_is_structurally_allowed`, gives
  TypeTree a proper abstractness field, adds tests; corrects adjacent gaps in scope only.

**Result: PASS.** Complexity Tracking empty.

## Project Structure

### Documentation (this feature)

```text
specs/048-node-mgmt-validation/
├── spec.md · plan.md · research.md · data-model.md · quickstart.md
├── contracts/validation-contract.md   # per-gap: trigger → status code → spec §
├── checklists/requirements.md
└── tasks.md                           # /speckit-tasks
```

### Source Code (repository root)

```text
async-opcua-nodes/src/
├── type_tree.rs        # P3-03 prereq: DefaultTypeTree stores IsAbstract; TypeTree::is_abstract();
│                       #   add_type_node gains an is_abstract arg
└── reference_type.rs   # P3-05: symmetric ⇒ InverseName prohibited (setters / build)
    (variable_type.rs)  # P3-07: subtype DataType/ValueRank refinement check surface

async-opcua-server/src/node_manager/memory/
└── memory_mgr_impl.rs  # P4-NODEMGMT-01b targetNodeClass (AddReferences); 01a hierarchical rules
                        #   (generalize reference_is_structurally_allowed); P3-06 HasTypeDefinition
                        #   cardinality; P3-03 consumer (validate_type_definition type_tree branch);
                        #   P3-07 AddNodes subtype-refinement validation

async-opcua-server/src/address_space/mod.rs          # add_type_node caller (thread is_abstract)
async-opcua-server/src/session/services/node_management.rs   # add_type_node caller
async-opcua-server/src/node_manager/memory/mod.rs            # add_type_node caller
async-opcua-nodes/src/events/{validation,evaluate}.rs        # add_type_node callers
async-opcua-server/src/services/subscription/filter.rs       # add_type_node caller
```

**Structure Decision**: Keep validations in the memory manager that owns the invariant; put the
abstractness data where the type metadata lives (`TypeTree`). Tests go beside the code: node_manager
unit tests in `memory_mgr_impl.rs`, TypeTree unit tests in `type_tree.rs`, and an integration test in
the `async-opcua` suite where a full server + client AddNodes/AddReferences round-trip is needed.

## Phase 0 Research Summary

See [research.md](./research.md). Key decisions:

- **R1 (P3-03 root fix)**: extend `DefaultTypeTree.nodes` to carry `is_abstract` (small struct or
  `HashMap<NodeId,(NodeClass,bool)>`); add `TypeTree::is_abstract(&NodeId)->Option<bool>`; thread an
  `is_abstract` argument through `add_type_node` at all ~8 call sites (default `false` for non-type/event
  helper sites). `validate_type_definition`'s type_tree branch then rejects abstract types. Rejected
  alternative: a hardcoded abstract-standard-id list (fragile, incomplete — violates Do-It-Right-Once).
- **R2 (status codes)**: targetNodeClass mismatch → `Bad_NodeClassInvalid`; disallowed hierarchical
  combination + second HasTypeDefinition → `Bad_ReferenceNotAllowed`; abstract typeDef →
  `Bad_TypeDefinitionInvalid` (existing); symmetric+InverseName / bad subtype refinement →
  `Bad_NodeAttributesInvalid`. Confirmed all exist in `status_codes`.
- **R3 (hierarchical rules, P4-NODEMGMT-01a)**: generalize `reference_is_structurally_allowed` into a
  table keyed by hierarchical reference type → allowed (source,target) NodeClass sets, derived from Part 3
  reference-type semantics; validated against the standard nodeset so no legitimate combination is
  rejected (FR-003/FR-008). Keep conservative: only reject combinations the spec clearly forbids.
- **R4 (subtype refinement, P3-07)**: scope to decidable checks — subtype DataType must be
  `is_subtype_of` supertype DataType; subtype ValueRank must not widen supertype ValueRank (using the
  existing value_rank restriction semantics). Skip cases where the supertype constraint is Any/undefined.
- **R5 (symmetric+InverseName, P3-05)**: enforce at the ReferenceType node boundary (build/setters); a
  symmetric ReferenceType with non-null InverseName is rejected/omitted. Standard symmetric types are
  already InverseName-free → no regression.

## Phase 1 Design Summary

- [data-model.md](./data-model.md): the validated request entities (AddNodeItem, AddReferenceItem), the
  TypeTree abstractness extension, and the per-gap validation predicate + status.
- [contracts/validation-contract.md](./contracts/validation-contract.md): the authoritative per-gap
  table (gap → trigger condition → returned status → spec §), the FR/SC map, and the verification commands.
- [quickstart.md](./quickstart.md): how to enable the writable AS + the red-first test pattern + the
  standard-nodeset-regression check.

**Post-Design Constitution Re-check: PASS** — the TypeTree change is additive (default `false`), no
default behavior changes, all new paths are opt-in hardening.

## Complexity Tracking

| Violation | Why Needed | Simpler Alternative Rejected Because |
|-----------|------------|-------------------------------------|
| None | N/A | N/A |
