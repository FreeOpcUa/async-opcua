# Phase 0 Research: Node-Management Validation Hardening

Current-code findings (verified 2026-07-01) and the resulting decisions.

## Current state (what exists)

`async-opcua-server/src/node_manager/memory/memory_mgr_impl.rs`:
- `validate_type_definition` (`:566`) rejects abstract types **only** when the type is a full node in the
  address space (`:585/:590`); for type-metadata-only types it checks *NodeClass only* (`:600-607`) — the
  P3-03 hole.
- `reference_is_structurally_allowed` (`:521`) checks **only** `HasProperty→Variable` — the
  P4-NODEMGMT-01a partial.
- AddReferences duplicate check (`:386`) is `has_reference(source, target, ref_type)` — same-target only;
  no [1..1] HasTypeDefinition cardinality (P3-06).
- `targetNodeClass` is carried on `AddReferenceItem` but only used for audit — never validated (P4-NODEMGMT-01b).

`async-opcua-nodes/src/type_tree.rs`:
- `DefaultTypeTree.nodes: HashMap<NodeId, NodeClass>` (`:49`) — **no abstractness stored**.
- `add_type_node(id, parent, node_class)` (`:190`) populates it; ~8 call sites across server + nodes.
- `TypeTree` trait: `get()→NodeClass`, `is_subtype_of()`, `get_node()`.

`async-opcua-nodes/src/reference_type.rs`: independent `symmetric` / `inverse_name` fields + setters,
no cross-check (P3-05).

## R1 — P3-03 root fix: TypeTree records IsAbstract

**Decision**: Extend the type metadata to carry `is_abstract`. Change `DefaultTypeTree.nodes` value from
`NodeClass` to a `(NodeClass, bool)` (or a 2-field struct), add `TypeTree::is_abstract(&NodeId) ->
Option<bool>`, and add an `is_abstract: bool` parameter to `add_type_node`. `validate_type_definition`'s
type-metadata branch then returns `Bad_TypeDefinitionInvalid` when `is_abstract == Some(true)`.

**Rationale**: This is the only complete, non-fragile fix (Do-It-Right-Once). Abstractness is known at
every real population site (the type node's `is_abstract()`), so threading it is mechanical.

**Alternatives rejected**: (a) a hardcoded `standard_type_is_abstract(NodeId)` list — incomplete and
rots as the nodeset evolves; (b) resolving abstractness by looking up the full node — impossible for
type-metadata-only types (that's the very gap).

**Call-site handling**: real type-population sites (`address_space/mod.rs:107`,
`node_management.rs:485`, `memory/mod.rs:1405`, `memory_mgr_impl.rs:1847/1905`) pass the node's real
`is_abstract`; event-helper/test sites (`events/validation.rs`, `events/evaluate.rs`,
`subscription/filter.rs`) pass `false` (they register concrete event types). `get()` keeps returning
`NodeClass` for source compatibility; `is_abstract()` is the new query.

## R2 — Status-code mapping

| Gap | Trigger | Status | Exists? |
|-----|---------|--------|---------|
| P4-NODEMGMT-01b | `targetNodeClass` ≠ actual target NodeClass (and not unspecified) | `Bad_NodeClassInvalid` | ✅ |
| P4-NODEMGMT-01a | hierarchical ref connects disallowed NodeClasses | `Bad_ReferenceNotAllowed` | ✅ |
| P3-03 | abstract typeDefinition (incl. type-metadata-only) | `Bad_TypeDefinitionInvalid` | ✅ (already used) |
| P3-06 | 2nd HasTypeDefinition (different target) | `Bad_ReferenceNotAllowed` | ✅ |
| P3-05 | symmetric ReferenceType + non-null InverseName | `Bad_NodeAttributesInvalid` | ✅ |
| P3-07 | subtype DataType/ValueRank widens supertype | `Bad_NodeAttributesInvalid` | ✅ |

Codes confirmed present in `async-opcua-types` status codes. Exact code per gap is re-checked against
the cited spec clause in tasks.md.

## R3 — Hierarchical structural rules (P4-NODEMGMT-01a)

**Decision**: Replace the single `HasProperty→Variable` special case with a rule table keyed by
hierarchical reference type, encoding the allowed source/target NodeClass sets per Part 3 reference
semantics (e.g. HasProperty target must be a Variable/Property; HasComponent/Organizes constraints).
Enforce only combinations the spec **clearly forbids**; when uncertain, allow (conservative), so no
legitimate model breaks. **Validate the table against the loaded standard nodeset** (FR-008) — any
standard combination the table would reject means the table is wrong, not the nodeset.

**Rationale**: Generalizes the existing check without over-reaching; the standard-nodeset guard is the
safety net against false rejections.

## R4 — Subtype refinement (P3-07)

**Decision**: Scope to two decidable checks on AddNodes of a VariableType (and DataType where
applicable): (1) subtype `DataType` must be `is_subtype_of` the supertype's DataType; (2) subtype
`ValueRank` must not be *less restrictive* than the supertype's (reuse existing value_rank semantics —
e.g. a scalar supertype can't be widened to an array subtype). Where the supertype constraint is
Any/undefined, impose nothing. Reject with `Bad_NodeAttributesInvalid`.

**Rationale**: These are the objective, testable refinement rules; broader semantic refinement (Part 3
§6.2 full generality) is out of scope per the spec.

## R5 — Symmetric ReferenceType + InverseName (P3-05)

**Decision**: At the ReferenceType boundary (`build_reference_type` / the node's attribute set), reject a
non-null InverseName when `symmetric == true` (`Bad_NodeAttributesInvalid`). Standard symmetric types
ship InverseName-free → no regression; the check is only reachable via custom ReferenceType definition.

## Open items

None — no NEEDS CLARIFICATION. All status codes exist; the TypeTree change is the only structural touch
and it is additive.
