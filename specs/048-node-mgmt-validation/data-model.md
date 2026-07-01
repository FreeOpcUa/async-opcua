# Phase 1 Data Model: Node-Management Validation Hardening

The "data" is validation predicates over request items + one metadata extension. Runtime state is the
in-memory address space + TypeTree (unchanged except the abstractness field).

## Entity: TypeTree metadata entry (extended)

| Field | Before | After |
|-------|--------|-------|
| node class | `NodeClass` (map value) | `NodeClass` (unchanged accessor `get()`) |
| **is_abstract** | — (absent) | `bool`, new — queried via `TypeTree::is_abstract(&NodeId) -> Option<bool>` |

**Population**: `add_type_node(id, parent, node_class, is_abstract)` — new trailing arg. Real type sites
pass the node's `is_abstract()`; event/test helper sites pass `false`.

**Invariant**: `is_abstract(id)` returns `Some(true)` iff the type node is abstract; `None` iff the id
is not a known type. Backwards-compatible: `get()` semantics unchanged.

## Entity: AddReferenceItem validation (memory manager)

| Field used | New rule | Status on violation |
|-----------|----------|---------------------|
| `target_node_class` | must equal the actual target node's NodeClass unless unspecified (P4-NODEMGMT-01b) | `Bad_NodeClassInvalid` |
| `reference_type_id` + source/target class | hierarchical ref must connect allowed NodeClasses (P4-NODEMGMT-01a) | `Bad_ReferenceNotAllowed` |
| `reference_type_id == HasTypeDefinition` | source must not already have a HasTypeDefinition to any target (P3-06) | `Bad_ReferenceNotAllowed` |

**Preserved** (unchanged): abstract-reference-type reject, duplicate-reference (same target),
per-node RBAC privilege.

## Entity: AddNodeItem validation (memory manager)

| Field used | New rule | Status on violation |
|-----------|----------|---------------------|
| `type_definition_id` | if abstract (address-space node OR type-metadata-only) → reject (P3-03) | `Bad_TypeDefinitionInvalid` |
| VariableType `data_type`/`value_rank` vs supertype | subtype may only further-restrict (P3-07) | `Bad_NodeAttributesInvalid` |

**Preserved**: browsename-duplicate, typeDefinition existence/class.

## Entity: ReferenceType node (nodes crate)

| Fields | New rule | Status on violation |
|--------|----------|---------------------|
| `symmetric`, `inverse_name` | symmetric ⇒ inverse_name must be null (P3-05) | `Bad_NodeAttributesInvalid` |

## Cross-cutting invariants

- **Gate**: every new rule is reachable only when `clients_can_modify_address_space` is enabled; default
  build behavior is byte-for-byte unchanged.
- **No standard-nodeset regression**: loading the generated core nodeset triggers none of the new
  rejections (verified by an explicit load test / existing integration suite).
- **Per-operation**: rejections are per AddNodes/AddReferences item (the service processes the rest),
  matching existing behavior.
