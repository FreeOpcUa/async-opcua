# Validation Contract: Node-Management Validation Hardening

Authoritative per-gap contract. The AddNodes/AddReferences rules (P4-NODEMGMT-01a/b, P3-03, P3-06,
P3-07) apply **only** on the writable path (`clients_can_modify_address_space` enabled). **Exception:**
P3-05 (symmetric+InverseName) is a node-level invariant enforced at ReferenceType construction
regardless of the flag (a symmetric ReferenceType with an InverseName is malformed at any entry point);
it must not reject any standard/generated node.

## Per-gap table

| Gap | User Story | Service | Trigger (reject when…) | Status code | Spec § | FR |
|-----|-----------|---------|------------------------|-------------|--------|----|
| P4-NODEMGMT-01b | US1 | AddReferences | declared `targetNodeClass` ≠ actual target NodeClass (and not the unspecified sentinel) | `Bad_NodeClassInvalid` | Part 4 §5.8.3(.4) | FR-001 |
| P3-03 | US2 | AddNodes | `typeDefinition` is an abstract ObjectType/VariableType (full node **or** type-metadata-only) | `Bad_TypeDefinitionInvalid` | Part 3 §5.5.2 / §5.6.5 | FR-002 |
| P4-NODEMGMT-01a | US3 | AddReferences | hierarchical reference connects NodeClasses its type forbids | `Bad_ReferenceNotAllowed` | Part 4 §5.8.3 / Part 3 §5.3, §7 | FR-003 |
| P3-06 | US4 | AddReferences | 2nd `HasTypeDefinition` from a source that already has one (different target) | `Bad_ReferenceNotAllowed` | Part 3 §5.5.1 / §5.6.2 | FR-004 |
| P3-05 | US5 | ReferenceType define | `symmetric == true` with non-null `InverseName` | `Bad_NodeAttributesInvalid` | Part 3 §5.3.2 | FR-005 |
| P3-07 | US6 | AddNodes (VariableType/DataType) | subtype `DataType`/`ValueRank` widens the supertype's | `Bad_NodeAttributesInvalid` | Part 3 §5.6.5 / §6.3 | FR-006 |

## Preserved behavior (no regression — FR-007)

- Default read-only: `clients_can_modify_address_space` OFF ⇒ AddNodes/AddReferences unsupported (unchanged).
- Existing validations: browsename-duplicate, typeDefinition existence, duplicate-reference (same target),
  abstract-reference-type, per-node RBAC privilege — all still hold.

## Prerequisite (US2 depends on it)

- `TypeTree::is_abstract(&NodeId) -> Option<bool>` + `add_type_node(.., is_abstract)`. Additive; `get()`
  unchanged. All ~8 call sites updated.

## Verification commands

```bash
# unit (node manager + type tree) — includes the red-first per-gap tests
cargo test -p async-opcua-server node_management
cargo test -p async-opcua-nodes type_tree

# server crate — ALL binaries (event_filter_tests etc. exercise add_type_node)
cargo test -p async-opcua-server

# e2e writable AddNodes/AddReferences
cargo test -p async-opcua --test integration_tests -- node_management

# standard-nodeset-regression + default behavior unchanged (SC-002/SC-003)
cargo test -p async-opcua-server            # standard nodeset loads in setup of many tests
cargo build -p async-opcua                  # default features, no new deps

# lint
cargo clippy -p async-opcua-server -p async-opcua-nodes --all-targets -- -D warnings
```

## Non-goals

- GeneralModelChangeEventType emission, persistence, full 9-node-class AddNodes.
- Any change to default read-only behavior or to node managers that override the memory manager.
