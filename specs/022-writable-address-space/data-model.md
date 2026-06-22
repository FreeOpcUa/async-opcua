# Data Model: Writable Address Space (NodeManagement)

No persistent storage. The "model" is the in-memory `AddressSpace` and the already-defined request item
types; this feature adds one config field and the mutation behavior.

## Config: modification gate (NEW)
- `Limits.clients_can_modify_address_space: bool` (`async-opcua-server/src/config/limits.rs`),
  `#[serde(default)]` = `false`. Read at request time via `context.info.config` → limits. Gates all four
  NodeManagement operations on the in-memory node manager.

## Request items (existing — `node_manager/node_management.rs`)
- **AddNodeItem**: getters `parent_node_id()`, `reference_type_id()`, `requested_new_node_id()` (may be
  null → server assigns), `browse_name()`, `node_class()`, `node_attributes()` (`AddNodeAttributes`),
  `type_definition_id()`, `status()`; mutator `set_result(node_id, status)`. Construction already runs
  null/attribute validation and may pre-set a bad status (the impl must honor it).
- **DeleteNodeItem**: target node id + `delete_target_references` flag → result status.
- **AddReferenceItem** / **DeleteReferenceItem**: source node, reference type, direction, target node →
  source/target result statuses.

## Address space (existing mutation API — `address_space/mod.rs`)
- `node_exists(&NodeId) -> bool`
- `insert(node, Some((parent_id, reference_type_id, forward)))` — add a node + its parent reference
- `insert_reference(source, target, reference_type, forward)`
- `delete_reference(...)`
- `delete(&NodeId, delete_target_references) -> Option<NodeType>`

## Node construction (existing types — `async-opcua-nodes`, `async-opcua-types::AddNodeAttributes`)
- `AddNodeAttributes` variant (Object/Variable/Method/ObjectType/VariableType/ReferenceType/DataType/
  View/Generic) → matching node type built with `(NodeId, browse_name, display_name)` + applied
  attributes (per the `specified_attributes` mask), then inserted with parent + type-definition refs.

## Behavioral states (per item, partial-success batch)
- gate off → `BadServiceUnsupported`.
- AddNodes → `Good`+assigned id | `BadNodeIdExists` | `BadParentNodeIdInvalid` |
  `BadReferenceTypeIdInvalid` | `BadNodeClassInvalid` | `BadTypeDefinitionInvalid` |
  `BadNodeAttributesInvalid`.
- DeleteNodes → `Good` | `BadNodeIdUnknown`.
- AddReferences → `Good` | `BadSourceNodeIdInvalid` | `BadTargetNodeIdInvalid` |
  `BadReferenceTypeIdInvalid`.
- DeleteReferences → `Good` | appropriate status.
