# API Surface: Writable Address Space (NodeManagement)

Additive. No public type is removed or changed in a breaking way.

## New public config field

```rust
// async-opcua-server/src/config/limits.rs — struct Limits
/// Allow clients to modify the address space via the NodeManagement service
/// (AddNodes/DeleteNodes/AddReferences/DeleteReferences) on supporting node managers.
/// Default false (read-only).
#[serde(default)]
pub clients_can_modify_address_space: bool,
```

## Behavioral contract (in-memory node manager, via the existing NodeManagement service)

No new public functions are strictly required — the four operations are the existing
`InMemoryNodeManagerImpl` trait methods (`add_nodes` / `add_references` / `delete_nodes` /
`delete_references`), whose in-memory default bodies change from `Err(BadServiceUnsupported)` to gated
mutation. Existing overrides on downstream impls continue to take precedence (additive).

| Operation | Gate off | Gate on — success | Gate on — failure statuses |
|-----------|----------|-------------------|----------------------------|
| AddNodes | `BadServiceUnsupported` | `Good` + assigned `NodeId`; node browsable/readable | `BadNodeIdExists`, `BadParentNodeIdInvalid`, `BadReferenceTypeIdInvalid`, `BadNodeClassInvalid`, `BadTypeDefinitionInvalid`, `BadNodeAttributesInvalid` |
| DeleteNodes | `BadServiceUnsupported` | `Good`; node + refs gone | `BadNodeIdUnknown` |
| AddReferences | `BadServiceUnsupported` | `Good`; reference shown by Browse | `BadSourceNodeIdInvalid`, `BadTargetNodeIdInvalid`, `BadReferenceTypeIdInvalid` |
| DeleteReferences | `BadServiceUnsupported` | `Good`; reference gone from Browse | appropriate status |

**Invariants**: per-item status (partial success in a batch); never panics on crafted input; batch bound
by `max_nodes_per_node_management`; address space stays consistent (no dangling references).

## Usage

```rust
// Enable in config (YAML): limits: { clients_can_modify_address_space: true }
// then a client may AddNodes/DeleteNodes/AddReferences/DeleteReferences against the in-memory server,
// and a subsequent Browse/Read reflects the change.
```

## Non-goals / unchanged

The `NodeMutator` trait, the NodeManagement service/dispatch, the request/result wire types, and all
other node managers are unchanged. No new runtime dependency. Model-change event emission, persistence,
and writability of non-in-memory managers are out of scope.
