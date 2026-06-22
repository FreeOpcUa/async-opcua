# Quickstart: Writable Address Space (NodeManagement)

## Enable it (off by default)

```yaml
# server config
limits:
  clients_can_modify_address_space: true   # default false
```

With the flag on, a client can mutate the in-memory address space:

```rust
// AddNodes — create a Variable under an existing parent
session.add_nodes(vec![AddNodesItem {
    parent_node_id: parent.into(),
    reference_type_id: ReferenceTypeId::HasComponent.into(),
    requested_new_node_id: NodeId::null().into(),     // server assigns
    browse_name: QualifiedName::new(ns, "MyVar"),
    node_class: NodeClass::Variable,
    node_attributes: variable_attributes,             // ExtensionObject
    type_definition: VariableTypeId::BaseDataVariableType.into(),
}]).await?;
// → Good + assigned NodeId; a subsequent Browse/Read of the parent shows MyVar.

// DeleteNodes
session.delete_nodes(vec![DeleteNodesItem { node_id: my_var, delete_target_references: true }]).await?;

// AddReferences / DeleteReferences between existing nodes, reflected by Browse.
```

With the flag **off** (default) every operation returns `BadServiceUnsupported` and nothing changes.

## Build & verify

```bash
# end-to-end NodeManagement tests (add/delete/refs + gate-off + edges):
cargo test -p async-opcua --test integration_tests node_management -- --test-threads=1
# lint across the CI legs:
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo clippy --locked -p async-opcua --no-default-features -- -D warnings
cargo clippy --locked -p async-opcua --no-default-features --features json -- -D warnings
# demo still builds:
cargo build -p async-opcua-demo-server
```

## Status-code cheat-sheet (Part 4 §5.7)

| Situation | Result |
|-----------|--------|
| gate disabled | `BadServiceUnsupported` |
| add under existing id | `BadNodeIdExists` |
| add under missing parent | `BadParentNodeIdInvalid` |
| delete unknown node | `BadNodeIdUnknown` |
| add reference with bad source/target/type | `BadSourceNodeIdInvalid` / `BadTargetNodeIdInvalid` / `BadReferenceTypeIdInvalid` |
| valid op | `Good` (+ assigned NodeId for AddNodes) |
