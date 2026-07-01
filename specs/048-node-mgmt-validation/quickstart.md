# Quickstart: Node-Management Validation Hardening

## For maintainers / implementers

### Enabling the path under test

The new validations are reachable only with the writable address space enabled:

```rust
// ServerBuilder / config
.clients_can_modify_address_space(true)
```

With it OFF (default) AddNodes/AddReferences are unsupported and none of these rules run.

### Red-first test pattern (per gap)

Each gap gets a paired test: the invalid case must **fail before** the change and **pass after**, and a
valid case must keep succeeding.

```rust
// invalid: rejected with the spec status
let status = add_reference_with(target_node_class = WRONG_CLASS);
assert_eq!(status, StatusCode::BadNodeClassInvalid);

// valid: still accepted
let status = add_reference_with(target_node_class = ACTUAL_CLASS);
assert!(status.is_good());
```

### Standard-nodeset regression guard (SC-003)

The generated core nodeset must load with zero new rejections. The server crate's tests build a server
with the standard address space in setup, so `cargo test -p async-opcua-server` is the guard; if a new
hierarchical rule (US3) rejects a standard combination, a setup will fail — that means the rule is too
strict, narrow it (the nodeset wins).

## Verification matrix

```bash
cargo test -p async-opcua-nodes type_tree                 # TypeTree is_abstract (US2 prereq)
cargo test -p async-opcua-server node_management          # per-gap unit tests
cargo test -p async-opcua-server                          # ALL binaries + standard-nodeset load
cargo test -p async-opcua --test integration_tests -- node_management   # e2e writable AS
cargo build -p async-opcua                                # default features unchanged (SC-002)
cargo clippy -p async-opcua-server -p async-opcua-nodes --all-targets -- -D warnings
```

Expected: all pass; default build pulls no new deps; the six invalid cases reject with their
spec-defined status and the six valid cases succeed.
