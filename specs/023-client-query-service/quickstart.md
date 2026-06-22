# Quickstart: Client Query Service

```rust
// QueryFirst: find nodes of a type, selecting some attributes.
let resp = session.query_first(
    ViewDescription::default(),                 // default view = whole address space
    vec![NodeTypeDescription { /* type_definition_node, data_to_return: [BrowseName, ...] */ ..Default::default() }],
    ContentFilter::default(),
    100,                                         // max data sets
    0,                                           // max references
).await?;
for ds in resp.query_data_sets.unwrap_or_default() { /* ds.node_id, ds.values */ }

// Page the rest:
let mut cp = resp.continuation_point;
while !cp.is_null() {
    let next = session.query_next(false, cp.clone()).await?;
    // ... next.query_data_sets ...
    cp = next.revised_continuation_point;
}
// Release early:
session.query_next(true, cp).await?;
```

## Verify
```bash
cargo test -p async-opcua --test integration_tests query -- --test-threads=1
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo clippy --locked -p async-opcua --no-default-features -- -D warnings
```
