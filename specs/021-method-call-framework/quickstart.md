# Quickstart: Typed Method-Call Framework

## Register a typed method

```rust
use opcua::server::node_manager::typed_method;

// 1 input, 1 output — no manual Variant handling:
manager.inner().add_method_callback(
    NodeId::new(ns, "HelloX"),
    typed_method(|name: String| -> Result<(String,), StatusCode> {
        Ok((format!("Hello {name}!"),))
    }),
);

// 2 inputs, 2 outputs:
manager.inner().add_method_callback(
    NodeId::new(ns, "AddAndDescribe"),
    typed_method(|a: i32, b: i32| -> Result<(i32, String), StatusCode> {
        Ok((a + b, format!("{a} + {b} = {}", a + b)))
    }),
);

// 0 inputs, 0 outputs:
manager.inner().add_method_callback(
    NodeId::new(ns, "NoOp"),
    typed_method(|| -> Result<(), StatusCode> { Ok(()) }),
);
```

The framework checks argument count and types for you and returns the spec-correct status on mismatch.
The existing raw form still works unchanged:

```rust
manager.inner().add_method_callback(id, |args: &[Variant]| {
    /* low-level: still fully supported */ Ok(vec![])
});
```

## Build & verify

```bash
# unit tests (decode / arity / marshal / status mapping):
cargo test -p async-opcua-server method_typed

# end-to-end typed Call through the server:
cargo test -p async-opcua --test integration_tests methods

# lint across feature legs (the CI gate):
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo clippy --locked -p async-opcua --no-default-features -- -D warnings
cargo clippy --locked -p async-opcua --no-default-features --features json -- -D warnings

# demo server still builds + runs (US2):
cargo build -p async-opcua-demo-server
```

## Status-code cheat-sheet (what callers see)

| Call | Result |
|------|--------|
| right count + types | `Good` + outputs |
| too few args | `BadArgumentsMissing` |
| too many args | `BadTooManyArguments` |
| wrong type for an arg | `BadInvalidArgument` |
| your closure returns `Err(code)` / `Err(error)` | that status |
