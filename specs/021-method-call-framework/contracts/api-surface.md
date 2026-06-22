# API Surface: Typed Method-Call Framework

All additive, in `async-opcua-server` (re-exported from a stable path, e.g.
`opcua::server::node_manager::{MethodArg, IntoMethodOutputs, typed_method, typed_method_with_context}`).
Nothing existing is changed or removed.

## New public traits

```rust
/// A Rust type usable as a typed OPC UA method parameter.
pub trait MethodArg: Sized {
    fn from_method_arg(v: Variant) -> Result<Self, StatusCode>;
}
impl<T: TryFromVariant> MethodArg for T { /* maps Error -> StatusCode */ }

/// A typed method return, marshaled positionally into output Variants.
pub trait IntoMethodOutputs {
    fn into_method_outputs(self) -> Vec<Variant>;
}
// impl for (), (A,), (A,B), ..., (A,B,C,D,E,F)  where each : Into<Variant>

/// Bridges a typed closure to the raw method callback. `Args` is an inference marker.
pub trait MethodHandler<Args> {
    fn handle(&self, args: &[Variant]) -> Result<Vec<Variant>, StatusCode>;
}
// impl for Fn(A1..An) -> Result<O, E>  where Ai: MethodArg, O: IntoMethodOutputs, E: Into<StatusCode>
```

## New public functions

```rust
/// Wrap a typed closure into the closure `add_method_callback` expects.
pub fn typed_method<F, Args>(f: F)
    -> impl Fn(&[Variant]) -> Result<Vec<Variant>, StatusCode> + Send + Sync + 'static
where F: MethodHandler<Args> + Send + Sync + 'static;

/// Context-aware variant for `add_method_callback_with_context` (US3, optional).
pub fn typed_method_with_context<F, Args>(f: F)
    -> impl Fn(&RequestContext, &[Variant]) -> Result<Vec<Variant>, StatusCode> + Send + Sync + 'static
where F: MethodHandlerWithContext<Args> + Send + Sync + 'static;
```

## Behavioral contract (the conformance-relevant part)

| Situation | Returned `StatusCode` |
|-----------|-----------------------|
| `args.len()` < declared arity | `BadArgumentsMissing` |
| `args.len()` > declared arity | `BadTooManyArguments` |
| an argument fails to decode to its declared type | `BadInvalidArgument` (failing index logged) |
| user closure returns `Err(e)` | `e.into()` (`StatusCode` passthrough; crate `Error` via `From`) |
| valid call | `Good`, outputs = `into_method_outputs()` |

**Known limitation (FR-004 refinement)**: the wire `inputArgumentResults` per-argument vector is **not**
populated — `add_method_callback` carries only a single `StatusCode` and the in-memory `call()` discards
anything finer. The operation-level status above is what a conformant client checks.

## Usage (replaces hand-written `|args: &[Variant]| { … }`)

```rust
// before: manual index + match + Vec build
manager.inner().add_method_callback(hello_x_id, typed_method(
    |name: String| -> Result<(String,), StatusCode> {
        Ok((format!("Hello {name}!"),))
    },
));

// multi-arg, multi-out:
manager.inner().add_method_callback(add_id, typed_method(
    |a: i32, b: i32| -> Result<(i32, String), StatusCode> {
        Ok((a + b, format!("{a}+{b}")))
    },
));
```

## Non-goals / unchanged

`InMemoryMethodCallback`, `add_method_callback[_with_context]`, `MethodCall`, the Call service, and all
wire types are unchanged. No new runtime dependency.
