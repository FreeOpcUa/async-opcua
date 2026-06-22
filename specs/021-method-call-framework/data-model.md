# Data Model: Typed Method-Call Framework

No persistent data. The "entities" are Rust traits/types in
`async-opcua-server/src/node_manager/method_typed.rs`.

## `MethodArg` (typed input)
- **Purpose**: a Rust type usable as a typed method parameter.
- **Shape**: `trait MethodArg: Sized { fn from_method_arg(v: Variant) -> Result<Self, StatusCode>; }`
- **Provided impl**: blanket `impl<T: TryFromVariant> MethodArg for T` (maps `Error` → `StatusCode`).
- **Validation**: decode failure yields a `StatusCode` (the adapter elevates it to `BadInvalidArgument`
  at the operation level).

## `IntoMethodOutputs` (typed output set)
- **Purpose**: marshal a typed return into the positional output `Vec<Variant>`.
- **Shape**: `trait IntoMethodOutputs { fn into_method_outputs(self) -> Vec<Variant>; }`
- **Provided impls**: tuples `()`, `(A,)`, …, `(A,B,C,D,E,F)` where each element `: Into<Variant>`
  (arity 0..=6). Single output = `(x,)`.
- **Validation**: total/infallible (output types are statically `Into<Variant>`).

## `MethodHandler<Args>` / `MethodHandlerWithContext<Args>` (adapter core)
- **Purpose**: bridge a typed closure to the existing callback signature.
- **Shape**:
  `trait MethodHandler<Args> { fn handle(&self, args: &[Variant]) -> Result<Vec<Variant>, StatusCode>; }`
  impl'd (macro, n=0..=6) for `F: Fn(A1..An) -> Result<O, E>` with `Aᵢ: MethodArg`,
  `O: IntoMethodOutputs`, `E: Into<StatusCode>`. Context variant adds a leading `&RequestContext`.
- **Behavior** (state-free, per call):
  1. `args.len() < N` → `Err(BadArgumentsMissing)`.
  2. `args.len() > N` → `Err(BadTooManyArguments)`.
  3. decode each `args[i].clone()` via `MethodArg`; first failure → `Err(BadInvalidArgument)` (log index).
  4. invoke the closure; `Err(e)` → `Err(e.into())`.
  5. success → `Ok(out.into_method_outputs())`.

## `typed_method` / `typed_method_with_context` (public entry points)
- **Purpose**: turn a typed closure into the exact closure type `add_method_callback[_with_context]`
  expects.
- **Shape**: `fn typed_method<F, Args>(f: F) -> impl Fn(&[Variant]) -> Result<Vec<Variant>, StatusCode> +
  Send + Sync where F: MethodHandler<Args> + Send + Sync + 'static`. Context variant returns the
  `Fn(&RequestContext, &[Variant]) -> …` shape.
- **Relationships**: output is consumed by the **unchanged** `SimpleNodeManager::add_method_callback`
  (and `_with_context`). No change to `InMemoryMethodCallback`, `MethodCall`, or the Call service.
