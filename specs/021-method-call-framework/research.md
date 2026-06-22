# Research: Typed Method-Call Framework

Findings from the existing method-call code and Rust trait-coherence constraints.

## Decision 1 — Layer over the existing callback, in `async-opcua-server`

**Finding**: `SimpleNodeManager` exposes `add_method_callback(id, Fn(&[Variant]) -> Result<Vec<Variant>,
StatusCode>)` and `add_method_callback_with_context(id, Fn(&RequestContext, &[Variant]) -> ...)`. The
Call service → `MethodCall` → in-memory `call()` dispatch already works.
**Decision**: implement the typed framework as a new module `async-opcua-server/src/node_manager/
method_typed.rs` whose public `typed_method(handler)` returns a closure of exactly the
`Fn(&[Variant]) -> Result<Vec<Variant>, StatusCode>` shape, so it is passed straight into the existing
`add_method_callback`. Nothing downstream changes. **Rationale**: additive (FR-006); the server crate is
where `RequestContext` and the callback types live; only `Variant`/`TryFromVariant`/`StatusCode`/`Error`
are needed from `async-opcua-types` (already a dependency) → no new dep, no types-crate edit.
**Alternatives**: putting the traits in `async-opcua-types` (rejected — the context variant needs the
server's `RequestContext`; splitting the traits across crates adds friction for no gain).

## Decision 2 — `MethodArg` (blanket over `TryFromVariant`)

**Decision**: `pub trait MethodArg: Sized { fn from_method_arg(v: Variant) -> Result<Self, StatusCode>; }`
with a blanket `impl<T: TryFromVariant> MethodArg for T` that calls `T::try_from_variant(v)` and maps the
returned `Error` to its `StatusCode` (via `From<Error> for StatusCode` / `.status()`). Arguments arrive
as `&[Variant]`; `try_from_variant` consumes a `Variant`, so the adapter **clones** each element
(`Variant: Clone`). **Rationale**: matches the TODO's `MethodArg` naming and reuses the entire existing
`TryFromVariant` conversion surface (every primitive, String, arrays, etc.) for free; the seam allows
future non-`TryFromVariant` extractors. **Alternatives**: using `TryFromVariant` directly (works, but no
seam and doesn't match the requested name); borrowing instead of cloning (rejected — `TryFromVariant` is
by-value and clone cost is negligible for method args).

## Decision 3 — `IntoMethodOutputs` for tuples only (coherence)

**Decision**: `pub trait IntoMethodOutputs { fn into_method_outputs(self) -> Vec<Variant>; }` implemented
**only for tuples** `()`, `(A,)`, `(A,B)`, … up to `(A,B,C,D,E,F)` (arity 0..=6) via a macro, where each
`Tᵢ: Into<Variant>`. A single output is returned as a 1-tuple `(x,)`. **Rationale**: a blanket
`impl<A: Into<Variant>> IntoMethodOutputs for A` would **conflict** with the tuple impls under Rust
coherence (the compiler cannot rule out a downstream `Into<Variant>` for a tuple), so the two cannot
coexist. Tuples-only is unambiguous and the `(x,)` form is a tiny, well-understood cost. The spec's
"plus single values" intent is satisfied via the 1-tuple. **Alternatives**: a distinct wrapper type for
single outputs (more ceremony than `(x,)`); a proc-macro attribute on the user fn (heavier, defer).

## Decision 4 — Status-code mapping + the `argumentResults` limitation (refines FR-004)

**Decision** (operation-level status, returned as the callback's single `StatusCode`):
- `args.len() < N` → `BadArgumentsMissing`.
- `args.len() > N` → `BadTooManyArguments`.
- any argument fails `MethodArg::from_method_arg` → `BadInvalidArgument` (operation-level), with the
  failing index emitted via `log`/diagnostic.
- user returns `Err(e)` → `e.into(): StatusCode` (so `StatusCode` passes through and the crate `Error`
  maps via `From<Error>`).
- success → `Ok(outputs.into_method_outputs())`, status `Good`.

**Finding / limitation**: the in-memory `call()` maps a callback `Err(code)` with
`MethodCall::set_status(code)` and **never** calls `set_argument_error`, so the wire
`inputArgumentResults` vector cannot be populated through `add_method_callback` (which only carries a
`StatusCode`). **Decision**: deliver the correct **operation-level** status (above) — which is the
spec-significant, client-visible outcome — and document that per-argument `argumentResults` would require
a richer callback type, deferred to preserve the additive/no-breakage constraint (FR-006). This is a
deliberate, recorded scope refinement of FR-004 (Constitution II "record the shortcut"). **Rationale**:
returning `BadInvalidArgument`/`BadArgumentsMissing`/`BadTooManyArguments` is exactly what a conformant
client checks; faking a per-arg vector through a path that discards it would be dishonest and impossible.
**Alternatives**: add a third callback map returning `(StatusCode, Vec<StatusCode>)` (rejected for MVP —
broader surface; can be a follow-up if a real consumer needs per-arg results).

## Decision 5 — The handler trait + tuple macro

**Decision**: `pub trait MethodHandler<Args> { fn handle(&self, args: &[Variant]) -> Result<Vec<Variant>,
StatusCode>; }`, implemented by a macro for `F: Fn(A1,…,An) -> Result<O, E>` where `Aᵢ: MethodArg`,
`O: IntoMethodOutputs`, `E: Into<StatusCode>`, for n = 0..=6. The `Args` type parameter (a marker tuple)
lets `typed_method` infer the closure shape (axum-style). `typed_method<F, Args>(f) -> impl Fn(&[Variant])
-> Result<Vec<Variant>, StatusCode> + Send + Sync` wraps it. **Rationale**: mirrors the codebase's
existing macro-generated `TryFromVariant` impls; arities 0..=6 cover real methods (extendable later).
**Alternatives**: hand-writing each arity (verbose, error-prone); proc-macro (overkill).

## Decision 6 — Context variant (US3)

**Decision**: a parallel `MethodHandlerWithContext<Args>` for `Fn(&RequestContext, A1,…,An) -> Result<O,
E>` and `typed_method_with_context(f) -> impl Fn(&RequestContext, &[Variant]) -> Result<Vec<Variant>,
StatusCode>`, fed to `add_method_callback_with_context`. Implemented only if it falls out cleanly from
the same macro (P3). **Rationale**: the existing context-aware registration already covers the need;
this is pure ergonomics.

## Decision 7 — Verification anchoring

**Decision**: Claude's tests are anchored to **OPC UA Part 4 Call status-code semantics** (the exact
codes in Decision 4) and to **real `Variant` round-trips** (decode each supported type, marshal each
tuple arity), plus an **end-to-end server Call** (register a typed method on a `SimpleNodeManager`, drive
it through the Call service, assert outputs + the reject codes). Not codex loopback. **Rationale**:
verification division; the status-code contract is the conformance-relevant behavior.
