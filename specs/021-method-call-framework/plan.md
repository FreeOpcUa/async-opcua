# Implementation Plan: Typed Method-Call Framework

**Branch**: `021-method-call-framework` | **Date**: 2026-06-22 | **Spec**: [spec.md](./spec.md)
**Input**: Feature specification from `/specs/021-method-call-framework/spec.md`

## Summary

Add an additive, opt-in **typed adapter** over the existing method-registration path so a server author
can register an OPC UA Method by writing a plain Rust closure with typed parameters and a typed tuple
return, instead of a raw `Fn(&[Variant]) -> Result<Vec<Variant>, StatusCode>`. The adapter performs:
arity check → per-argument decode (`TryFromVariant`) → invoke → output marshal, choosing the
Call-service-correct StatusCode on failure. It plugs into the **unchanged** `add_method_callback` /
`add_method_callback_with_context` API on `SimpleNodeManager`; the low-level callback type, the Call
service, and the wire types are untouched. (US1 MVP; US2 demo adoption; US3 optional context variant.)

## Technical Context

**Language/Version**: Rust (workspace edition 2021).
**Primary Dependencies**: existing `async-opcua-types` (`Variant`, `TryFromVariant`, `StatusCode`,
`Error`), `async-opcua-server` (`RequestContext`, `SimpleNodeManager::add_method_callback[_with_context]`,
`InMemoryMethodCallback`). **No new dependency.**
**Storage**: N/A.
**Testing**: Rust unit tests (the adapter's decode/arity/marshal/status behavior) + a server integration
test (a typed method invoked end-to-end via the Call service), authored + run by Claude.
**Target Platform**: library; all feature configurations.
**Project Type**: library + samples.
**Performance Goals**: N/A (per-call O(arity); one clone per argument — `Variant: Clone`).
**Constraints**: additive/no-public-breakage; no new dep; warning-free under `-D warnings` in **all**
feature legs (default / all-features / no-default-features / json-off / xml-only); existing suites pass.
**Scale/Scope**: one new server module (traits + tuple macro + `typed_method` wrapper) + a demo rewrite
+ unit/integration tests.

### Key API facts (verified in code)

- `SimpleNodeManager::add_method_callback(id, impl Fn(&[Variant]) -> Result<Vec<Variant>, StatusCode>)`
  and `add_method_callback_with_context(id, impl Fn(&RequestContext, &[Variant]) -> Result<Vec<Variant>,
  StatusCode>)` (`async-opcua-server/src/node_manager/memory/simple.rs`). The typed adapter produces a
  closure of exactly these shapes.
- `TryFromVariant::try_from_variant(v: Variant) -> Result<Self, Error>` (by value → clone each slice
  element). `impl From<Error> for StatusCode` exists; `StatusCode` is `Copy`; identity `From<StatusCode>`
  is automatic → bound `E: Into<StatusCode>` accepts both `StatusCode` and the crate `Error`.
- Call status codes all exist: `BadArgumentsMissing`, `BadTooManyArguments`, `BadInvalidArgument`,
  `BadTypeMismatch`.
- **Constraint discovered**: the in-memory `call()` maps a callback `Err(code)` via
  `MethodCall::set_status(code)` and never calls `set_argument_error`, so the **wire `argumentResults`
  vector is NOT representable through `add_method_callback`** (it carries a single `StatusCode`). The
  adapter therefore returns the correct **operation-level** status (`BadInvalidArgument` on a decode
  failure, `BadArgumentsMissing` / `BadTooManyArguments` on miscount) and records the failing index in a
  log/diagnostic. Per-argument `argumentResults` would require a richer callback type — deferred, as it
  would break the additive constraint (FR-006). This refines FR-004 (see research.md Decision 4).

## Constitution Check

- **I. Correctness Over Completion**: the adapter handles every edge — arity under/over, per-arg decode
  failure, user error — with the spec-correct StatusCode and **no panic** (no indexing without bounds
  checks; clone-then-decode). The FR-004 `argumentResults` limitation is surfaced honestly rather than
  faked. ✅
- **IV. Security Is Paramount**: methods are remotely callable; the adapter must never panic on
  attacker-controlled argument count/types. Bounds-checked arity, fallible decode, total mapping to
  StatusCode. ✅
- **II/III. Do It Right Once / Discipline**: reuses `TryFromVariant` + the existing callback path rather
  than forking the Call service; macro-generates tuple arities like the existing `TryFromVariant` impls;
  additive only. One commit per user story. ✅
- **V. Leave It Better**: removes boilerplate from the sample + gives all users a safe typed path;
  advances the Tier 3 "Method Call" conformance facet (correct Call status codes). ✅
- **Verification division**: codex may implement the traits/macro/wrapper + demo rewrite (production
  /sample code); Claude authors + runs all tests, anchored to Part 4 Call status-code semantics and real
  `Variant` round-trips (incl. an end-to-end server Call), never codex loopback. ✅

**Gate: PASS** — no violations; no Complexity Tracking entries. (The FR-004 wire-`argumentResults`
nuance is a documented scope refinement, not a constitution violation.)

## Project Structure

### Documentation (this feature)

```
specs/021-method-call-framework/
├── spec.md  plan.md  research.md  data-model.md  quickstart.md
├── contracts/api-surface.md
└── checklists/requirements.md
```

### Source Code (repository root)

```
async-opcua-server/src/node_manager/
├── method_typed.rs     # NEW (codex): MethodArg (+ blanket over TryFromVariant), IntoMethodOutputs
│                        #   (tuple arities 0..=6 via macro), MethodHandler<Args> /
│                        #   MethodHandlerWithContext<Args>, `typed_method(..)` /
│                        #   `typed_method_with_context(..)` wrappers returning the existing callback
│                        #   closure shapes. Maps miscount→BadArgumentsMissing/BadTooManyArguments,
│                        #   decode-fail→BadInvalidArgument, user E: Into<StatusCode>.
├── method.rs            # (unchanged) existing MethodCall
└── mod.rs               # re-export the new public items
async-opcua-server/src/lib.rs (or node_manager re-exports)  # expose typed_method etc.
async-opcua-server/tests/ or src tests  # Claude: unit tests for decode/arity/marshal/status
async-opcua/tests/integration/methods.rs (or new)           # Claude: end-to-end typed Call test
samples/demo-server/src/methods.rs       # US2 (codex): rewrite HelloX + a multi-arg method via the
                                          #   typed API; KEEP one raw-Variant method (e.g. NoOp).
```

**Structure decision**: everything lives in `async-opcua-server` (it needs `RequestContext` for the
context variant and the callback types are there); only `Variant`/`TryFromVariant`/`StatusCode`/`Error`
are pulled from `async-opcua-types` (already deps). No types-crate change, no new crate, no new dep.

## Complexity Tracking

No constitution violations; no entries.
