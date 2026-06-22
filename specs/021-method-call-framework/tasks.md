---
description: "Task list for feature 021 — typed method-call framework"
---

# Tasks: Typed Method-Call Framework

**Input**: design docs in `/specs/021-method-call-framework/`. Upstream `TODO.md` "framework for method calls".

**Verification division**: codex implements the traits/macro/wrapper (`method_typed.rs`) + the demo
rewrite (production/sample code, NO git, NO tests); **Claude authors + runs ALL tests** independently,
anchored to OPC UA Part 4 Call status-code semantics + real `Variant` round-trips (incl. an end-to-end
server Call), never codex loopback. One commit per user story.

**Gate**: `cargo fmt --all --check && cargo clippy --all-targets --all-features --locked -- -D warnings`
plus the json-off legs (`clippy -p async-opcua --no-default-features [--features json|xml] -- -D warnings`)
and `cargo test -p async-opcua-server method_typed` + `cargo test -p async-opcua --test integration_tests methods`.

**Pinned facts (plan/research):** layer over the UNCHANGED `SimpleNodeManager::add_method_callback`
(`Fn(&[Variant])->Result<Vec<Variant>,StatusCode>`) / `add_method_callback_with_context`
(`Fn(&RequestContext,&[Variant])->…`). `TryFromVariant::try_from_variant(Variant)` (by value → clone
each slice elem); `From<Error> for StatusCode` exists; `StatusCode: Copy` → `E: Into<StatusCode>` covers
StatusCode + Error. Status map: too-few→`BadArgumentsMissing`, too-many→`BadTooManyArguments`,
decode-fail→`BadInvalidArgument`, user-`Err`→`e.into()`. `IntoMethodOutputs` = TUPLES ONLY (coherence;
single output = `(x,)`), arity 0..=6. **Wire `argumentResults` is NOT representable** through
`add_method_callback` (single StatusCode; in-memory `call()` discards finer) → operation-level status
only (documented FR-004 refinement). New module `async-opcua-server/src/node_manager/method_typed.rs`,
re-exported. No new dep; must build warning-free in ALL feature legs.

## Phase 1: Setup
- [X] T001 Confirm the registration signatures + `RequestContext` import path + `TryFromVariant` /
  `Variant: Clone` / `From<Error> for StatusCode` / the 4 Call status codes, and the `node_manager`
  re-export point in `async-opcua-server/src/node_manager/mod.rs` + `lib.rs`. No code change.

## Phase 2: Foundational (blocking — the traits everything builds on)
- [X] T002 codex: create `async-opcua-server/src/node_manager/method_typed.rs` with the `MethodArg`
  trait + blanket `impl<T: TryFromVariant> MethodArg for T` (map `Error`→`StatusCode`), and the
  `IntoMethodOutputs` trait with a macro generating tuple impls `()`,`(A,)`,…,`(A..F)` (each
  `: Into<Variant>`). Register `mod method_typed;` and re-export `MethodArg`/`IntoMethodOutputs` from
  `node_manager/mod.rs`. Warning-free under `-D warnings`. (depends T001)

## Phase 3: US1 — Typed method registration (P1) 🎯 MVP
- [X] T003 [US1] codex: in `method_typed.rs`, add `MethodHandler<Args>` + a macro impl for
  `F: Fn(A1..An)->Result<O,E>` (n=0..=6; `Aᵢ: MethodArg`, `O: IntoMethodOutputs`, `E: Into<StatusCode>`)
  doing arity-check (`<`→BadArgumentsMissing, `>`→BadTooManyArguments), per-arg clone+decode (fail→
  BadInvalidArgument, log index), invoke, marshal. Add `pub fn typed_method<F,Args>(f)->impl
  Fn(&[Variant])->Result<Vec<Variant>,StatusCode>+Send+Sync+'static`. Re-export `typed_method`. (depends T002)
- [X] T004 [P] [US1] Claude: unit tests in `async-opcua-server/src/node_manager/method_typed.rs`
  (`#[cfg(test)]`) — anchored to Part 4 status semantics + real Variant round-trips: each supported arg
  type decodes; arity-too-few→BadArgumentsMissing; arity-too-many→BadTooManyArguments; wrong-type arg→
  BadInvalidArgument; user `Err(StatusCode)` and `Err(Error)` both surface; 0-in/0-out, 1-out `(x,)`,
  multi-out marshaling. NO panics on any bad input. (depends T003)
- [X] T005 [US1] Claude: end-to-end test in `async-opcua/tests/integration/methods.rs` (extend or add) —
  register a typed method on a `SimpleNodeManager`, invoke it through the **Call service**, assert
  correct outputs for a valid call and the reject StatusCode for a bad-arity / bad-type call. Register
  `mod methods;` if new. (depends T003)
- [X] T006 [US1] Gate (fmt + clippy all-features + the json-off/no-default legs + the two test cmds);
  **commit US1** (`feat(021 US1): typed method-call framework (MethodArg/IntoMethodOutputs/typed_method)`).

## Phase 4: US2 — demo-server adoption + before/after (P2)
- [X] T007 [US2] codex: rewrite `samples/demo-server/src/methods.rs` — express `HelloX` (1-in/1-out) and
  a multi-arg method via `typed_method`, KEEP at least one raw-Variant method (e.g. `NoOp`) to prove the
  low-level path still works. No behavior change to the methods themselves. (depends T006)
- [X] T008 [US2] Claude: verify — `cargo build -p async-opcua-demo-server` clean + a small assertion or
  manual check that the rewritten methods still produce identical results (reuse the demo or a focused
  test). Gate; **commit US2** (`feat(021 US2): demo-server adopts the typed method framework`).

## Phase 5: US3 — context-aware variant (P3, optional — only if clean)
- [X] T009 [US3] codex: add `MethodHandlerWithContext<Args>` (`Fn(&RequestContext,A1..An)->Result<O,E>`)
  + `typed_method_with_context(..)->impl Fn(&RequestContext,&[Variant])->…` reusing the same arity/decode
  /marshal logic; re-export. Skip if it doesn't fall out cleanly from the macro. (depends T003)
- [X] T010 [US3] Claude: unit + (optional) e2e test for the context variant (context readable + same
  validation). Gate; **commit US3** (`feat(021 US3): context-aware typed method variant`). (depends T009)

## Phase 6: Polish
- [X] T011 Update `TODO.md` — mark the method-call framework done (or note it shipped); update
  `docs/` if a method section exists. Doc-comment the `argumentResults` limitation on `typed_method`.
- [X] T012 Final gate: fmt + clippy --all-targets --all-features + json-off/no-default legs +
  `cargo test -p async-opcua-server method_typed` + `cargo test -p async-opcua --test integration_tests
  methods` + `cargo build -p async-opcua-demo-server`; existing suites spot-check.

---

## Dependencies & Execution
- Setup (T001) → Foundational (T002) → US1 (T003–T006, the runnable MVP) → US2 (T007–T008) → US3
  (T009–T010, optional) → Polish. codex: T002, T003, T007, T009 (production/sample). Claude: all tests
  (T004, T005, T008, T010) + docs. One commit per story. T004 [P] can be written alongside T005 (same
  story, different files).

## Notes
- Additive only: `InMemoryMethodCallback` / `add_method_callback[_with_context]` / `MethodCall` / Call
  service / wire types UNCHANGED; existing raw callbacks keep working.
- Deferred: per-argument `argumentResults` over the wire (needs a richer callback type); the broader
  Tier 3 Method/Audit facet; other `TODO.md` items.
- US3 is optional; if the context variant doesn't fall out cleanly, ship US1+US2 and note US3 deferred.
