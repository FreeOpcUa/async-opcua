# TODO

This is a list of things that are known to be missing, or ideas that could be implemented. Feel free to pick up any of these if you wish to contribute.

 - Flesh out the server and client SDK with tooling for ease if use.
   - Make it even easier to implement custom node managers.
 - Add Nano/Micro/Embedded conformance-profile builds. There is no profile feature today — the crate
   gates by capability (`generated-address-space`, crypto backend, `ecc`, `wss`, `json`, `xml`,
   `server`/`base-server`). Proposed: `nano`/`micro` feature aliases selecting the minimal set, plus a
   `samples/nano-server` that compiles against `base-server` with a minimal custom node manager (the
   default managers assume the core address space, so `base-server` doesn't build out of the box). The
   generated core address space is the dominant size lever (~4.7 MB of a 24 MB stripped server binary).
 - Implement Part 4 7.41.2.3, encrypted secrets. We currently only support legacy secrets. We should also support more encryption algorithms for secrets.
 - Implement a better framework for security checks on the server.
 - Write a sophisticated server example with a persistent store. This would be a great way to verify the flexibility of the server.
 - Write some "bad ideas" servers, it would be nice to showcase how flexible this is.
 - ~~Write a framework for method calls.~~ **Done** — `async-opcua-server`'s `node_manager::{MethodArg, IntoMethodOutputs, typed_method, typed_method_with_context}` (`method_typed.rs`). Write a method as a typed Rust closure (`typed_method(|name: String, n: i32| -> Result<(String,), StatusCode> { … })`); arguments decode via a `MethodArg` blanket impl over `TryFromVariant`, outputs marshal from a tuple (arity 0..=6), and the adapter returns the Part 4 Call status codes (`BadArgumentsMissing`/`BadTooManyArguments`/`BadInvalidArgument`). Additive over the existing `add_method_callback` path (raw callbacks still work). The demo server uses it (`samples/demo-server/src/methods.rs`).
 - Implement `Query`. I never got around to this, because the service is just so complex. Currently there is no way to actually implement it, since it won't work unless _all_ node managers implement it, and the core node managers don't.

## Performance / bounded-time (Big-O) backlog

A complexity-cuts triage (bounded-time on attacker-influenced input) lives in
[`specs/complexity-cuts-backlog.md`](specs/complexity-cuts-backlog.md). Highest value first:

 - **Tier 1 — fix first:** the subscription **retransmission / publish-request queues use `Vec::remove` in a filter loop → O(n²)** under a publish flood (`async-opcua-server/src/subscriptions/session_subscriptions.rs`). Use `retain` / index by `(subscription_id, sequence_number)`.
 - **Tier 2 — index/memoize:** memoize `is_subtype_of` (type-tree walk per reference during Browse/Translate/Query, `async-opcua-nodes/src/type_tree.rs`); add a `(parent, BrowseName) → children` index for TranslateBrowsePaths.
 - **Tier 3 — cache/hoist (latency):** client per-tick subscription recompute; CreateSession all-sessions scan; per-tick priority re-sort; chunk-header re-parse.
 - Conformance backlog tie-in: fold the `Variant` MultipleRanges perf cleanup into the NumericRange work (conformance Tier 2 #4).
