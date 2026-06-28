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
 - Encrypted identity-token secrets now cover legacy RSA, RSA-OAEP, and ECC `EccEncryptedSecret`.
   Remaining optional follow-ups are RSA-DH / authenticated-encryption variants if a target profile
   requires them.
 - Implement a better framework for security checks on the server.
 - Write a sophisticated server example with a persistent store. This would be a great way to verify the flexibility of the server.
 - Write some "bad ideas" servers, it would be nice to showcase how flexible this is.
 - ~~Write a framework for method calls.~~ **Done** — `async-opcua-server`'s `node_manager::{MethodArg, IntoMethodOutputs, typed_method, typed_method_with_context}` (`method_typed.rs`). Write a method as a typed Rust closure (`typed_method(|name: String, n: i32| -> Result<(String,), StatusCode> { … })`); arguments decode via a `MethodArg` blanket impl over `TryFromVariant`, outputs marshal from a tuple (arity 0..=6), and the adapter returns the Part 4 Call status codes (`BadArgumentsMissing`/`BadTooManyArguments`/`BadInvalidArgument`). Additive over the existing `add_method_callback` path (raw callbacks still work). The demo server uses it (`samples/demo-server/src/methods.rs`).
 - ~~Implement `Query`.~~ **Done** — the server has QueryFirst/QueryNext handlers and the client exposes
   `Session::query_first` / `Session::query_next`; the in-memory/core node manager path has e2e coverage.

## Performance / bounded-time (Big-O) backlog

A complexity-cuts triage (bounded-time on attacker-influenced input) lives in
[`specs/complexity-cuts-backlog.md`](specs/complexity-cuts-backlog.md). Highest value first:

 - **Applied:** the real O(n²) retransmission / publish-request queue cleanup was reduced to O(n).
 - **Deferred unless measured:** retransmission key-indexing, `is_subtype_of` memoization, TranslateBrowsePaths indexing,
   client per-tick subscription recompute, CreateSession per-channel counters, priority-sort caching, and chunk-header reuse.
 - **Still useful cleanup:** make `async-opcua-pubsub` and `async-opcua-history-sqlite` optional facade deps.
