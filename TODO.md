# TODO

This is a list of things that are known to be missing, or ideas that could be implemented. Feel free to pick up any of these if you wish to contribute.

 - Flesh out the server and client SDK with tooling for ease if use.
   - Make it even easier to implement custom node managers.
 - Implement Part 4 7.41.2.3, encrypted secrets. We currently only support legacy secrets. We should also support more encryption algorithms for secrets.
 - Implement a better framework for security checks on the server.
 - Write a sophisticated server example with a persistent store. This would be a great way to verify the flexibility of the server.
 - Write some "bad ideas" servers, it would be nice to showcase how flexible this is.
 - Write a framework for method calls. The foundation for this has been laid with `TryFromVariant`, if we really wanted to we could use clever trait magic to let users simply define a rust method that takes in values that each implement a trait `MethodArg`, with a blanket impl for `TryFromVariant`, and return a tuple of results. Could be really powerful, but methods are a little niche.
 - Implement `Query`. I never got around to this, because the service is just so complex. Currently there is no way to actually implement it, since it won't work unless _all_ node managers implement it, and the core node managers don't.

## Performance / bounded-time (Big-O) backlog

A complexity-cuts triage (bounded-time on attacker-influenced input) lives in
[`specs/complexity-cuts-backlog.md`](specs/complexity-cuts-backlog.md). Highest value first:

 - **Tier 1 — fix first:** the subscription **retransmission / publish-request queues use `Vec::remove` in a filter loop → O(n²)** under a publish flood (`async-opcua-server/src/subscriptions/session_subscriptions.rs`). Use `retain` / index by `(subscription_id, sequence_number)`.
 - **Tier 2 — index/memoize:** memoize `is_subtype_of` (type-tree walk per reference during Browse/Translate/Query, `async-opcua-nodes/src/type_tree.rs`); add a `(parent, BrowseName) → children` index for TranslateBrowsePaths.
 - **Tier 3 — cache/hoist (latency):** client per-tick subscription recompute; CreateSession all-sessions scan; per-tick priority re-sort; chunk-header re-parse.
 - Conformance backlog tie-in: fold the `Variant` MultipleRanges perf cleanup into the NumericRange work (conformance Tier 2 #4).
