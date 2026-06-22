---
description: "Task list for feature 023 — client Query service (QueryFirst/QueryNext)"
---

# Tasks: Client Query Service (QueryFirst / QueryNext)

**Input**: design docs in `/specs/023-client-query-service/`. Conformance Tier 3 #7.

**Verification division**: codex implements the client Query methods + any minimal server-handler fix
surfaced by testing (production code, NO git, NO tests); **Claude authors + runs ALL tests** independently,
anchored to OPC UA Part 4 §5.9 Query semantics + real client↔server round-trips (NOT codex loopback).
One commit per user story.

**Gate**: `cargo fmt --all --check && cargo clippy --all-targets --all-features --locked -- -D warnings`
+ json-off legs (`clippy -p async-opcua --no-default-features [--features json] -- -D warnings`) +
`cargo test -p async-opcua --test integration_tests query -- --test-threads=1`.

**Pinned facts (plan/research):** mirror the client service-method pattern (`services/node_management.rs`
`AddNodes`, `services/view.rs` `Browse`): builder `Op::new(session)` w/ `header:
RequestHeaderBuilder::new_from_session(session)` + setters + `.send(&self.channel).await?` → typed
response; thin `pub async fn` on `Session`. Register `pub(super) mod query;` in `services/mod.rs`. Wire
types: `QueryFirstRequest{view, node_types:Option<Vec<NodeTypeDescription>>, filter:ContentFilter,
max_data_sets_to_return, max_references_to_return}` → `QueryFirstResponse{query_data_sets, continuation_point,
parsing_results, filter_result, ...}`; `QueryNextRequest{release_continuation_point, continuation_point}`
→ `QueryNextResponse{query_data_sets, revised_continuation_point}`. Server already implements query
(`InMemoryNodeManager::query` → QueryFirst/QueryNextHandler; CoreNodeManager). VERIFY (don't assume) the
non-default-view + empty-result status (backlog's BadViewIdUnknown may be stale); continuation uses
BadContinuationPointInvalid. Additive; no new dep; warning-free all feature legs; run e2e single-threaded.

## Phase 1: Setup
- [X] T001 Confirm the client builder pattern + `RequestHeaderBuilder`/`.send()` plumbing, the Query wire
  types, the `services/mod.rs` registration point, and how `Session` re-exports service methods. Identify
  a queryable core ObjectType + selectable attributes for the e2e test. No code change.

## Phase 2: US1 — client QueryFirst/QueryNext API (P1) 🎯 MVP
- [X] T002 [US1] codex: create `async-opcua-client/src/session/services/query.rs` with `QueryFirst` and
  `QueryNext` builders + `Session::query_first(view, node_types, filter, max_data_sets_to_return,
  max_references_to_return)` and `Session::query_next(release_continuation_point, continuation_point)`,
  mirroring `AddNodes`/`Browse`. Register `pub(super) mod query;` in `services/mod.rs`; expose the methods
  on `Session`. Surface the server StatusCode via the existing `.send` error path. Warning-free in ALL
  feature legs. (depends T001)
- [X] T003 [P] [US1] Claude: a focused client-API integration test in
  `async-opcua/tests/integration/query.rs` (register `mod query;`) — QueryFirst returns data sets for a
  type-filtered query over the core address space; QueryNext with the continuation point returns more;
  a clearly-empty/no-match query returns the documented status (no panic). Anchored to Part 4 §5.9. (depends T002)
- [X] T004 [US1] Gate; **commit US1** (`feat(023 US1): client QueryFirst/QueryNext API + first e2e`).

## Phase 3: US2 — end-to-end verification + view caveat + authorization (P2)
- [X] T005 [US2] Claude: extend `query.rs` tests — multi-batch QueryNext pagination retrieves ALL data
  sets (no loss/duplication); assert the ACTUAL non-default/unknown-view behavior (document the real
  status, whether BadViewIdUnknown or other); authorization respected (a restricted session returns no
  unauthorized nodes — use an anonymous/limited token vs the data); crafted/oversized query → no panic.
  If a test surfaces a genuine server-handler defect, hand the minimal fix to codex (T006). (depends T002)
- [X] T006 [US2] codex (CONDITIONAL — NOT NEEDED: tests found no server defect; Query already correct — only if T005 surfaces a real defect): minimal fix in
  `async-opcua-server/src/services/query/handlers.rs` (no redesign). Re-run T005 tests. (depends T005)
- [X] T007 [US2] Gate; **commit US2** (`feat(023 US2): Query e2e — pagination, view caveat, authorization`).

## Phase 4: US3 — demo/doc + continuation release (P3, optional)
- [X] T008 [US3] Claude: a continuation-point RELEASE test (QueryNext release → subsequent use fails with
  the documented status) + a short doc/example snippet (quickstart-style) for a Query against the demo
  server, only if cheap. Gate; **commit US3** (`docs(023 US3): Query continuation-release test + example`).

## Phase 5: Polish
- [X] T009 Update `specs/conformance-gap-backlog.md` Tier 3 #7 → client Query exposed + verified e2e;
  correct the stale "CoreNodeManager doesn't implement Query" claim; record the actual view/empty status.
- [X] T010 Final gate: fmt + clippy --all-targets --all-features + json-off/no-default legs +
  `cargo test -p async-opcua --test integration_tests query -- --test-threads=1` + existing-suite spot-check.

---

## Dependencies & Execution
- Setup (T001) → US1 (T002–T004 MVP) → US2 (T005–T007) → US3 (T008, optional) → Polish. codex: T002,
  T006(conditional). Claude: all tests (T003, T005, T008) + docs. One commit per story.

## Notes
- Additive: new client methods only; server handler untouched unless a real defect is found.
- Deferred: redesigning the server Query handler; Query over non-core/non-in-memory managers; federated
  query; new query capabilities beyond the existing handler.
