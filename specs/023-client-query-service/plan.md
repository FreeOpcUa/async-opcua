# Implementation Plan: Client Query Service (QueryFirst / QueryNext)

**Branch**: `023-client-query-service` | **Date**: 2026-06-22 | **Spec**: [spec.md](./spec.md)
**Input**: Feature specification from `/specs/023-client-query-service/spec.md`

## Summary

Add `QueryFirst` / `QueryNext` to the async-opcua **client** (the server side already implements Query
via the in-memory `QueryFirstHandler`/`QueryNextHandler`, used by `CoreNodeManager`). Mirror the existing
client service-method pattern (builder + `send(&self.channel)` + a thin `pub async fn` on `Session`),
then add the **first** end-to-end Query tests — which double as the first coverage of the server handler
and may surface real server defects to fix minimally. (US1 client API MVP; US2 e2e verification; US3
demo/doc + continuation release.)

## Technical Context

**Language/Version**: Rust (workspace edition 2021).
**Primary Dependencies**: `async-opcua-client` (Session, channel, `RequestHeaderBuilder`,
`builder_base!`/`builder_error!` macros), `async-opcua-types` Query wire types (`QueryFirstRequest/
Response`, `QueryNextRequest/Response`, `ViewDescription`, `NodeTypeDescription`, `ContentFilter`,
`QueryDataSet`, `ContinuationPoint`). **No new dependency.**
**Storage**: N/A.
**Testing**: integration tests through the live server via the harness (`setup()` etc.), run
single-threaded; authored + run by Claude.
**Target Platform**: library; all feature legs.
**Project Type**: library + samples.
**Performance Goals**: N/A.
**Constraints**: additive (new client methods only); no new dep; clippy clean on all-features + json-off
legs; existing suites pass.
**Scale/Scope**: 1 new client module (`services/query.rs`) + 2 `Session` methods + integration tests
(+ optional doc/demo). Possibly a minimal server-handler fix if tests surface a defect.

### Key facts (verified in code)

- Client service-method pattern (`services/node_management.rs`, `services/view.rs`): a builder struct
  `Op::new(session)` with `header: RequestHeaderBuilder::new_from_session(session)` + per-field setters +
  `.send(&self.channel).await?` returning the typed response; a thin `pub async fn` on `Session` wraps
  it. New module registered as `pub(super) mod query;` in `services/mod.rs`; methods exposed on `Session`.
- Wire types: `QueryFirstRequest { view, node_types: Option<Vec<NodeTypeDescription>>, filter:
  ContentFilter, max_data_sets_to_return, max_references_to_return }` → `QueryFirstResponse {
  query_data_sets: Option<Vec<QueryDataSet>>, continuation_point, parsing_results, filter_result, ... }`.
  `QueryNextRequest { release_continuation_point: bool, continuation_point }` → `QueryNextResponse {
  query_data_sets, revised_continuation_point }`.
- Server: `InMemoryNodeManager::query` → `QueryFirstHandler`/`QueryNextHandler::execute`
  (`services/query/handlers.rs`); `CoreNodeManager = InMemoryNodeManager<CoreNodeManagerImpl>`. The
  handler supports node-type descriptions, content filter, traversal, data sets, authorization
  (`query_result_is_authorized`) and continuation points (`BadContinuationPointInvalid`).
- **Open verification points** (tests determine actual behavior; don't assume): whether a non-default/
  unknown `ViewDescription` is rejected (the backlog says `BadViewIdUnknown`, but `execute()` did not
  obviously reject views — may be stale); the empty-result status. The tests assert the ACTUAL handler
  behavior and, if it deviates from Part 4 §5.9 in a clear defect, a minimal server fix is in scope.

## Constitution Check

- **I. Correctness Over Completion**: the new tests are the first real exercise of the server Query
  handler; any genuine defect they surface is FIXED minimally, not masked. Status codes surfaced
  faithfully. ✅
- **IV. Security Is Paramount**: Query is remotely reachable; tests confirm authorization filtering (no
  unauthorized nodes returned) and no panic on malformed/oversized input (bounded by existing limits). ✅
- **II/III. Do It Right Once / Discipline**: reuse the existing client builder pattern + wire types; no
  parallel path; additive; one commit per story. ✅
- **V. Leave It Better**: Query becomes usable from the SDK + gains its first test coverage; corrects a
  stale backlog entry. ✅
- **Verification division**: codex writes the client methods (+ any minimal server fix); Claude authors/
  runs all tests, anchored to Part 4 §5.9 + real round-trips. ✅

**Gate: PASS** — no violations; no Complexity Tracking entries.

## Project Structure

### Documentation (this feature)

```
specs/023-client-query-service/
├── spec.md  plan.md  research.md  data-model.md  quickstart.md
├── contracts/api-surface.md
└── checklists/requirements.md
```

### Source Code (repository root)

```
async-opcua-client/src/session/services/
├── query.rs            # NEW (codex): QueryFirst/QueryNext builders + Session::query_first/query_next,
│                        #   mirroring node_management.rs/view.rs (RequestHeaderBuilder + .send()).
└── mod.rs              # register `pub(super) mod query;`
async-opcua-client/src/session/...            # expose query_first/query_next on Session (re-export)
async-opcua/tests/integration/query.rs (new)  # Claude: e2e QueryFirst (type filter over core address
                                               #   space), QueryNext pagination, empty/no-match, view
                                               #   caveat, authorization, no-panic. Register `mod query;`.
async-opcua-server/src/services/query/handlers.rs  # ONLY if a real defect is surfaced (minimal fix)
```

**Structure decision**: a new client `services/query.rs` mirroring the established builder pattern; new
integration test module. Server handler untouched unless tests prove a defect. No new crate/dep.

## Complexity Tracking

No constitution violations; no entries.
