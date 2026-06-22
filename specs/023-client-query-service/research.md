# Research: Client Query Service

## Decision 1 — Mirror the existing client service-method pattern
**Finding**: client services (`services/node_management.rs`, `services/view.rs`) use a builder struct
`Op::new(session)` carrying `header: RequestHeaderBuilder::new_from_session(session)` + per-field setters
+ `.send(&self.channel).await?` → typed response, wrapped by a thin `pub async fn` on `Session`.
**Decision**: add `services/query.rs` with `QueryFirst`/`QueryNext` builders and `Session::query_first` /
`query_next`, mirroring that exactly; register `pub(super) mod query;` in `services/mod.rs`.
**Rationale**: zero new abstraction, consistent with the rest of the client, no new dep.
**Alternatives**: a bespoke one-off method (rejected — inconsistent).

## Decision 2 — Method shapes
**Decision**:
- `query_first(view: ViewDescription, node_types: Vec<NodeTypeDescription>, filter: ContentFilter,
  max_data_sets_to_return: u32, max_references_to_return: u32) -> Result<QueryFirstResponse-ish, Error>`
  returning data sets + continuation point + (parsing/filter results). An ergonomic return is fine
  (e.g. return the response, or a `(Vec<QueryDataSet>, ContinuationPoint)` tuple) — match how
  browse/add_nodes shape their returns.
- `query_next(release_continuation_point: bool, continuation_point: ContinuationPoint)
  -> Result<..., Error>` returning the next data sets + revised continuation point.
**Rationale**: 1:1 with the wire types; surfaces the server StatusCode via the existing `.send` error
mapping. **Alternatives**: hide ContentFilter/ViewDescription behind helpers — defer (the raw types are
fine for an SDK method).

## Decision 3 — Verify, don't assume, the view + empty semantics
**Finding**: the server `QueryFirstHandler::execute` did not obviously reject non-default views; the
backlog's `BadViewIdUnknown` claim may be stale. Continuation handling uses
`BadContinuationPointInvalid`.
**Decision**: tests assert the ACTUAL handler behavior for (a) non-default/unknown view and (b)
empty/no-match, and document it. If the behavior is a clear Part 4 §5.9 defect (e.g. a non-empty view
silently ignored in a way that returns wrong nodes, or a panic), fix it minimally in the handler;
otherwise record the actual status as the contract. **Rationale**: correctness over completion + no
assumptions; the tests are the first coverage of this handler.

## Decision 4 — End-to-end verification anchoring
**Decision**: Claude's integration tests drive the live server through the new client API: a type-
filtered QueryFirst over the **core** address space (e.g. find instances/subtypes of a known ObjectType,
selecting BrowseName/NodeClass), QueryNext pagination via the continuation point (no loss/duplication),
empty/no-match status, view caveat, authorization (a restricted session sees no unauthorized nodes), and
a no-panic pass on crafted/oversized input. Anchored to Part 4 §5.9 + real round-trips, not loopback.
