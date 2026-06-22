# API Surface: Client Query Service

Additive — new client methods only. Server handler, wire types, and existing client methods unchanged.

## New (async-opcua-client)
```rust
impl Session {
    /// QueryFirst (OPC UA Part 4 §5.9.3). Find nodes by type + content filter; returns data sets and a
    /// continuation point for paging via `query_next`.
    pub async fn query_first(
        &self,
        view: ViewDescription,
        node_types: Vec<NodeTypeDescription>,
        filter: ContentFilter,
        max_data_sets_to_return: u32,
        max_references_to_return: u32,
    ) -> Result<QueryFirstResponse /* or an ergonomic result */, Error>;

    /// QueryNext (OPC UA Part 4 §5.9.4). Continue or release a QueryFirst continuation point.
    pub async fn query_next(
        &self,
        release_continuation_point: bool,
        continuation_point: ContinuationPoint,
    ) -> Result<QueryNextResponse /* or an ergonomic result */, Error>;
}
```
(Builders `QueryFirst`/`QueryNext` in `services/query.rs` mirror `AddNodes`/`Browse`.)

## Behavioral contract (verified by tests, anchored to Part 4 §5.9)
| Situation | Result |
|-----------|--------|
| type-filtered query over core address space | data sets for matching nodes (+ continuation point if paged) |
| QueryNext with a continuation point | next batch; full result retrievable without loss/duplication |
| QueryNext with release flag | continuation point freed |
| empty / no-match | the handler's documented status (verified) |
| non-default / unknown view | the handler's documented status (verified — backlog's `BadViewIdUnknown` is to be confirmed) |
| unauthorized nodes | not returned |
| malformed / oversized | surfaced status, no panic (bounded by server limits) |

## Non-goals / unchanged
Server Query handler (unless a real defect is found), wire types, other client methods. No new dep.
