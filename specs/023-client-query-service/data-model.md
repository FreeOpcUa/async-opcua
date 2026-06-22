# Data Model: Client Query Service

No persistent data. Reuses existing wire types (`async-opcua-types`).

## QueryFirst (request → response)
- in: `view: ViewDescription`, `node_types: Option<Vec<NodeTypeDescription>>`, `filter: ContentFilter`,
  `max_data_sets_to_return: u32`, `max_references_to_return: u32`.
- out: `query_data_sets: Option<Vec<QueryDataSet>>`, `continuation_point: ContinuationPoint`,
  `parsing_results`, `filter_result`, `diagnostic_infos`, + operation `StatusCode` (via response header).

## QueryNext (request → response)
- in: `release_continuation_point: bool`, `continuation_point: ContinuationPoint`.
- out: `query_data_sets: Option<Vec<QueryDataSet>>`, `revised_continuation_point: ContinuationPoint`.

## QueryDataSet
- `node_id`, `type_definition_node`, `values: Vec<Variant>` (the selected attributes per
  NodeTypeDescription).

## Client surface (NEW)
- `Session::query_first(...) -> Result<…, Error>`, `Session::query_next(...) -> Result<…, Error>`
  (builders in `services/query.rs`). Additive; nothing else changes.
