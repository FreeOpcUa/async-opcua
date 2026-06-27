# Contract: AnnotationCount aggregate + Annotations Property

## AnnotationCount aggregate (Part 13 §5.4.3.20, i=2351) — US1

```text
agg_annotation_count(input) -> DataValue {
    value  = Int32(count of input.annotations)   // annotation timestamps in [interval_start, interval_end)
    status = Good (Calculated)
    source_timestamp = interval_start
}
```
- Per interval, counts annotations whose source timestamp is in `[interval_start, interval_end)`
  (start-inclusive, end-exclusive — the Count convention).
- Empty interval / no annotations → `Int32(0)`, Good (not an error).
- Advertised in `SUPPORTED_AGGREGATE_IDS` (count 34 → 35); a request is computed, not rejected.
- Does NOT require raw values in the interval (annotations are independent of the node's values).

## Annotation load path (both backends) — US1

`read_processed(node_id, aggregate_type, …)` — in BOTH the trait default (`history/backend.rs`) and the
sqlite override (`async-opcua-history-sqlite/src/backend.rs`):
```text
if aggregate_type == AnnotationCount {
    annotation_times = read_annotations(node_id, &[], None)        // all annotations for the node
        .map(|(dvs, _)| dvs.iter().map(get_value_timestamp)
            .filter(|t| *t >= start_time && *t <= end_time).sorted().collect())
        .unwrap_or_default()                                       // Err/unsupported → empty → count 0
} else {
    annotation_times = &[]                                         // no load; other aggregates unaffected
}
compute_processed_intervals(&raw_values, aggregate_type, …, annotation_times)
```
- Other aggregates: `annotation_times` is `&[]`; their results are unchanged (FR-006).
- A backend without annotation support → empty set → AnnotationCount 0 (FR-007), never an error.

## compute_processed_intervals signature change — US1

```text
compute_processed_intervals(raw_values, aggregate_type, config, start, end, interval, stepped,
                            annotation_times: &[DateTime]) -> Vec<DataValue>
```
- Per interval, slices `annotation_times` in `[min_t, max_t)` into `AggregateInput.annotations`.
- Both callers (server trait default + sqlite override) updated; the monitored-item and test-helper
  AggregateInput sites pass `&[]`.

## Annotations Property helper (Part 11 §5.1.2) — US2

```text
attach_annotations_property(address_space, &source_var) -> NodeId   // the Annotations Variable
// creates a Variable { BrowseName "Annotations", PropertyType, DataType Annotation (i=891) }
// + HasProperty reference source_var -> Annotations
```
- Opt-in per variable; browsable + readable after attach. Not auto-added to every variable.

## Invariants

- The 34 existing aggregates return identical results for all sources (annotations are additive).
- No panic on any input, including missing/unsupported annotation reads and empty intervals.
- The existing annotation store / `read_annotations` / HistoryUpdate paths are unchanged.
- Builds under `--no-default-features` and `--all-features`; sqlite parity behind the `sqlite` feature.
