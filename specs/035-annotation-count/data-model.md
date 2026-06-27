# Data Model: AnnotationCount aggregate + Annotations Property

No persisted entities are added (annotations are already stored). This refines the aggregate input.

## AggregateInput.annotations (new field — engine.rs)

```text
pub struct AggregateInput<'a> {
    pub values: &'a [&'a DataValue],
    pub prior: Option<&'a DataValue>,
    pub next: Option<&'a DataValue>,
    pub interval_start: DateTime,
    pub interval_end: DateTime,
    pub config: &'a AggregateConfiguration,
    pub stepped: bool,
    pub annotations: &'a [DateTime],   // NEW: annotation source-timestamps in [interval_start, interval_end)
}
```

- For every aggregate except AnnotationCount, `annotations` is `&[]` and unused.
- Populated by `compute_processed_intervals` from the node's annotation timestamps (sliced per interval);
  `&[]` at the `monitored_item.rs` and test-helper construction sites.

## Annotation timestamp (derived, not stored)

An annotation is a `DataValue` whose value is `Variant::ExtensionObject(Annotation)` (validated by the
existing `is_annotation_data_value`). For AnnotationCount only the **source timestamp**
(`get_value_timestamp(annotation_dv)`) matters — the count is `annotations.len()` per interval. Content
(message/user/time fields) is not inspected.

## AnnotationCount result

```text
agg_annotation_count(input) -> DataValue {
    value:  Int32(input.annotations.len() as i32),   // >= 0
    status: Good,                                     // Calculated (Part 13 §5.4.3.20)
    source_timestamp: interval_start,                 // StartTime
    server_timestamp: now,
}
```

## Aggregate registry delta

| Item | Before | After |
|---|---|---|
| `SUPPORTED_AGGREGATE_IDS` count | 34 | 35 (adds 2351) |
| Dispatch for i=2351 | (none → `Bad_AggregateNotSupported`) | `agg_annotation_count` |

## Annotations Property (US2 — address space)

| Field | Value |
|---|---|
| BrowseName | `Annotations` |
| NodeClass | Variable |
| TypeDefinition | `PropertyType` |
| DataType | `Annotation` (i=891) |
| Reference from source variable | `HasProperty` (forward) |

Opt-in per variable via a helper; not auto-attached. Part 11 §5.1.2.
