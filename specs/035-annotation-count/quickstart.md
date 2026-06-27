# Quickstart: AnnotationCount aggregate + Annotations Property

## Before

```text
HistoryRead(AnnotationCount, node=Temperature, start=T0, end=T1, interval=…)
→ Bad_AggregateNotSupported     // AnnotationCount was the one omitted standard aggregate
```

## After

A client has added annotations to a node via HistoryUpdate (UpdateStructureData), then reads the count:

```text
// 3 annotations at 12:00:01, 12:00:03, 12:00:05; one processing interval [12:00:00, 12:00:10)
HistoryRead(AnnotationCount, node=Temperature, start=12:00:00, end=12:00:10, interval=10s)
→ Value = Int32(3), status = Good        // Part 13 §5.4.3.20

// finer intervals partition the count
HistoryRead(AnnotationCount, …, interval=2s)
→ [0, 1, 1, 0, 1, 0, …]                   // each interval counts its own annotations; empty → 0
```

AnnotationCount now appears in the server's advertised aggregate set (i=2351), so a conformant client
discovers it via `Server.ServerCapabilities.AggregateFunctions`.

## Annotations Property (discoverability)

```text
// opt in for a variable that should expose its annotation collection
let annotations = attach_annotations_property(&mut address_space, &temperature_node);
// → Browse(Temperature, HasProperty) now includes an "Annotations" Variable (DataType Annotation)
```

## Unchanged

- The 34 other aggregates return identical results.
- Annotation values are still written/read via HistoryUpdate `UpdateStructureData` / annotation
  HistoryRead — this feature only *counts* them and makes them *discoverable*.
- A backend with no annotation support reports AnnotationCount = 0 (never an error).
