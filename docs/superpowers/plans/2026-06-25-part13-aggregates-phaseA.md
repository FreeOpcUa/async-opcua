# Part-13 Aggregates — Phase A Plan (refactor foundation, zero new aggregates)

> codex implements; Claude validates. Scope-escape rule + `cargo fmt` in every brief; no-git guardrail.
> I (Claude) run `cargo fmt --all` after each codex dispatch (codex's rustfmt reorders imports).
> Design: `docs/superpowers/specs/2026-06-25-part13-aggregates-design.md`.
> Goal of Phase A: restructure the aggregate engine so future phases add one function per aggregate in
> `aggregates/` only — never the backends — and thread `AggregateConfiguration` to the engine. The 4
> existing aggregates (TimeAverage 2343, Minimum 2346, Maximum 2347, StandardDeviationSample 11426)
> produce BYTE-IDENTICAL output (no client-visible change). `aggregates_tests.rs` + `hda.rs` stay green.

## Current shape (grounding)

- `aggregates/engine.rs::calculate_aggregate(values_in_interval: &[&DataValue], aggregate_type: &NodeId, interval_start, interval_end) -> DataValue` — single match over the 4 NodeIds; result always `Variant::Double`, `source_timestamp = interval_start`, status from `compute_aggregate_quality`.
- `history/backend.rs::read_processed` (DEFAULT trait impl) and `async-opcua-history-sqlite/src/backend.rs:300` (OVERRIDE) BOTH: read raw via `read_raw_modified(.., return_bounds=false, ..)`, sort, `partition_intervals`, per-interval filter strictly-inside, call `calculate_aggregate`. Duplicated logic.
- `aggregates/middleware.rs::read_processed_aggregates` calls `backend.read_processed(node_id, start, end, processing_interval, &aggregate_type, None)`. It HAS `details.aggregate_configuration` but does not pass it.
- `AggregateConfiguration { use_server_capabilities_defaults, treat_uncertain_as_bad, percent_data_bad: u8, percent_data_good: u8, use_sloped_extrapolation }`.

---

### Task A1 (codex): additive new engine API (old path untouched)

**Files:** `async-opcua-server/src/aggregates/engine.rs`, `async-opcua-server/src/aggregates/mod.rs`.

Add the new structures/functions ALONGSIDE the existing `calculate_aggregate` (do NOT remove or change
it yet — A2 switches callers and deletes it). Mark new-but-unused items `#[allow(dead_code)]` so the
build stays warning-clean.

1. ```rust
   /// All inputs an aggregate needs to compute one interval (Part 13 §5.4).
   pub struct AggregateInput<'a> {
       /// Raw values whose timestamp falls inside [interval_start, interval_end), time-sorted.
       pub values: &'a [&'a DataValue],
       /// Last raw value at/before interval_start (the start-bound source). None until Phase C.
       pub prior: Option<&'a DataValue>,
       /// First raw value after interval_end (for interpolation/extrapolation). None until Phase C.
       pub next: Option<&'a DataValue>,
       pub interval_start: DateTime,
       pub interval_end: DateTime,
       pub config: &'a AggregateConfiguration,
   }
   ```
   (import `AggregateConfiguration` from `opcua_types`.)

2. Per-aggregate functions, one per existing aggregate, each `fn(input: &AggregateInput) -> DataValue`,
   porting the EXACT current logic from `calculate_aggregate` so output is identical:
   - `agg_time_average` (2343) → `calculate_time_weighted_average(numeric_points, interval_start, interval_end)`
   - `agg_minimum` (2346) → min of numeric points
   - `agg_maximum` (2347) → max of numeric points
   - `agg_std_dev_sample` (11426) → `calculate_std_dev_sample`
   Each must reproduce the current BadNoData / empty-numeric / quality handling from `calculate_aggregate`
   (the `compute_aggregate_quality` call, the BadNoData early returns, `Variant::Double` result,
   `source_timestamp = interval_start`). Factor the shared preamble (quality, numeric_points extraction,
   BadNoData guards) into a private helper so each aggregate fn is just its math.

3. ```rust
   /// Dispatch one interval to the aggregate identified by `aggregate_type`.
   pub fn dispatch_aggregate(aggregate_type: &NodeId, input: &AggregateInput) -> DataValue
   ```
   match on `aggregate_type.identifier` (the same `opcua_types::Identifier::Numeric(N)` consts), unknown
   id → the existing `BadAggregateNotSupported` DataValue. Reuse the const ids already in the file.

4. ```rust
   /// Orchestrate a full ReadProcessed: partition [start,end], build AggregateInput per interval, dispatch.
   pub fn compute_processed_intervals(
       raw_values: &[DataValue],
       aggregate_type: &NodeId,
       config: &AggregateConfiguration,
       start_time: DateTime, end_time: DateTime, processing_interval: f64,
   ) -> Vec<DataValue>
   ```
   Body = the partition + per-interval filter loop CURRENTLY in `history/backend.rs::read_processed`
   (copy it), but calling `dispatch_aggregate` with an `AggregateInput { values, prior: None, next: None,
   interval_start, interval_end, config }`. `prior`/`next` stay `None` in Phase A (Phase C wires bounds).

**Acceptance:** `cargo build -p async-opcua-server` clean (no warnings); `cargo test -p async-opcua-server --lib` green; existing `calculate_aggregate` untouched. SCOPE-ESCAPE: stay in `aggregates/`; if `AggregateConfiguration` can't be imported or the port can't reproduce current outputs, STOP + report.

---

### Task A2 (codex): switch backends to the new API + thread config; delete the old path

**Files:** `async-opcua-server/src/history/backend.rs`, `async-opcua-history-sqlite/src/backend.rs`,
`async-opcua-server/src/aggregates/middleware.rs`, `async-opcua-server/src/aggregates/engine.rs`,
`async-opcua-server/src/aggregates/mod.rs`.

1. Change the `read_processed` trait method signature (in `history/backend.rs`) to add
   `aggregate_configuration: &AggregateConfiguration` (import from `opcua_types`). Put it right after
   `aggregate_type`.
2. Default impl (`history/backend.rs`): keep the raw read (still `return_bounds = false` in Phase A),
   then REPLACE the inline partition/filter/`calculate_aggregate` block with a single
   `let processed_values = crate::aggregates::engine::compute_processed_intervals(&raw_values, aggregate_type, aggregate_configuration, start_time, end_time, processing_interval);`
3. sqlite override (`async-opcua-history-sqlite/src/backend.rs:300`): same change — add the param, keep
   its raw read, delegate to `compute_processed_intervals`. (It depends on `async-opcua-server`; confirm
   the function is reachable/`pub`. If `async-opcua-history-sqlite` does NOT depend on
   `async-opcua-server`, STOP and report — the dependency direction changes the plan.)
4. `middleware.rs`: pass `&details.aggregate_configuration` into the `backend.read_processed(...)` call.
5. DELETE the now-unused `calculate_aggregate` from `engine.rs` and drop it from `mod.rs`'s `pub use`.
   Keep `partition_intervals`, `get_value_timestamp`, `variant_to_f64`, `calculate_time_weighted_average`,
   `calculate_std_dev_sample` (now called by the new aggregate fns). Remove any `#[allow(dead_code)]`
   added in A1 that is no longer needed.

**Acceptance:** `cargo build -p async-opcua-server -p async-opcua-history-sqlite` clean; `cargo test -p async-opcua-server --lib` + `cargo test -p async-opcua-history-sqlite` green; **no behavior change** (the 4 aggregates produce identical results — `aggregates_tests.rs` unchanged + passing). SCOPE-ESCAPE: if the trait-signature change ripples beyond these files (other impls/callers of `read_processed`), STOP + list them.

---

### Task A.T (Claude): no-regression validation

- `cargo test -p async-opcua-server --test aggregates_tests` (or the integration target hosting it) +
  `cargo test -p async-opcua --test integration_tests -- hda history_read` green — the 4 aggregates'
  values/status/timestamps are byte-identical to pre-refactor (these are lock-in tests with concrete
  expected values).
- `cargo test -p async-opcua-history-sqlite` green (the override path).
- Full gate: clippy `--all-targets -D warnings` (default + `--no-default-features`), `--no-default-features`
  build, `cargo fmt --all -- --check`.
- Confirm `git diff` shows NO change to any `aggregates_tests.rs` expected values (refactor only).

---

## Self-review

- **Coverage:** A1 adds the new engine API additively (green, old path intact); A2 switches both backends
  + threads config + deletes the old path; A.T proves zero regression. No new client-visible aggregates
  (that's Phase B), matching the design's "Phase A foundation."
- **Risk:** (1) two `read_processed` impls — both updated in A2, scope-escape if more exist;
  (2) `async-opcua-history-sqlite` → `async-opcua-server` dependency direction (A2 step 3 scope-escape);
  (3) the port must be output-identical — guarded by unchanged lock-in tests in A.T.
- **Phasing fields:** `prior`/`next` exist in `AggregateInput` but are `None` until Phase C wires
  `return_bounds=true` — deliberate, avoids a struct change later and any Phase-A data change.
