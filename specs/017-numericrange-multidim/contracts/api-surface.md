# API Surface: Multi-dimensional NumericRange

No signature changes — the two existing public methods gain correct `MultipleRanges` behavior. All in
`async-opcua-types/src/variant/mod.rs`. Panic-free + bounded on attacker input.

## `Variant::range_of(&self, range: &NumericRange) -> Result<Variant, StatusCode>`

- `None` / `Index` / `Range` arms: **unchanged**.
- `MultipleRanges(ranges)` arm — **rewritten**:
  - `Variant::Array(array)`: treat `ranges` as one-per-dimension against `array.dimensions` (or `[len]`
    if `None`). Rank mismatch / lower-bound out of range / overflow → `Bad_IndexRangeNoData`. Clamp upper
    bounds (partial). Return `Variant::Array` with the row-major selected `values` and result
    `dimensions = Some([extent_d…])`. For `String`/`ByteString`-element arrays, treat the **final** range
    entry as a per-element substring (Decision 5).
  - non-array (scalar / String / ByteString scalar): a multi-dimensional range is not applicable →
    `Bad_IndexRangeNoData` (a scalar String with a 1-D range is the existing `Index`/`Range` substring
    path, not `MultipleRanges`).

## `Variant::set_range_of(&mut self, range: &NumericRange, other: &Variant) -> Result<(), StatusCode>`

- `None` / `Index` / `Range` arms: **unchanged** (existing single-dimension partial-copy behavior).
- `MultipleRanges(ranges)` arm — **implemented** (replaces the "Not yet supported" stub):
  - target must be `Variant::Array` else `Bad_WriteNotSupported`.
  - `other` must be `Variant::Array` of matching `value_type` whose shape **exactly matches** the
    addressed sub-extent (`extent_d` per dimension) else `Bad_IndexRangeDataMismatch`.
  - addressed extent out of range / rank mismatch / overflow → `Bad_IndexRangeNoData`.
  - copy each addressed cell (row-major) from `other` into the destination; leave others unchanged.

## Private helpers (new, in `variant/mod.rs`)

- a row-major **strides** computation (checked arithmetic) from `&[usize]` dims;
- a **sub-extent iterator/collector** that yields the flat indices of the Cartesian product
  `[lo_d ..= hi_d]` in row-major order;
- a small `MultipleRanges` clone/allocation cleanup (TODO.md tie-in), in-scope only.

## Invariants

- BNF parser (`numeric_range.rs`) unchanged; single-dimension arms byte-for-byte behavior unchanged.
- No new dependency; no feature gate; `clippy --all-targets --all-features` clean.
- No panic / no unbounded allocation / no integer overflow on any attacker-controlled range or value.
