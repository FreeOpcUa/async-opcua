# Data Model: Multi-dimensional NumericRange

## NumericRange (Part 4 §7.27 / §A.3) — existing, unchanged

- `None` — not used (whole value).
- `Index(u32)` — a single element of one dimension.
- `Range(min, max)` — inclusive `min:max`; the parser guarantees `min < max` (so the application code
  never sees `min >= max`).
- `MultipleRanges(Vec<NumericRange>)` — **one entry per array dimension**, in ArrayDimensions (row-major)
  order. Each entry is an `Index` or `Range` (the BNF allows a single index per dimension).

## Array — existing, unchanged

- `value_type: VariantScalarTypeId`
- `values: Vec<Variant>` — flat, **row-major** (higher-rank dimension first; for `[d0,d1,d2]` the order is
  `[0,0,0],[0,0,1],…`).
- `dimensions: Option<Vec<u32>>` — row-major dimension extents. `None` ⇒ rank 1 (`[values.len()]`).
  Invariant: `Π dimensions == values.len()` (else the array is invalid → fail closed).

## Multi-dimensional sub-extent walk (the new logic)

Inputs: `dims: &[usize]` (array rank), `ranges: &[NumericRange]` (must be `dims.len()` entries).
Per dimension `d`: `lo_d = range.min`, `hi_d = clamp(range.max, dims[d]-1)`.
- **Rank check**: `ranges.len() == dims.len()` else `Bad_IndexRangeNoData`.
- **Lower-bound check**: any `lo_d >= dims[d]` → `Bad_IndexRangeNoData`.
- **Upper clamp**: `hi_d = min(hi_d, dims[d]-1)` (partial read result).
- **Result extents**: `extent_d = hi_d - lo_d + 1`; result `dimensions = [extent_0, …]`.
- **Row-major strides** (checked): `stride_d = Π_{e>d} dims[e]`; flat index of cell `(i_0,…,i_{n-1})` =
  `Σ_d (i_d × stride_d)`. All products via `checked_mul`/`checked_add` → overflow ⇒ `Bad_IndexRangeNoData`.
- **Result order**: iterate the Cartesian product of `[lo_d ..= hi_d]` in row-major order, pushing
  `values[flat_index].clone()`.

## Read (`range_of` MultipleRanges) → sub-array

Returns `Variant::Array { value_type, values: <selected, row-major>, dimensions: Some([extent_d…]) }`.
Size-1 extents are kept (rank preserved). Out-of-range lower / rank mismatch → `Bad_IndexRangeNoData`.

## Write (`set_range_of` MultipleRanges) → exact-size copy

The source `Variant` MUST be an array whose effective shape **exactly matches** the addressed sub-extent
(`extent_d` per dimension) and whose element type matches; copy source cell `k` → `dest.values[flat]` for
each addressed cell (row-major), leaving non-addressed elements unchanged. Mismatch in size/type →
`Bad_IndexRangeDataMismatch`; addressed extent out of range → `Bad_IndexRangeNoData`; non-array target →
`Bad_WriteNotSupported`. (Single-dimension `set_range_of` keeps its existing partial-copy behavior —
back-compat; see research Decision 4.)

## String / ByteString arrays as 2-D (read, Decision 5)

For a `String`/`ByteString` **array** with a 2-D range `[arrayRange, substringRange]`: select array
elements via `arrayRange` (lower out of range → `Bad_IndexRangeNoData`; upper clamp → partial), then apply
`substringRange` to each selected element via the existing `substring` helper; an element whose substring
is fully out of bounds becomes a **null/empty** value (partial, Table 166 row 4). If the substring lower
bound is out of range for **all** selected elements → `Bad_IndexRangeNoData` (row 5). A 1-D string/bytestring
array therefore has effective rank 2.

## StatusCode contract (Part 4 §7.27)

| Condition | Code |
|---|---|
| Lower bound out of range / no overlap / rank mismatch / overflow | `Bad_IndexRangeNoData` |
| Invalid **syntax** (handled by the parser, not here) | `Bad_IndexRangeInvalid` |
| Write: source size/type ≠ addressed sub-extent | `Bad_IndexRangeDataMismatch` |
| Range write to a non-array target | `Bad_WriteNotSupported` |
