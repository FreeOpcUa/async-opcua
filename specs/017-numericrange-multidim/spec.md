# Feature Specification: Multi-dimensional NumericRange for Variant Array Indexing (Part 6 §6.9)

**Feature Branch**: `017-numericrange-multidim`
**Created**: 2026-06-22
**Status**: Draft
**Input**: Complete multi-dimensional `NumericRange` support for `Variant` array indexing (Tier 2 #4 in
`specs/conformance-gap-backlog.md`), per OPC UA Part 6 §6.9 and the Part 4 NumericRange BNF.

## Context *(mandatory)*

`NumericRange` is the index-range syntax used by the Read and Write services (the `IndexRange`
parameter) and by monitored-item filters to address a **sub-range** of an array or string Value. Per the
Part 4/6 BNF, a comma separates **dimensions** of a multi-dimensional array (e.g. `1:2,0:1` selects rows
1..=2 of dimension 0 *and* columns 0..=1 of dimension 1), not disjoint ranges.

async-opcua parses the BNF correctly into `NumericRange::{None, Index, Range, MultipleRanges}` (where
`MultipleRanges` holds one entry per dimension), and `Array` carries the flat `values` plus a row-major
`dimensions` descriptor. But the multi-dimensional application is **incomplete / incorrect**:

- **Write** (`Variant::set_range_of`): the `MultipleRanges` case is unimplemented — it logs "Multiple
  ranges not supported" and returns `Bad_IndexRangeNoData`. Writing a sub-range of a multi-dimensional
  array does not work.
- **Read** (`Variant::range_of`): the `MultipleRanges` case **ignores the array's `dimensions`** and
  flattens each range as an independent 1-D slice of the same flat `values` vector — producing a wrong,
  flat concatenation instead of a correctly-shaped multi-dimensional sub-array.

This feature implements correct multi-dimensional `NumericRange` read and write per Part 6 §6.9, while
preserving the existing (correct) single-dimension behavior and the fail-closed StatusCode contract. The
inputs are attacker-controlled (they arrive in Read/Write requests), so the work must be panic-free and
bounded.

## User Scenarios & Testing *(mandatory)*

### User Story 1 — Read a multi-dimensional sub-range (Priority: P1) 🎯 MVP

As an OPC UA client reading a sub-range of a multi-dimensional array Value (Read with `IndexRange`), I
want a multi-dimensional `NumericRange` to select the correct sub-extent across every dimension and
return a correctly-shaped sub-array, so I get exactly the elements the range addresses.

**Why this priority**: Read is the most common path for `IndexRange`; the current flattening returns
wrong data, which is a correctness/conformance defect.

**Independent Test**: For a known 2-D and 3-D array (known `dimensions` + values), applying a known
multi-dimensional range yields exactly the Part 6 §6.9 sub-array — both the selected element values and
the resulting `dimensions` — verified against hand-derived expectations from the spec, not the code.

**Acceptance Scenarios**:

1. **Given** a 2-D array with `dimensions = [3,3]` (row-major) and a range `1:2,0:1`, **When** read,
   **Then** the result is the sub-array of rows 1..=2 × columns 0..=1 with `dimensions = [2,2]`, in
   row-major order.
2. **Given** a 3-D array and a multi-dimensional range, **When** read, **Then** the result contains
   exactly the addressed elements with `dimensions` equal to the per-dimension selected extents.
3. **Given** a range whose upper bound exceeds a dimension's extent, **When** read, **Then** the bound is
   clamped to that dimension (per §6.9) and the in-range elements are returned (not an error), matching
   the existing single-dimension clamping behavior.

---

### User Story 2 — Write a multi-dimensional sub-range (Priority: P1)

As an OPC UA client writing a sub-range of a multi-dimensional array Value (Write with `IndexRange`), I
want a multi-dimensional `NumericRange` to copy the source values into exactly the addressed sub-extent
of the destination array, leaving the rest unchanged.

**Why this priority**: Write `IndexRange` is the matching half; today it is entirely unsupported for
multi-dimensional arrays (returns an error).

**Independent Test**: Writing a correctly-shaped source sub-array into a known multi-dimensional range of
a destination array updates exactly the addressed elements (verified element-by-element) and leaves all
other elements unchanged; the destination `dimensions` are preserved.

**Acceptance Scenarios**:

1. **Given** a destination 2-D array `dimensions = [3,3]` and a range `1:2,0:1` with a matching source
   sub-array, **When** written, **Then** exactly the rows 1..=2 × columns 0..=1 elements are replaced and
   every other element is unchanged.
2. **Given** a write whose source sub-array does NOT exactly match the addressed sub-extent (wrong shape
   or element type), **When** written, **Then** it is rejected with `Bad_IndexRangeDataMismatch` — a
   multi-dimensional write is exact-size per §7.27 ("the size of the array shall match the size specified
   by the NumericRange"), not a partial copy.

---

### User Story 3 — Edge cases & fail-closed StatusCodes (Priority: P1)

As the server processing attacker-controlled Read/Write `IndexRange` values, I want every malformed,
out-of-range, mismatched, or oversized range rejected with the correct StatusCode and **never a panic**,
so the index-range surface is safe and conformant.

**Why this priority**: These values are remote and untrusted; a panic or unbounded allocation here is a
DoS, and conformance requires the exact StatusCodes.

**Independent Test**: Each negative case returns the documented StatusCode and never panics: a range with
more dimensions than the array's rank, a dimension fully out of range / no overlap, `min > max`, a write
target that is not an array, a multi-dimensional range against a scalar/string, and an oversized declared
sub-extent (must be clamped/bounded, not allocated wholesale).

**Acceptance Scenarios**:

1. **Given** a multi-dimensional range with more dimensions than the array's rank, **When** applied,
   **Then** it is rejected (no panic) with the appropriate StatusCode.
2. **Given** a dimension range that selects nothing (start beyond the dimension extent), **When** applied,
   **Then** `Bad_IndexRangeNoData`.
3. **Given** a structurally invalid range string (`min >= max`, bad characters), **When** parsed, **Then**
   `Bad_IndexRangeInvalid` — note this is a **parser/syntax-only** code; the parser already rejects such
   ranges, so `range_of`/`set_range_of` (which receive an already-parsed range) never emit it. All
   valid-syntax-but-invalid application-layer cases → `Bad_IndexRangeNoData`.
4. **Given** a write whose source shape/type does not match the addressed sub-extent, **When** applied,
   **Then** `Bad_IndexRangeDataMismatch`; a range write to a non-array → `Bad_WriteNotSupported`.
5. **Given** an oversized declared sub-extent (e.g. a huge upper bound), **When** applied, **Then** it is
   bounded to the actual values length — no unbounded allocation, no integer overflow, no panic.

---

### User Story 4 — Backward compatibility (Priority: P2)

As a maintainer, I want the existing single-dimension behavior and the BNF parser to remain unchanged, so
no current usage regresses.

**Independent Test**: All existing `NumericRange` parser tests and `Variant` range tests still pass; the
`None` / `Index` / `Range` single-dimension read and write for arrays and the String/ByteString substring
path behave exactly as before.

**Acceptance Scenarios**:

1. **Given** the existing single-dimension read/write and string-substring cases, **When** exercised,
   **Then** results are identical to today.
2. **Given** the existing NumericRange BNF parser, **When** parsing valid/invalid range strings, **Then**
   behavior is unchanged.

### Edge Cases

- A multi-dimensional range whose dimension count differs from the array's `dimensions` rank.
- An array with no `dimensions` (treated as 1-D) addressed by a multi-dimensional range.
- A dimension range partially or fully out of the dimension extent (clamp the upper bound; empty
  selection → `Bad_IndexRangeNoData`).
- Huge declared bounds → must clamp to actual extent (no unbounded allocation / overflow / panic).
- Multi-dimensional range applied to a non-array (scalar / String / ByteString).
- Write where the source sub-array's shape/type does not match the addressed sub-extent.

## Requirements *(mandatory)*

- **FR-001**: `Variant::range_of` MUST interpret a multi-dimensional `NumericRange::MultipleRanges`
  against the array's row-major `dimensions`, selecting the per-dimension sub-extent and returning a
  sub-array whose `values` (row-major) and `dimensions` reflect exactly the selected extents (Part 6 §6.9).
- **FR-002**: `Variant::set_range_of` MUST apply a multi-dimensional `NumericRange::MultipleRanges` as an
  **exact-size** write (§7.27): the source array's shape and element type MUST match the addressed
  sub-extent exactly, copying it into the destination array (by its `dimensions`) and leaving
  non-addressed elements unchanged; a non-matching source MUST be rejected with `Bad_IndexRangeDataMismatch`
  (not a partial copy).
- **FR-003**: The existing single-dimension behavior (`None` / `Index` / `Range` for arrays and the
  String/ByteString substring path) and the NumericRange BNF parser MUST remain unchanged.
- **FR-004**: Per-dimension upper bounds that exceed the dimension extent MUST be clamped to that extent
  (consistent with the current single-dimension `Range` clamping); a selection that addresses no elements
  MUST return `Bad_IndexRangeNoData`.
- **FR-005**: The application-layer (`range_of`/`set_range_of`) StatusCode contract MUST hold:
  out-of-range / no overlap / **dimension-count vs array-rank mismatch** / overflow → `Bad_IndexRangeNoData`;
  type/shape mismatch on write → `Bad_IndexRangeDataMismatch`; range write to a non-array →
  `Bad_WriteNotSupported`. `Bad_IndexRangeInvalid` is reserved for invalid **syntax** and is produced by
  the BNF parser only (the parser already rejects `min >= max`), never by `range_of`/`set_range_of`.
- **FR-006**: All of `range_of` / `set_range_of` MUST be **panic-free** and **bounded** on
  attacker-controlled ranges and values: every dimension/index/length is checked before indexing or
  allocating; dimension products MUST NOT overflow; an oversized declared sub-extent MUST be clamped to
  the actual values length (no unbounded allocation).
- **FR-007**: Pure-Rust, no new dependencies, in `async-opcua-types` (core encoding, always compiled — no
  feature gate). `cargo clippy --all-targets --all-features` clean; existing unit + integration suites
  pass.

### Key Entities *(include if feature involves data)*

- **`NumericRange`** (Part 6 §6.9): the parsed index range — `None`, `Index(n)`, `Range(min,max)`, or
  `MultipleRanges([...])` (one entry per dimension for multi-dimensional indexing).
- **`Array`**: a Variant array — flat row-major `values` plus a row-major `dimensions` descriptor
  (higher-rank dimension first); the dimensions are what a multi-dimensional range indexes against.
- **Sub-array (read result)**: the elements addressed by a multi-dimensional range, in row-major order,
  with `dimensions` equal to the per-dimension selected extents.

## Success Criteria *(mandatory)*

- **SC-001**: A multi-dimensional Read `IndexRange` over a known 2-D and 3-D array returns exactly the
  Part 6 §6.9 sub-array — correct element values **and** correct result `dimensions` — verified against
  spec-derived expectations.
- **SC-002**: A multi-dimensional Write `IndexRange` updates exactly the addressed elements of a known
  multi-dimensional array and leaves all others unchanged (verified element-by-element).
- **SC-003**: Every application-layer negative case returns the documented StatusCode
  (`Bad_IndexRangeNoData` / `Bad_IndexRangeDataMismatch` / `Bad_WriteNotSupported`; `Bad_IndexRangeInvalid`
  remains the parser's syntax code) and **no input causes a panic** (including oversized/overflowing
  declared bounds).
- **SC-004**: All existing NumericRange parser tests and Variant single-dimension range tests continue to
  pass unchanged; `cargo clippy --all-targets --all-features` is clean with no new dependency.

## Assumptions

- **Semantics source**: the exact dimension ordering (row-major, higher-rank first), the read result's
  sub-array `dimensions`, the per-dimension clamping rule, and the precise StatusCode for each error are
  pinned from Part 6 §6.9 (NumericRange) + the Part 4 NumericRange BNF + the Read/Write `IndexRange`
  semantics in `~/opcua-specs` during `/speckit-plan` — not guessed.
- **Parser is correct**: the BNF parser is assumed correct and out of scope unless planning finds a real
  parsing bug.
- **Out of scope / deferred**: JSON/XML encoding edges (Tier 2 #5, a separate feature); any change to the
  NumericRange parser grammar.
- **In-scope cleanup**: the small `Variant` `MultipleRanges` allocation/clone cleanup (TODO.md perf
  tie-in) may be folded in where the code is already being changed, but not as a separate optimization
  project.
- **Verification division**: codex implements production code only; **Claude authors and runs all tests**
  independently — the multi-dimensional shape/value assertions derived from the Part 6 §6.9 semantics
  (hand-computed 2-D/3-D worked examples), the per-error StatusCode, and panic-free/bounded behavior on
  oversized/malformed ranges — anchored to the spec text, not the implementation.
- **Spec source**: Part 6 §6.9 + Part 4 NumericRange BNF text in `~/opcua-specs` (PDFs not committed).
