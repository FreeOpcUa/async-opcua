# Research: Multi-dimensional NumericRange (OPC UA Part 4 §7.27 / §A.3)

Pinned from the actual spec PDF in `~/opcua-specs` (Part 4 Services **1.05.07**, §7.27 Table 165/166 +
§A.3 BNF + the Read §5.10.2 / Write §5.10.4 `IndexRange` result codes). **Note**: the conformance
backlog cited "Part 6 §6.9" — that is wrong for 1.05.07 (Part 6 §6.9 is RSA-DH); NumericRange is **Part 4
§7.27**. These are the normative facts the implementation MUST follow.

## Decision 1 — Multi-dimensional indexing semantics (§7.27)

**Decision**: a multi-dimensional `NumericRange` (`MultipleRanges`) carries **one range per dimension**,
in **ArrayDimensions order** (row-major, higher-rank first — matches `Array.dimensions`). "All dimensions
shall be specified for a NumericRange to be valid." Indices are **0-based**; max index = `dim_len - 1`; a
`min:max` range is **inclusive** of both ends.
- Worked example (§7.27): a `2×2` block of a `4×4` matrix = `1:2,0:1`; `1,1` selects element `[1,1]`.
- The read result is the **Cartesian product** of the per-dimension selected indices, in row-major order,
  with result `dimensions = [extent_0, extent_1, …]` (each `extent_d = clamped_hi_d - lo_d + 1`).
- Row-major flat index: `idx = Σ_d (index_d × stride_d)`, `stride_d = Π_{e>d} dim_e`.
**Rationale**: §7.27 paragraphs + the BNF (§A.3): `<numeric-range> ::= <dimension> [',' <numeric-range>]`,
`<dimension> ::= <index> [':' <dimension>]`.

## Decision 2 — StatusCodes: `Bad_IndexRangeInvalid` is SYNTAX-ONLY

**Decision**: per §7.27, "`Bad_IndexRangeInvalid` is only used for invalid **syntax** of the NumericRange.
All other invalid requests with a valid syntax shall result in `Bad_IndexRangeNoData`." The BNF parser
(`numeric_range.rs`) already rejects bad syntax — including `min >= max` (`"7:5"`, `"5:5"` are invalid) —
so a **parsed** `NumericRange` always has `min < max`. Therefore `range_of`/`set_range_of` (which receive
an already-parsed range) **never** produce `Bad_IndexRangeInvalid`; their valid-syntax error is
`Bad_IndexRangeNoData`.
- **Corrects spec FR-005**: a `min > max` range and a dimension-count-vs-rank mismatch are NOT
  `Bad_IndexRangeInvalid` in the application code — `min>max` is rejected at parse time
  (`Bad_IndexRangeInvalid` belongs to the decode/parse layer), and a dimension-count mismatch is valid
  syntax → **`Bad_IndexRangeNoData`**.
**Rationale**: §7.27 + the existing parser (`from_str` returns `NumericRangeError` for `min>=max`).

## Decision 3 — Read out-of-range: lower→NoData, upper→clamp/partial (§7.27, Table 166)

**Decision** (read / `range_of`):
- If **any** dimension's **lower** bound is out of range (`lo_d >= dim_d`) → **`Bad_IndexRangeNoData`**.
- If a dimension's **upper** bound is out of range (`hi_d >= dim_d`) → **clamp** to `dim_d - 1` and return
  **partial results** (not an error).
- A dimension-count mismatch (range rank ≠ array rank) → `Bad_IndexRangeNoData` (Decision 2).
**Table 166 read vectors (external test anchors — derive expectations from these, not the code):**

| Value | Range | Result |
|---|---|---|
| `[2,33,12,0,99]` | `0:2` | `[2,33,12]` |
| `[2,33,12,0,99]` | `3:7` | `[0,99]` (upper clamped, partial) |
| `[2,33,12,0,99]` | `7:9` | `Bad_IndexRangeNoData` (lower out of range) |
| `["TestString","Test","String"]` | `0:1,7:9` | `["ing", <Null String>]` (array dim 0:1 + substring 7:9; out-of-bounds substring → null) |
| `["TestString","Test","String"]` | `0:1,10:15` | `Bad_IndexRangeNoData` (substring lower bound out of range for all) |

The single-dimension read (`None`/`Index`/`Range`) already matches rows 1–3 (verified) — keep it.

## Decision 4 — Write is EXACT-size, not partial (§7.27 + Write §5.10.4)

**Decision** (write / `set_range_of`): "When writing a value, the size of the array shall match the size
specified by the NumericRange. The Server shall return an error if it cannot write all elements." So a
multi-dimensional write requires the **source sub-array to exactly match the addressed sub-extent**
(per-dimension extents and element type); otherwise → **`Bad_IndexRangeDataMismatch`** (Write table:
"The data to be written does not match the IndexRange"). A range write to a non-array →
`Bad_WriteNotSupported`. Out-of-range addressed extent → `Bad_IndexRangeNoData`.
- **Back-compat tension (decision)**: the EXISTING single-dimension `set_range_of` does a *partial* copy
  (copies until source or dest is exhausted), which is NOT the spec's exact-match. Per spec FR-003
  (single-dimension behavior unchanged) we **preserve the existing single-dimension partial-copy
  behavior** and implement the **new multi-dimensional write per spec (exact match)**. This deviation is
  recorded; aligning single-dimension write to exact-match is a separate, larger back-compat change and
  is **out of scope** here (would touch existing tests/callers).
**Rationale**: §7.27 write paragraph + Write service `Bad_IndexRangeDataMismatch`.

## Decision 5 — String / ByteString arrays are 2-D (final index = substring)

**Decision**: "Arrays of ByteString and String values are treated as two dimensional arrays where the
final index specifies the substring range." So for a `String`/`ByteString` **array**, a 2-D range =
`[arrayDim , substringDim]`: select the array elements with the first range, then apply the substring
range to each selected element. An out-of-bounds substring for an element → that element is a **null /
empty** value (partial), NOT an error (Table 166 row 4). If the substring lower bound is out of range for
**all** elements → `Bad_IndexRangeNoData` (row 5). A **scalar** String/ByteString with a 1-D range = the
existing `substring` path (unchanged). The implicit substring dimension means a 1-D string/bytestring
array has effective rank 2 for range purposes.
**Rationale**: §7.27 substring paragraph + Table 166 rows 4–5.

## Decision 6 — Panic-free & bounded on attacker input (FR-006)

**Decision**: `NumericRange` + the Variants arrive in Read/Write requests (attacker-controlled). The
implementation MUST:
- Check the range rank against the array rank before indexing.
- Clamp every upper bound to the actual dimension extent **before** computing extents/allocations (the
  declared `max` can be up to `u32::MAX` — never allocate from it).
- Compute strides / element counts with **checked** arithmetic (`checked_mul`/`checked_add`) and bail to
  `Bad_IndexRangeNoData` on overflow — never panic, never allocate unbounded.
- Validate `dimensions` consistency (`Π dimensions == values.len()`); if inconsistent, fail closed
  (`Bad_IndexRangeNoData`) rather than trusting the declared shape.
- Use only checked slice access (`.get`/`.get_mut`), never index-panic.
**Rationale**: Constitution IV (network-facing, untrusted input); the existing `clippy::indexing_slicing`
discipline elsewhere in the crate.

## Decision 7 — Scope / structure

**Decision**: implement entirely in `async-opcua-types/src/variant/mod.rs` (`range_of` + `set_range_of`
`MultipleRanges` arms), with small private helpers for the row-major sub-extent walk; `array.rs` only if a
shape-validation helper is warranted. No feature gate (core encoding, always compiled). No new deps. The
BNF parser (`numeric_range.rs`) is unchanged (it is correct, Decision 2). Fold in the minor `MultipleRanges`
clone/allocation cleanup while here (TODO.md tie-in), in-scope only.

## Decision 8 — Test anchoring (verification division)

**Decision**: Claude-authored tests anchored to **Table 166** (the 5 worked vectors above) + hand-computed
2-D/3-D numeric sub-arrays (assert both values and result `dimensions`) + each negative StatusCode + an
oversized/overflowing-bound case proving no panic / bounded allocation. The expectations are derived from
§7.27, not from the implementation.
**Rationale**: the project's verification division (codex writes code; Claude writes spec-anchored tests);
prior features caught self-verification bugs.

## Open question deferred to implementation

- The exact representation of a 3-D+ read result's `dimensions` when an inner extent collapses to 1 — keep
  all selected extents (including size-1 dimensions) so the rank is preserved, matching ArrayDimensions
  semantics; confirm against any existing multi-dim test fixtures during implementation.
