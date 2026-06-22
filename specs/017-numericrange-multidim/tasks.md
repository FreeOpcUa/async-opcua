---
description: "Task list for feature 017 — multi-dimensional NumericRange for Variant array indexing (Part 4 §7.27)"
---

# Tasks: Multi-dimensional NumericRange for Variant Array Indexing (Part 4 §7.27)

**Input**: design docs in `/specs/017-numericrange-multidim/` (spec, plan, research, data-model,
contracts/api-surface, quickstart). Tier 2 #4 of the conformance backlog.

**Tests**: INCLUDED (conformance + attacker-facing decode; Constitution I/IV).
**Verification division**: codex writes production code only (no self-authored tests); **Claude authors
and runs all tests** independently, anchored to **Part 4 §7.27 Table 166** worked vectors + hand-computed
2-D/3-D sub-arrays + each negative StatusCode — NOT codex loopback. codex no-git guardrail + verify branch
after; do not let codex read/modify test files. **One commit per user story.**
Gate: `cargo fmt --all --check && cargo clippy --all-targets --all-features --locked -- -D warnings &&
cargo test -p async-opcua-types`.

**Pinned facts (research.md — Part 4 §7.27 / §A.3 / Table 166):** `NumericRange::MultipleRanges` = one
range per dimension, ArrayDimensions (row-major) order; "all dimensions shall be specified" (rank must
match). Indices 0-based, `min:max` inclusive, parser guarantees `min<max`. **Read**: any lower bound out
of range → `Bad_IndexRangeNoData`; upper bound out of range → clamp + partial. **`Bad_IndexRangeInvalid`
is SYNTAX-ONLY** (the parser; never produced by range_of/set_range_of) — valid-syntax errors (incl. rank
mismatch) → `Bad_IndexRangeNoData`. **Write is EXACT-size**: source must match the addressed sub-extent
else `Bad_IndexRangeDataMismatch`; range write to non-array → `Bad_WriteNotSupported`. **String/ByteString
arrays are 2-D** (final index = substring; out-of-bounds substring → null/empty element, partial). Result
sub-array `dimensions = [extent_d…]` (size-1 extents kept). Panic-free + bounded: clamp declared bounds
before allocating; checked stride/extent arithmetic (no overflow); checked slice access. Single-dimension
arms (None/Index/Range) + the BNF parser are UNCHANGED.

**Table 166 read vectors (external test anchors):**
`[2,33,12,0,99]` `0:2`→`[2,33,12]`; `3:7`→`[0,99]`; `7:9`→`Bad_IndexRangeNoData`;
`["TestString","Test","String"]` `0:1,7:9`→`["ing",<NullString>]`; `0:1,10:15`→`Bad_IndexRangeNoData`.

## Format: `[ID] [P?] [Story] Description`

---

## Phase 1: Setup

- [X] T001 Capture the baseline gate; re-confirm the §7.27 / §A.3 / Table 166 facts in research.md against
  `~/opcua-specs` and confirm the in-tree shapes (`NumericRange::MultipleRanges`, `Array.values` +
  `Array.dimensions` row-major, `Variant::substring`, the existing single-dimension `range_of`/`set_range_of`
  arms and the StatusCodes already used). No code change.

## Phase 2: User Story 1 — Multi-dimensional read (`range_of`) (P1) 🎯 MVP

**Goal**: a multi-dimensional `NumericRange` selects the correct sub-extent of an array's `dimensions` and
returns a correctly-shaped sub-array (upper bounds clamped → partial); string/bytestring arrays handled as 2-D.

- [X] T002 [US1] Claude-authored failing tests in `async-opcua-types/src/tests/variant.rs`: the Table 166
  read vectors (the 1-D rows must still pass; the 2 string-array rows); a 2-D array `dimensions=[3,3]`
  range `1:2,0:1` → values `[…]` with `dimensions=[2,2]` (hand-computed, row-major); a 3-D example; an
  upper-bound-past-extent clamp/partial case. Expectations derived from §7.27, not the implementation.
- [X] T003 [US1] Implement the `NumericRange::MultipleRanges` arm of `Variant::range_of` in
  `async-opcua-types/src/variant/mod.rs`: interpret one range per dimension against `array.dimensions`
  (or `[len]` if `None`), rank-check (mismatch → `Bad_IndexRangeNoData`), lower-bound check (→
  `Bad_IndexRangeNoData`), clamp upper bounds, collect the row-major Cartesian sub-extent into a sub-array
  with `dimensions=[extent_d…]`; for `String`/`ByteString`-element arrays treat the final range as a
  per-element substring (out-of-bounds substring → null/empty element; all-out-of-range → `Bad_IndexRangeNoData`).
  Add private row-major **stride** + **sub-extent flat-index** helpers using checked arithmetic
  (overflow → `Bad_IndexRangeNoData`); validate `Π dimensions == values.len()` (else fail closed).
  Panic-free; no unbounded allocation (clamp before allocate). Single-dimension arms unchanged. (codex; depends T002)
- [X] T004 [US1] Gate; verify T002 passes; **commit US1** (`feat(017 US1): dimension-aware multi-dimensional NumericRange read`).

## Phase 3: User Story 2 — Multi-dimensional write (`set_range_of`) (P1)

**Goal**: a multi-dimensional `NumericRange` copies an exact-size source sub-array into the addressed
sub-extent, leaving other elements unchanged.

- [X] T005 [US2] Claude-authored failing tests: destination 2-D `[3,3]`, range `1:2,0:1`, exact-shaped
  source → exactly those cells replaced, all others unchanged, `dimensions` preserved; a 3-D write; an
  exact-match round-trip with `range_of` (write then read back the same range).
- [X] T006 [US2] Implement the `NumericRange::MultipleRanges` arm of `Variant::set_range_of` in
  `async-opcua-types/src/variant/mod.rs` (replacing the "Not yet supported" stub): target must be an
  array (else `Bad_WriteNotSupported`); source must be an array of matching `value_type` whose shape
  **exactly matches** the addressed sub-extent (else `Bad_IndexRangeDataMismatch`); addressed extent out
  of range / rank mismatch / overflow → `Bad_IndexRangeNoData`; copy each addressed cell (row-major) from
  source into destination, leaving others unchanged. Reuse the T003 stride/sub-extent helpers. Panic-free.
  Single-dimension arm unchanged (keeps existing partial-copy behavior, back-compat). (codex; depends T003, T005)
- [X] T007 [US2] Gate; verify T005 passes; **commit US2** (`feat(017 US2): multi-dimensional NumericRange write`).

## Phase 4: User Story 3 — Fail-closed StatusCodes & panic-free bounds (P1)

**Goal**: every malformed / out-of-range / mismatched / oversized range is rejected with the correct code
and never panics.

- [ ] T008 [US3] Claude-authored tests (against the T003/T006 impls): rank mismatch (range dims ≠ array
  rank) → `Bad_IndexRangeNoData`; lower bound out of range → `Bad_IndexRangeNoData` (Table 166 `7:9`,
  `0:1,10:15`); write source shape/type ≠ addressed extent → `Bad_IndexRangeDataMismatch`; range write to
  a non-array → `Bad_WriteNotSupported`; an **oversized/overflowing declared bound** (e.g. `0:4294967294`,
  and a multi-dim range whose extents would overflow `usize`) → bounded, **no panic**, no unbounded alloc.
- [ ] T009 [US3] If T008 surfaces any gap, fix it in `variant/mod.rs` (codex; bounds/clamp/checked-arith
  only — no behavior change beyond fail-closed). Otherwise no-op.
- [ ] T010 [US3] Gate; verify T008 passes; **commit US3** (`test(017 US3): fail-closed StatusCodes + panic-free bounds`).

## Phase 5: User Story 4 — Backward compatibility (P2)

- [ ] T011 [P] [US4] Claude-authored regression tests: the Table 166 single-dimension rows
  (`0:2`→`[2,33,12]`, `3:7`→`[0,99]`, `7:9`→NoData) and a single-dimension write behave as today; confirm
  the existing NumericRange parser tests + Variant single-dimension range tests still pass.
- [ ] T012 [US4] Gate; verify T011 passes; **commit US4** (`test(017 US4): single-dimension + parser back-compat`).

## Phase 6: Polish

- [ ] T013 [P] Fold in the minor `NumericRange::MultipleRanges` clone/allocation cleanup in `variant/mod.rs`
  (TODO.md tie-in), in-scope only — no behavior change. (codex)
- [ ] T014 [P] Fuzz the attacker-reachable range application: add/extend a fuzz target over arbitrary
  `(Variant, NumericRange)` pairs running `range_of` + `set_range_of` → zero panics; run a bounded campaign.
- [ ] T015 Final gate: fmt + clippy --all-targets --all-features + `cargo test -p async-opcua-types`;
  confirm single-dimension byte-identical and the BNF parser unchanged.

---

## Dependencies & Execution Order

- **Setup (T001)** → **US1 read (T002→T003)** builds the shared stride/sub-extent helpers → **US2 write
  (T005→T006)** reuses them → **US3 negatives (T008→T009)** harden against the impls → **US4 back-compat
  (T011)** → **Polish**. One task per codex dispatch (codex: T003, T006, optionally T009, T013; all test
  tasks are Claude). Tests precede their implementation within each story.

## Implementation Strategy

**MVP = US1** (correct multi-dimensional read — the most common, currently-wrong path). US2 adds the
matching write; US3 locks the fail-closed/panic-free contract; US4 guards single-dimension back-compat.
Reuse the existing single-dimension arms, `Array.dimensions`, and `Variant::substring`; no new deps; no
feature gate.

## Notes

- codex implements production code only; Claude authors/runs all tests anchored to Table 166 + §7.27.
- Single-dimension `None`/`Index`/`Range` arms + the BNF parser are UNCHANGED; one commit per story;
  panic-free + bounded on attacker ranges; `Bad_IndexRangeInvalid` stays a parser-only (syntax) code.
- Deferred (recorded): JSON/XML encoding edges (Tier 2 #5); aligning single-dimension write to the spec's
  exact-size semantics (back-compat-risky, separate change).
