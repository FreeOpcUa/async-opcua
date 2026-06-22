# Implementation Plan: Multi-dimensional NumericRange for Variant Array Indexing (Part 4 §7.27)

**Branch**: `017-numericrange-multidim` | **Date**: 2026-06-22 | **Spec**: [spec.md](./spec.md)
**Input**: Feature specification from `/specs/017-numericrange-multidim/spec.md`

## Summary

Implement correct multi-dimensional `NumericRange` read (`Variant::range_of`) and write
(`Variant::set_range_of`) per OPC UA Part 4 §7.27, replacing the read path's dimension-ignoring flatten
and the write path's unimplemented `MultipleRanges` arm. Reads select the Cartesian sub-extent across the
array's row-major `dimensions` and return a correctly-shaped sub-array (clamping upper bounds → partial
results); writes require an exact-size source match into the addressed sub-extent. String/ByteString
arrays are handled as 2-D (final index = substring). All paths are panic-free and bounded on
attacker-controlled ranges. The BNF parser and single-dimension behavior are unchanged.

## Technical Context

**Language/Version**: Rust (workspace edition 2021), `async-opcua-types` v0.19.
**Primary Dependencies**: none new — pure in-crate (`Array` flat `values` + row-major `dimensions`,
`NumericRange`, `StatusCode`). Core encoding, always compiled (no feature gate).
**Storage**: N/A.
**Testing**: `cargo test -p async-opcua-types` — Claude-authored, anchored to Part 4 §7.27 **Table 166**
worked vectors + hand-computed 2-D/3-D sub-arrays (verification division).
**Target Platform**: all async-opcua targets (incl. embedded).
**Project Type**: library (protocol stack).
**Performance Goals**: bounded time/allocation on attacker input; fold in the minor `MultipleRanges`
clone cleanup (TODO.md).
**Constraints**: panic-free + bounded on attacker ranges (clamp before allocate; checked stride/extent
arithmetic, no overflow); single-dimension behavior + BNF parser **unchanged**; `clippy --all-targets
--all-features` clean; existing NumericRange + Variant range tests keep passing.
**Scale/Scope**: two function arms (`range_of` + `set_range_of` `MultipleRanges`) + small private
row-major sub-extent helpers, all in `variant/mod.rs`.

## Constitution Check

- **I. Correctness Over Completion (NON-NEGOTIABLE)**: semantics pinned from the actual Part 4 §7.27 +
  §A.3 BNF + Table 166 (see research.md), not guessed — incl. two spec corrections
  (`Bad_IndexRangeInvalid` is syntax-only; write is exact-match). ✅
- **IV. Security Is Paramount**: `NumericRange` + Variants are network-facing/untrusted — MUST NOT panic,
  MUST clamp declared bounds (`u32::MAX`) before allocating, MUST use checked stride/extent arithmetic
  (no overflow) and checked slice access, MUST fail closed (`Bad_IndexRangeNoData`) on inconsistent
  declared `dimensions`. ✅
- **II. Do It Right Once / III. Individual Task Discipline**: one codex task per arm; one commit per
  story; reuse the existing single-dimension paths + `Array`/`substring` rather than re-rolling. ✅
- **V. Leave It Better**: replaces an incorrect flatten + a TODO stub with spec-correct code; folds in the
  small allocation cleanup; no scaffolding left. ✅
- **Verification division**: codex implements; Claude authors/runs tests anchored to Table 166 + §7.27
  (external ground truth), not codex loopback. ✅

**Gate: PASS** — no violations; no Complexity Tracking entries.

## Project Structure

### Documentation (this feature)

```
specs/017-numericrange-multidim/
├── spec.md
├── plan.md            # this file
├── research.md        # §7.27 semantics + Table 166 vectors + the 2 spec corrections
├── data-model.md      # NumericRange / Array / sub-extent walk
├── quickstart.md      # verification commands per story
├── contracts/
│   └── api-surface.md  # range_of / set_range_of MultipleRanges behavior
└── checklists/
    └── requirements.md
```

### Source Code (repository root)

```
async-opcua-types/src/
├── variant/mod.rs        # range_of (MultipleRanges arm: dimension-aware sub-array),
│                         # set_range_of (MultipleRanges arm: exact-size sub-extent write),
│                         # + private row-major sub-extent / stride helpers
├── array.rs              # (only if a shape-validation helper is warranted)
└── tests/
    └── variant.rs        # NEW (Claude): Table 166 vectors + 2-D/3-D read/write + negatives + bounds
```

**Structure decision**: contained in `variant/mod.rs` (+ tests in the existing `tests/variant.rs`); the
BNF parser (`numeric_range.rs`) and single-dimension arms are untouched. No new module/crate, no feature
gate.

## Complexity Tracking

No constitution violations; no entries.
