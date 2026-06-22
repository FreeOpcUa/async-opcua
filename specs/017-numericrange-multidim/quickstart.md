# Quickstart / Verification: Multi-dimensional NumericRange (Part 4 §7.27)

All commands from the workspace root. Tests authored + run by Claude (verification division), anchored to
Part 4 §7.27 **Table 166** worked vectors + hand-computed 2-D/3-D sub-arrays — not loopback.

## Baseline gate (before any change)

```bash
cargo fmt --all --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test -p async-opcua-types
```

## US1 — multi-dimensional read (`range_of`)

- A 2-D array `dimensions=[3,3]`, range `1:2,0:1` → sub-array of rows 1..=2 × cols 0..=1, `dimensions=[2,2]`,
  row-major values.
- A 3-D array + multi-dim range → addressed elements + per-dimension extents as `dimensions`.
- Upper bound past a dimension extent → clamped, partial result (not error).
- Table 166 string-array vector: `["TestString","Test","String"]` `0:1,7:9` → `["ing", <Null String>]`.

## US2 — multi-dimensional write (`set_range_of`)

- Destination 2-D `[3,3]`, range `1:2,0:1`, exact-shaped source → exactly those cells replaced, all others
  unchanged, destination `dimensions` preserved.

## US3 — fail-closed StatusCodes / panic-free

- Lower bound out of range → `Bad_IndexRangeNoData` (Table 166 `7:9`, `0:1,10:15`).
- Range rank ≠ array rank → `Bad_IndexRangeNoData`.
- Write source size/type ≠ addressed sub-extent → `Bad_IndexRangeDataMismatch`; range write to non-array →
  `Bad_WriteNotSupported`.
- Oversized / overflowing declared bound (e.g. `0:4294967294`) → bounded, no panic, no unbounded alloc.

## US4 — backward compatibility

- Table 166 single-dimension rows (`0:2`→`[2,33,12]`, `3:7`→`[0,99]`, `7:9`→NoData) unchanged.
- Existing NumericRange parser tests + Variant single-dimension range tests pass unchanged.

## Final gate

```bash
cargo fmt --all --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test -p async-opcua-types
```
One commit per user story; coding to codex; tests authored + run by Claude.
