# Specification Quality Checklist: JSON DateTime Full-Precision Encoding

**Created**: 2026-06-22 | **Feature**: [spec.md](../spec.md)

## Content Quality
- [x] No implementation details leaked beyond the necessary §5.4.2.6 / format vocabulary
- [x] Focused on the conformance defect + round-trip value
- [x] All mandatory sections completed

## Requirement Completeness
- [x] No [NEEDS CLARIFICATION] markers
- [x] Requirements testable + unambiguous; SC measurable
- [x] Edge cases (whole-second, min/max sentinels, malformed) identified
- [x] Scope bounded (JSON encoder only; XML/Display/binary unchanged)

## Notes
- Single ~1-line encoder change + tests; research folded into the spec (the fix and the AutoSi/lossless
  format decision are settled). Streamlined ceremony given triviality; verification division still applies.
- One existing JSON assertion (`json.rs:448` `…00.000Z`) updates to the full-precision/minimal output.
