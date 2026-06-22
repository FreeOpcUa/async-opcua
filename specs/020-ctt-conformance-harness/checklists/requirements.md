# Specification Quality Checklist: OPC UA Conformance Test Harness (CTT)

**Created**: 2026-06-22 | **Feature**: [spec.md](../spec.md)

## Content Quality
- [x] Focused on conformance value; mandatory sections complete
- [x] Written for maintainers/testers

## Requirement Completeness
- [x] No [NEEDS CLARIFICATION] markers (scope chosen by the user: all three deliverables)
- [x] Requirements testable; SC measurable
- [x] Edge cases (invalid cells, ECC/RSA single-cert constraint, parallel flakiness, UACTT-out-of-CI) identified
- [x] Scope bounded (proxy smoke + ECC demo profile + guide; mixed-cert + Tier 3 facets deferred)
- [x] Dependencies/assumptions identified

## Notes
- Real UACTT can't run here (Windows/proprietary) → the CI smoke is an explicit proxy; the guide covers
  the manual Windows run. ECC is a separate server profile (single-cert constraint; 012 mixed-cert stays
  deferred). Verification division: the smoke IS the test (Claude authors/runs); codex does the demo
  ECC profile + launch script.
