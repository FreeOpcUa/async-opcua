# Specification Quality Checklist: Reliable Notification-Delivery Hardening

## Content Quality
- [x] Behavior anchored to exact local Part 4 1.05.07 text (cited)
- [x] Focused on control-system reliability value
- [x] All mandatory sections completed

## Requirement Completeness
- [x] No [NEEDS CLARIFICATION] markers
- [x] Requirements testable (each FR → a spec-cited assertion)
- [x] Success criteria measurable
- [x] Edge cases identified (discard modes, QueueSize 1, eviction boundary, roll-over, transfer)
- [x] Scope bounded (server Subscription/Publish path; not PubSub/Safety/client/redundancy)
- [x] Assumptions + verification division stated

## Feature Readiness
- [x] FRs have acceptance criteria
- [x] Mostly characterization; fixes only where a test proves a Part-4 violation (FR-006/007)

## Notes
- Spec rules quoted from §5.13.1.5 (overflow), lifecycle (h), retransmission (i), sequence-number text.
- Highest bug-risk target: discardOldest=FALSE overflow (replace-last + flag-newest), currently untested.
