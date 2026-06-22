# Implementation Plan: Bounded-Time Subscription Retransmission Queue

**Branch**: `027-retransmission-queue-bounded-time` | **Date**: 2026-06-22 | **Spec**: [spec.md](./spec.md)
**Input**: `specs/027-retransmission-queue-bounded-time/spec.md`

## Summary

Extract the per-session retransmission queue (today a bare `VecDeque<NonAckedPublish>` in
`session_subscriptions.rs`) into a `RetransmissionQueue` struct backed by a `BTreeMap<insertion_id,
entry>` (global insertion order + O(log n) oldest eviction), a `HashMap<(sub,seq), insertion_id>`
(O(1) keyed lookup), and a `HashMap<sub, BTreeSet<insertion_id>>` (O(k log n) teardown + ordered
available-sequence-numbers). This removes the O(n²)/O(acks·n)/O(removed·n) paths (teardown, ack
flood, multi-sub removal) while preserving behavior exactly: global-FIFO eviction, ack status codes,
insertion-ordered available sequence numbers, republish results, and reclaim-to-pool. Std-only, no
new dependency. Full design + decisions in [research.md](./research.md).

## Technical Context

**Language/Version**: Rust (workspace edition; stable + beta CI).
**Primary Dependencies**: none new — `std::collections::{BTreeMap, BTreeSet, HashMap}` only (FR-008).
**Storage**: in-memory per-session queue.
**Testing**: `cargo test -p async-opcua-server`; new struct-level behavior + scaling tests authored
by Claude; the existing server unit + integration suite is the behavioral baseline (Iron Law).
**Target Platform**: library; Linux CI.
**Project Type**: Rust library (async-opcua-server crate).
**Performance Goals**: enqueue/ack/evict O(log n); teardown O(k log n); republish O(1)+clone;
available_sequence_numbers O(k). No quadratic path remains.
**Constraints**: behavior-preserving (no client-observable change); reclaim-to-pool preserved on
every removal; clippy `-D warnings` across `--all-features`, `--no-default-features`, `json`-off;
existing suites pass unchanged; fork CI green.
**Scale/Scope**: one crate, one new module + rewiring ~6 methods in session_subscriptions.rs.

## Constitution Check

| Principle | Assessment |
|---|---|
| **I. Correctness Over Completion** | PASS — "done" = behavior identical to baseline (existing suite green) + new behavior tests + scaling proof; not just "faster". |
| **II. Do It Right Once** | PASS — encapsulate the queue once with the right structure; removes the standing `// potentially inefficient` debt rather than papering over it. |
| **III. Individual Task Discipline** | PASS — one codex dispatch for the struct+rewire (cohesive, must compile together), tests authored separately. |
| **IV. Security Is Paramount** | PASS (motivating) — removes a reachable asymmetric DoS (ack-flood / churn → quadratic server work) on a network-facing path; bounds per-request work. No new attack surface; std-only. |
| **V. Leave It Better Than You Found It** | PASS — deletes the quadratic loops + misleading "probably fine" comment; localizes queue logic into a tested unit. |

**Untrusted-input note**: ack batches and subscription churn are client-driven; the new structure
bounds their cost. No panic/unwrap on the path; the `(sub,seq)` uniqueness `debug_assert` is
non-reachable in release (documented in research).

No violations → no Complexity Tracking entries.

## Project Structure

```text
async-opcua-server/src/subscriptions/
├── retransmission_queue.rs   # NEW — RetransmissionQueue struct + its tests live alongside
├── session_subscriptions.rs  # field type change + rewire remove/ack/republish/available/teardown
└── mod.rs                     # NonAckedPublish (unchanged); declare the new module
```

**Structure Decision**: a new `retransmission_queue` submodule keeps the change localized and
unit-testable; `NonAckedPublish` stays in `mod.rs`. No new crate, no public-API change
(`SessionSubscriptions` method signatures and observable behavior are unchanged).

## Verification Division (binding)

- **codex** implements production code only — one dispatch for the `RetransmissionQueue` struct +
  the session_subscriptions rewiring (cohesive, compiles together). No tests, no git; verify branch
  is `027-retransmission-queue-bounded-time` after. Ponytail: minimal correct diff, preserve every
  documented behavior + reclaim-to-pool.
- **Claude** authors/runs ALL tests: struct behavior tests + scaling test + ports the two existing
  enqueue tests; runs the full server suite before (baseline) and after. Anchored to Part-4
  Publish/Republish semantics and the current behavior, not codex output.
- One commit per user story; PR to the FORK `occamsshavingkit/async-opcua`.

## Phasing

US1 (the struct + rewire, sub-quadratic, behavior-identical) → US2 (characterization + scaling
tests). US1 is the MVP; US2 proves it. Run the existing server suite green as the pre-refactor
baseline before US1 lands.
