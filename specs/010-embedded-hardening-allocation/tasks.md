# Tasks: Embedded Hardening & Allocation Follow-ups

**Feature**: `010-embedded-hardening-allocation` | **Spec**: [spec.md](./spec.md) | **Plan**: [plan.md](./plan.md)

## Format: `[ID] [P?] [Story] Description with file path`

- **[P]** = parallelizable (different files, no dependency on an incomplete task)
- Production-code tasks are dispatched to **codex one at a time** (Constitution III); tests/measurement performed directly. Commit cadence: **one commit per user story**.

---

## Phase 1: Setup (Shared Infrastructure)

- [ ] T001 Record pre-feature baselines: full `cargo test --workspace` pass count, the publish-allocation baseline (`publish_allocation_baseline_reports_construction_and_clone --ignored`), and `cargo fmt --all --check` / `cargo clippy --locked -D warnings` clean — capture numbers in `specs/010-embedded-hardening-allocation/research.md` (Cross-cutting section).
- [ ] T002 [P] Inventory the existing fuzz targets and decode entry points under `fuzz/` (and their corpora) so the US1 panic-hunt extends them rather than duplicating.

---

## Phase 2: Foundational (Blocking Prerequisites)

*(None blocking — the decode limits live with US1; the allocation harness extension lives with US2. No shared foundational code precedes the stories.)*

---

## Phase 3: User Story 1 — A hostile or buggy peer cannot crash or exhaust the server (Priority: P1) 🎯 MVP

**Goal**: every remote-reachable path is panic-free and bounded; the server rejects hostile input cleanly and keeps serving others.
**Independent test**: feed crafted/malformed/oversized/deeply-nested inputs (regression + fuzz); assert no panic/abort, bounded memory, recoverable errors, other clients served (SC-001/SC-002).

### Tests for User Story 1

- [ ] T003 [P] [US1] Reproduction/regression test: a chunk declaring `message_size > max_message_size` is rejected before buffering, in `async-opcua-core/tests/` (or inline `tcp_codec` test) (FR-002).
- [ ] T004 [P] [US1] Regression test: structure nested past `max_decode_depth` returns a decode error; at-limit succeeds, in `async-opcua-types/` tests (FR-003).
- [ ] T005 [P] [US1] Test: GDS registry stays bounded + defined FIFO-evict on overflow, in `async-opcua-server/tests/` (FR-004).

### Implementation for User Story 1

- [ ] T006 [US1] Enforce `max_message_size` in `TcpCodec::decode` and make `MessageHeader::decode` honor its `DecodingOptions` (reject over-limit declared size before buffering → `BadTcpMessageTooLarge`) in `async-opcua-core/src/comms/tcp_codec.rs` + `async-opcua-core/src/comms/tcp_types.rs` (FR-002).
- [ ] T007 [US1] Add `max_decode_depth` to `DecodingOptions` (safe default) + a depth counter at the recursive nesting points (ExtensionObject/Variant/Array/custom-struct) in `async-opcua-types/src/` (FR-003).
- [ ] T008 [US1] Cap/TTL the GDS push registries (`signing_requests`, `created_requests`) with FIFO-evict + config in `async-opcua-server/src/.../gds/push_methods.rs` (FR-004).
- [ ] T009 [US1] Cap/TTL the GDS pull registries (`rejected`/`updated`/`finished`) with FIFO-evict + config in `async-opcua-server/src/.../gds/pull_methods.rs` (FR-004).
- [ ] T010 [US1] Panic-surface: add scoped `#![deny(clippy::unwrap_used, expect_used, indexing_slicing, panic)]` to `async-opcua-types` and drive to zero (Result/checked replacements; justified `#[allow]` only) (FR-001).
- [ ] T011 [US1] Panic-surface sweep on `async-opcua-core` (same lints, fix to zero) (FR-001).
- [ ] T012 [US1] Panic-surface sweep on `async-opcua-crypto` (same lints, fix to zero) (FR-001).
- [ ] T013 [US1] Panic-surface sweep on the decode/transport paths of `async-opcua-server` (lints scoped to those modules, fix to zero) (FR-001).
- [ ] T013b [P] [US1] Panic-surface sweep on the decode/transport paths of `async-opcua-client` (lints scoped to those modules, fix to zero) (FR-001).
- [ ] T014 [US1] Panic-hunting fuzz pass: extend/run the `fuzz/` decode targets under a constrained stack; confirm zero panic/abort over the corpus (FR-001, SC-001).

**Checkpoint**: server is panic-free + bounded against hostile input — releasable security baseline. **Commit US1.**

---

## Phase 4: User Story 2 — Steady-state operation has minimal, predictable allocation (Priority: P2)

**Goal**: cut steady-state per-tick (event path) and per-request allocation churn, byte-identical on the wire.
**Independent test**: allocation harness shows constant per-tick event-path allocation + reduced per-request allocation; full integration suite green (SC-003/SC-004/SC-005).

### Tests for User Story 2

- [ ] T015 [P] [US2] No-stale-data regression test for the event pool (decreasing event-batch sizes prove no leftover events leak) in `async-opcua-server/src/subscriptions/subscription.rs` tests (FR-005).

### Implementation for User Story 2

- [ ] T016 [US2] Extend the counting-allocator baseline harness to measure the event-notification path (and the small-read dispatch path) in `async-opcua-server/src/subscriptions/subscription.rs` (and a dispatch harness) (FR-010).
- [ ] T017 [US2] Pool the event-notification `Vec<EventFieldList>` — extend the `DataChangeNotificationVecPool` pattern (draw cleared + capacity-checked; reclaim at `NonAckedPublish` drop via `Arc::into_inner` + `into_inner_as::<EventNotificationList>` + clear; bounded; graceful fallback) in `async-opcua-server/src/subscriptions/` (FR-005, SC-003).
- [ ] T018 [US2] Inline read fast-path for small single-node-manager Reads avoiding per-request `Box`+`tokio::spawn`, preserving isolation, in `async-opcua-server/src/session/message_handler.rs` — **measure-first**; defer with recorded rationale if no clear win or isolation can't be kept clean (FR-006, SC-004).
- [ ] T019 [US2] Verify byte-equality + run the full `async-opcua --test integration_tests` (98) green after US2 changes (FR-009, SC-005).

**Checkpoint**: steady-state churn reduced with measured before/after numbers, wire unchanged. **Commit US2.**

---

## Phase 5: User Story 3 — Embedded deployments have guidance and lean decoding (Priority: P3)

**Goal**: documented low-jitter/low-footprint config + copy-free decode.
**Independent test**: docs section present + verifiable; string/bytestring/array decode produces identical values with fewer allocations (SC-006/SC-007).

### Tests for User Story 3

- [ ] T020 [P] [US3] Test: string/byte-string/array decode from a shareable `Bytes` source yields identical values with fewer allocations (counting-allocator assertion) in `async-opcua-types/` tests (FR-007, SC-006).

### Implementation for User Story 3

- [ ] T021 [US3] Document the `current_thread` tokio runtime as the recommended low-jitter embedded config + a size-optimized release profile (LTO, `opt-level="z"`, feature-minimal) in `docs/setup.md` and the workspace `Cargo.toml` profile (FR-008, SC-007).
- [ ] T022 [US3] Zero-copy decode: thread the source `Bytes` so `ByteString`/`String`/array decode slice/`split` from the shared buffer (covers the per-array-field decode `Vec`), identical values, copy fallback where no `Bytes` source — in `async-opcua-types/src/` — **measure-first**; stage/defer with recorded rationale if the trait-surface change outweighs the measured benefit (FR-007, SC-006).

**Checkpoint**: embedded guidance shipped; decode leaner. **Commit US3.**

---

## Phase N: Polish & Cross-Cutting Concerns

- [ ] T023 Final gate: `cargo fmt --all --check`, `cargo clippy --locked -D warnings`, full `cargo test --workspace` zero failures; `verify-clean-codegen` unaffected (no generated edits).
- [ ] T024 Record before/after allocation numbers (event path, dispatch, decode) in the PR body (FR-010) and reconcile `docs/EMBEDDED_AUDIT_2026-06-18.md` §5/§6 — mark the addressed items, note anything staged/deferred with rationale.

---

## Dependencies & Execution Order

- **Setup (Phase 1)**: T001–T002, no deps, start immediately.
- **Foundational (Phase 2)**: none.
- **US1 (Phase 3)**: depends on Setup; is the MVP / security gate. Within US1: T006/T007 (limits) are independent [P]; T008/T009 (GDS) independent [P]; T010–T013 (panic sweep) per-crate and largely independent [P] but each depends on the lints existing; T014 (fuzz) after the sweep lands.
- **US2 (Phase 4)**: depends on Setup; independent of US1 (different code). T017 depends on T016 (harness) for measurement; T018 measure-first.
- **US3 (Phase 5)**: depends on Setup; independent of US1/US2. T022 measure-first.
- **Polish**: after the stories worked.

Stories US1/US2/US3 are independently implementable and testable. **US1 first** (security gate / MVP).

## Parallel Execution Examples

- US1: T003/T004/T005 (tests, different files) in parallel; T006/T007 and T008/T009 in parallel; the per-crate panic sweeps T010/T011/T012 in parallel (different crates).
- Across stories: US1, US2, US3 touch largely disjoint code and could progress in parallel, but per Constitution III each production task is a single codex dispatch verified before the next.

## Implementation Strategy

MVP = **US1** (panic-free + bounded against hostile input) — ship/verify first. Then US2 (allocation churn), then US3 (docs + lean decode). Architectural tasks (T018 dispatch, T022 zero-copy) are **measure-first** and may be staged/deferred within the feature if the measured benefit does not justify the risk, with the rationale recorded (Constitution I/II).
