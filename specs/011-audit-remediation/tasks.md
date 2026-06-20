---
description: "Task list for feature 011 — audit remediation"
---

# Tasks: Audit Remediation (Security & Long-Uptime Hardening)

**Input**: Design documents from `/specs/011-audit-remediation/`
**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/api-surface.md, quickstart.md

**Tests**: INCLUDED. The constitution (Principle I/II: "tests accompany fixes") and the quickstart
require a regression test per fix — each must FAIL before the change and PASS after.

**Execution discipline (constitution III + project memory)**: one task per codex dispatch; complete
and verify one task before the next; **one commit per user story** (the `gate & commit` task that
closes each phase). Run the gate (`cargo fmt --all --check && cargo clippy --all-targets
--all-features --locked -- -D warnings && cargo test --workspace`) before each per-story commit.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: parallelizable (different files, no dependency on an incomplete task)
- **[Story]**: US1–US5 from spec.md

---

## Phase 1: Setup

- [ ] T001 Capture baseline per quickstart.md: run the full gate + the publish-allocation baseline and record pass counts / numbers in this feature dir (so each story can show before/after).

## Phase 2: Foundational (Blocking Prerequisites)

**None.** Each user story is an independent, surgical edit to existing crates; there is no shared
blocking prerequisite. Stories may proceed in priority order or in parallel.

---

## Phase 3: User Story 1 — Bounded history reads (Priority: P1) 🎯 MVP

**Goal**: history-sqlite reads only ~`num_values_per_node` rows regardless of range; remainder via a keyset cursor.
**Independent Test**: wide range + small cap ⇒ rows fetched ≈ cap, continuation returned, `HistoryReadNext` pages in order (quickstart US1).

- [ ] T002 [US1] Add a failing regression test in `async-opcua-history-sqlite` (tests): large populated interval, `read_raw_modified` with wide range + small `num_values_per_node`; assert rows loaded ≈ cap (not range) and a continuation token is returned; `HistoryReadNext` returns the remainder in order with no dup/gap.
- [ ] T003 [US1] Add a row `LIMIT` parameter (`num_values_per_node + 1`) to `query::fetch_interval` in `async-opcua-history-sqlite/src/query.rs`; keyset-resume support (`after = last_timestamp`).
- [ ] T004 [US1] Replace the materialized-`Vec` continuation in `async-opcua-history-sqlite/src/backend.rs` (`read_raw_modified` + Next path) with the keyset cursor from data-model.md; apply a server-side hard ceiling when `num_values_per_node == 0`. (depends on T003)
- [ ] T005 [US1] Run the gate; verify T002 passes; **commit US1** (`fix(011 US1): bound SQLite history reads — LIMIT + keyset cursor`).

**Checkpoint**: US1 independently functional and testable.

---

## Phase 4: User Story 2 — Replay-safe session activation (Priority: P1)

**Goal**: stale-nonce concurrent `ActivateSession` is rejected fail-closed; uncontended path unchanged.
**Independent Test**: race two activations; the one that observed the rotated-away nonce is rejected (quickstart US2).

- [ ] T006 [US2] Add a failing regression test in `async-opcua-server` (session tests): simulate a stale observed nonce at the commit step; assert rejection (`BadNonceInvalid`/`BadSessionIdInvalid`) with no identity/nonce mutation; assert uncontended activation still succeeds.
- [ ] T007 [US2] In `async-opcua-server/src/session/manager.rs` `activate_session`, under the write lock that commits `activate()`, re-read `session.session_nonce()` and compare to the observed value; reject if changed; preserve `is_cross_channel_transfer_forbidden` semantics. (depends on T006)
- [ ] T008 [US2] Run the gate; verify T006 passes; **commit US2** (`fix(011 US2): re-check session nonce under commit lock (replay-safe activation)`). Note in commit body: hold upstream PR pending private disclosure to Einar.

**Checkpoint**: US1 + US2 independently functional.

---

## Phase 5: User Story 3 — Bounded decode allocations (Priority: P1)

**Goal**: every decode allocation from untrusted counts is validated before allocating.
**Independent Test**: oversized UADP field counts + overflowing custom-struct dims are rejected; valid inputs byte-identical (quickstart US3).

- [ ] T009 [US3] Add PubSub decode limit fields (`max_dataset_fields`, `max_dataset_messages`, `max_secured_payload_len`) to `DecodingOptions` in `async-opcua-types` (encoding options), with conformant defaults per data-model.md and `#[serde(default)]`.
- [ ] T010 [P] [US3] Add failing tests: (a) UADP message with excessive `field_count`/dataset count rejected before allocation (`async-opcua-pubsub` tests); (b) custom multidimensional struct whose dims overflow is rejected with a decode error (`async-opcua-types` tests).
- [ ] T011 [US3] Enforce `max_dataset_fields`/`max_dataset_messages` in `async-opcua-pubsub/src/codec/uadp.rs` at lines ~172 and ~282 **before** `Vec::with_capacity`. (depends on T009)
- [ ] T012 [US3] Enforce `max_secured_payload_len` in `async-opcua-pubsub/src/security/codec.rs` before payload copy/decrypt. (depends on T009)
- [ ] T013 [P] [US3] Replace `len *= *dim as u32` with `checked_mul` in `async-opcua-types/src/custom/custom_struct.rs:495`, erroring on overflow and bounding each running product against `max_array_length`.
- [ ] T014 [US3] Run the gate; verify T010 passes; **commit US3** (`fix(011 US3): bound decode allocations (PubSub limits + checked array dims)`).

**Checkpoint**: all P1 stories independently functional.

---

## Phase 6: User Story 4 — No growth over long uptime (Priority: P2)

**Goal**: indexes/maps/tasks return to baseline under churn.
**Independent Test**: churn soak ⇒ `monitored_items`/`subscription_to_session` baseline-stable; abandoned continuations TTL-evicted; suspended `Engine` drop aborts task (quickstart US4).

- [ ] T015 [P] [US4] Add failing tests: (a) create/delete data-change monitored items N× ⇒ `monitored_items` + `subscription_to_session` return to baseline; (b) abandoned browse/query continuation points are TTL-evicted without session close; (c) dropping a suspended `Engine` aborts its task.
- [ ] T016 [US4] Centralize subscription removal on `SubscriptionCache` in `async-opcua-server/src/subscriptions/mod.rs`: remove **all-attribute** `monitored_items` handles + `subscription_to_session` on `delete_subscriptions` (not just `EventNotifier`). (depends on T015)
- [ ] T017 [US4] Clean the outer indexes on the expiry path: have `SessionSubscriptions::tick()` in `async-opcua-server/src/subscriptions/session_subscriptions.rs` return removed subscription IDs/refs so the cache holder cleans `monitored_items`/`subscription_to_session`. (depends on T016)
- [ ] T018 [US4] Convert the browse/query continuation `HashMap`s in `async-opcua-server/src/session/instance.rs` to the moka TTL/LRU pattern (mirror `history/continuation.rs`); stop treating `0` as unlimited. (depends on T015)
- [ ] T019 [US4] `impl Drop for Engine` in `async-opcua-server/src/programs/engine.rs`: cancel the token / abort the handle and wake `suspend_notify` so a suspended task observes cancellation. (depends on T015)
- [ ] T020 [US4] Run the gate; verify T015 passes; **commit US4** (`fix(011 US4): eliminate long-uptime growth (index cleanup, continuation TTL, Engine Drop)`).

**Checkpoint**: US1–US4 independently functional.

---

## Phase 7: User Story 5 — Config & defense-in-depth (Priority: P3)

**Goal**: close config footguns + latent allocs; ship safe defaults/profiles.
**Independent Test**: both-zero rejected; `read_bytes` bounded; no pre-alloc-before-validate; profiles load+start (quickstart US5).

- [ ] T021 [P] [US5] Add failing tests: both-zero `max_chunk_count`+`max_message_size` rejected at config validation; `read_bytes` enforces `max_message_size`; `ByteString` does not pre-allocate before stream-length confirmed; the three profiles parse and start a server.
- [ ] T022 [US5] Reject (or hard-ceiling) `max_chunk_count == 0 && max_message_size == 0` in config validation / `effective_max_chunk_count` (`async-opcua-server/src/transport/tcp.rs` + `config/limits.rs`).
- [ ] T023 [P] [US5] Bound `MessageHeader::read_bytes` against `max_message_size` in `async-opcua-core/src/comms/tcp_types.rs` (or remove it if confirmed zero external callers; note in release notes).
- [ ] T024 [P] [US5] Allocate-after-validate in `async-opcua-types/src/byte_string.rs` `decode` (and the UADP buffer path) — read incrementally / `take`-limited, no `vec![0u8; len]` before the stream is confirmed.
- [ ] T025 [US5] Give `max_notifications_per_publish` a bounded non-zero default in `async-opcua-server/src/config/limits.rs`; update `samples/server.conf` accordingly; ensure `deploy-profiles.md` profiles (micro/gateway/server) are referenced from docs.
- [ ] T026 [US5] Run the gate; verify T021 passes; **commit US5** (`fix(011 US5): config + defense-in-depth hardening; bounded defaults & profiles`).

**Checkpoint**: all stories independently functional.

---

## Phase 8: Polish & Cross-Cutting

- [ ] T027 [P] Update `docs/setup.md` embedded section + release notes for the behavior changes (bounded `max_notifications_per_publish` default, both-zero rejection, `read_bytes`).
- [ ] T028 Record the US2 activation finding in the private upstream-disclosure note for Einar (do NOT open an upstream PR for it yet).
- [ ] T029 Run full `quickstart.md` validation + final gate (fmt/clippy/`--workspace`/98-test integration/`verify-clean-codegen`); confirm wire byte-identity preserved.
- [ ] T030 [P] Run the decode fuzz targets (`cargo +nightly fuzz run fuzz_deserialize` and the other decode targets) and confirm zero process aborts across the malformed/oversized/deeply-nested corpus — owns SC-003's fuzz criterion; validates US3 + US5 decode hardening.

---

## Dependencies & Execution Order

- **Setup (T001)** → no deps.
- **Foundational** → none.
- **Stories**: US1, US2, US3, US4, US5 are mutually independent (different files/crates) and may run in priority order **or** in parallel. Within a story: test (fails) → implementation → gate & commit.
- Intra-story deps noted inline (e.g. T004 depends T003; T011/T012 depend T009; T016→T017).
- **Polish (T027–T029)** → after the stories it documents/validates.

### Parallel opportunities

- Across stories: US1–US5 can be staffed in parallel after Setup.
- Within US3: T010 (tests) and T013 (custom_struct, different file) ∥ the T009→T011/T012 chain.
- Within US4: T015 (tests) then T018 ∥ T019 (different files) after the T016→T017 index chain.
- Within US5: T023, T024 ∥ T022/T025.

## Implementation Strategy

**MVP = US1** (the HIGH-severity history DoS). Then incremental: US2 (auth) → US3 (decode bounds) →
US4 (long-uptime) → US5 (config). Each story is a standalone, independently-testable, single-commit
increment; stop at any checkpoint to validate.

## Notes

- One task per codex dispatch; verify the regression test fails before implementing, passes after.
- One commit per user story (the closing `gate & commit` task), per project memory.
- No generated-code edits; `verify-clean-codegen` must stay green.
- u32 ID-wraparound is deferred (spec Assumptions) — intentionally NOT in this task list.
