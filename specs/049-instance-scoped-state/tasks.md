# Tasks: Instance-Scoped Server State

**Feature**: `049-instance-scoped-state` | **Spec**: [spec.md](./spec.md) | **Plan**: [plan.md](./plan.md)
**Contract**: [contracts/ownership-contract.md](./contracts/ownership-contract.md)

> State-ownership refactor: relocate 3 process-global statics onto `ServerInfo`. Behavior-preserving
> (no wire/decode/crypto change). Each relocation = add field(s) to `ServerInfo` + init in `server.rs`
> + reroute the free-fn/global read to `info.<field>` + a two-instance isolation test (red-first per
> FR-005). US1a/US1b/US2 all edit `info.rs`, so they are sequential (no cross-story `[P]`).
> Each task is one indivisible, independently verifiable job (Constitution III).

## Phase 1: Setup

- [x] T001 Baseline: `cargo test -p async-opcua-server` green + `cargo clippy --workspace --all-features --lib -- -W clippy::await_holding_lock -W clippy::await_holding_refcell_ref` clean; record the pre-change state. No file change.

## Phase 2: User Story 1a — FOTA cleanup registry per server (P1, correctness)

**Goal**: two servers sharing a session `NodeId` never read/overwrite/evict each other's FOTA cleanup resources.
**Independent test**: two `ServerInfo`; register a cleanup resource for `NodeId` X on A; B's `cleanup_session(X)` is empty; A's still returns its resource.

- [x] T002 [US1] Red-first test (in `async-opcua-server/src/fota/cleanup.rs` tests or a server test): two `ServerInfo` instances, same session `NodeId` — register on A, assert B sees nothing and A sees its resource. (Fails: currently one global registry → B sees A's data.)
- [x] T003 [US1] Implement in `info.rs` (+ `server.rs` init): add `fota_cleanup: RwLock<HashMap<NodeId, Vec<CleanupResource>>>` to `ServerInfo`; reroute `fota/cleanup.rs` `register_session_file`/`register_session_file_path`/`cleanup_session` to operate on a passed `&ServerInfo` (remove the `CLEANUP_REGISTRY` static + `registry()`); update the `session/manager.rs` teardown callers (`:667/:809/:823`) to pass `&self.info`. Make T002 pass. _Standard: OPC 10000-12 GDS/FOTA session-file cleanup — semantics preserved._

## Phase 3: User Story 1b — Localized-text variant side-table per server (P1, correctness)

**Goal**: two servers sharing a `(NodeId, AttributeId)` keep isolated written-LocalizedText variants.
**Independent test**: two `ServerInfo`; remember a variant for `(X, DisplayName)` on A; B has none for that key; clear on A does not affect B.

- [x] T004 [US1] Red-first test (in `async-opcua-server/src/address_space/utils.rs` tests): two `ServerInfo`, same `(NodeId, AttributeId)` — remember on A, assert B has no variant; empty-locale remove on A does not touch B. (Fails: one global `DashMap`.)
- [x] T005 [US1] Implement in `info.rs` (+ `server.rs` init): add `localized_text_variants: DashMap<(NodeId, AttributeId), Vec<LocalizedText>>` to `ServerInfo`; reroute `address_space/utils.rs` `remember_localized_text_attribute_value` + `locale_ids_for_session`/`localized_text_for_session` read/write paths to use `ctx.info` (remove the `LOCALIZED_TEXT_ATTRIBUTE_VALUES` static). Preserve remember / locale-match-replace / clear-on-empty-locale behavior. Make T004 pass. _Standard: OPC 10000-4 §5.4 (locale negotiation) — behavior preserved._

## Phase 4: User Story 2 — Per-server session-id space + locale map (P2, hygiene)

**Goal**: each server allocates session ids from its own counter and keeps its own per-session locale map.
**Independent test**: two `SessionManager` (over two `ServerInfo`); each allocates ids from its own `next_session_id`; setting locales on A is invisible to B; teardown on A does not affect B.

- [ ] T006 [US2] Red-first test (in `async-opcua-server/src/session/manager.rs` tests): two `SessionManager`/`ServerInfo` — assert independent `next_session_id` allocation and isolated `session_locale_ids` (set on A ⇒ B's `locale_ids_for_session` unaffected). (Fails: shared global counter + map.)
- [ ] T007 [US2] Implement in `info.rs` (+ `server.rs` init): add `next_session_id: AtomicU32` (init 1) + `session_locale_ids: DashMap<u32, Vec<UAString>>` to `ServerInfo`; reroute `session/manager.rs` (`NEXT_SESSION_ID.fetch_add` → `self.info.next_session_id`; `set_session_locale_ids`/`clear_session_locale_ids`/`locale_ids_for_session` → `info.session_locale_ids`) and the `utils.rs:523` read (via `ctx.info`). Move the counter + map together (R2). Preserve the 3 teardown clear paths. Make T006 pass. _Standard: OPC 10000-4 §5.4 (session locale) — behavior preserved._

## Phase 5: User Story 3 — Document deliberately-global statics (P3)

- [ ] T008 [US3] Add a one-line rationale comment to each leave-global static per the contract table: `SERIALIZATION_METRICS` (`core/comms/tcp_codec.rs`), `TRACE_LOCKS_STATE`/`ENV_LOCK` (`core/lib.rs`), `TEMP_FILE_COUNTER` (`server/gds/cache.rs`), secure-channel thread-local scratch (`core/comms/secure_channel.rs`), `COUNTING_ALLOCATOR` (`server/subscriptions/subscription.rs`), regex caches (`core/logging/redact.rs`, `nodes/xml.rs`), client `NEXT_SESSION_ID` (`client/session/mod.rs`). No behavior change.

## Phase 6: Polish & Cross-Cutting

- [ ] T009 Full verification: `cargo test -p async-opcua-server` (ALL binaries — single-server no-regression, SC-003) + the isolation tests green; `cargo build -p async-opcua` default features unchanged (SC-003).
- [ ] T010 [P] Lints: `cargo clippy --workspace --all-features --lib -- -W clippy::await_holding_lock -W clippy::await_holding_refcell_ref` clean (SC-004); `cargo clippy -p async-opcua-server --all-targets -- -D warnings`; **`cargo fmt --all`** (verify-clean-codegen gate — run before pushing).
- [ ] T011 [P] Update `specs/SESSION-HANDOFF.md` (record 049) and the `async-lock-discipline` memory note (global-static finding resolved).

## Dependencies & Execution Order

- **T001** first.
- **US1a (T002→T003)**, **US1b (T004→T005)**, **US2 (T006→T007)** — all add fields to `info.rs` and init in `server.rs`, so they are **sequential** (do in order). Each is independently testable once done.
- **US3 (T008)** is independent (different statics) — can go anytime after T001.
- **Polish (T009–T011)** after all stories; T010/T011 are `[P]` (lint vs docs).
- Within each story: the red test precedes its implementation.

## Implementation Strategy

- **MVP = US1a + US1b** (the two P1 correctness fixes — the actual cross-server collisions). US2 is P2 hygiene.
- One task at a time; each red test must fail before its impl and pass after (Constitution I/III).
- Behavior-preserving: the single-server suite (T009) is the primary guard that nothing regressed.

## Parallel Opportunities

- Minimal: US1a/US1b/US2 share `info.rs`+`server.rs` → sequential.
- **T008** (docs on leave-global statics) is `[P]` relative to the relocations (different files).
- **T010**/**T011** (lint vs docs) are `[P]`.
