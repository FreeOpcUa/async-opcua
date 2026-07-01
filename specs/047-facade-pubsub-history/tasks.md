# Tasks: Facade Exposure of PubSub and SQLite History

**Feature**: `047-facade-pubsub-history` | **Spec**: [spec.md](./spec.md) | **Plan**: [plan.md](./plan.md)
**Contract**: [contracts/facade-contract.md](./contracts/facade-contract.md)

> Packaging-only feature. All edits are in the `async-opcua` umbrella crate (`Cargo.toml`, `src/lib.rs`,
> docs). No member crate is modified. US1 and US2 edit the **same** `Cargo.toml` and `lib.rs`, so they
> are sequential (no cross-story `[P]`). Each task is independently verifiable (Constitution III).

## Phase 1: Setup

- [x] T001 Capture the baseline default-build footprint: run `cargo tree -p async-opcua -e no-dev | grep -iE 'pubsub|history|sqlite|lapin|rumqtt|amqp|mqtt|tungstenite'` and confirm it prints nothing (records the pre-change invariant that must still hold after the feature). No file change.

## Phase 2: Foundational

_No shared blocking prerequisite: the PubSub and history wiring are independent and are handled within their own story phases. The self-referential dev-dependency feature list and the two standalone dev-dep removals are done per-subsystem in US1/US2 to keep each story independently testable._

## Phase 3: User Story 1 — Use PubSub Through the Umbrella Crate (P1)

**Standard grounding — OPC 10000-14 (PubSub)**: exposing the PubSub subsystem makes the Part 14
Publisher/Subscriber surface reachable through the facade — §6.1 (PubSub component overview), §3.1.4
(DataSetReader), §5.4.2 (Message reception / Subscriber decode + dispatch), §7.2.4 (UADP NetworkMessage
layout), §9.1.8.2 (DataSetReaderType information model). The re-exported crate already implements these;
these tasks change only reachability, not conformance.

**Goal**: A consumer can enable `pubsub` on `async-opcua` and reach the full PubSub API via `opcua::pubsub`, with no direct sub-crate dependency.

**Independent test**: `cargo build -p async-opcua --features pubsub` compiles; `use opcua::pubsub::PubSubConfigManager;` resolves; the umbrella's `tests/integration/{pubsub,fx_spike}.rs` pass; default-build footprint grep still empty.

- [x] T002 [US1] In `async-opcua/Cargo.toml`, add `async-opcua-pubsub = { path = "../async-opcua-pubsub", version = "0.19.0", optional = true }` to `[dependencies]`, and add `pubsub = ["dep:async-opcua-pubsub"]` to `[features]`. Do NOT add `pubsub` to `default`.
- [x] T003 [US1] In `async-opcua/src/lib.rs`, add the gated re-export (place with the other `pub use` re-exports, alphabetically consistent): `#[cfg(feature = "pubsub")]` / `#[doc(inline)]` / `pub use opcua_pubsub as pubsub;`.
- [x] T004 [US1] In `async-opcua/Cargo.toml`, forward legacy policies: add `"async-opcua-pubsub?/legacy-crypto"` to the existing `legacy-crypto` feature array. (Do NOT add `aws-lc-rs`/`ecc` arms — those features don't exist on the sub-crate; they arrive via crypto-crate unification per research R2.) _Standard: OPC 10000-14 §5.3 (PubSub message security / security keys) + OPC 10000-7 legacy SecurityPolicy profiles (Basic128Rsa15, Basic256) — the `legacy-crypto` feature governs which deprecated policies the exposed subsystem may use; keeping the fail-closed default (policies off unless opted in) satisfies Constitution IV._
- [x] T005 [US1] In `async-opcua/Cargo.toml`, append `"pubsub"` to the self-referential `[dev-dependencies] async-opcua = { path = ".", features = [...] }` list, and remove the standalone `async-opcua-pubsub` line from `[dev-dependencies]`. Confirm `tests/integration/pubsub.rs` and `tests/integration/fx_spike.rs` still compile with their existing `use opcua_pubsub::…` imports; if the extern name is not visible to the test target, switch those two files to `opcua::pubsub::…` (research R3 fallback).
- [x] T006 [US1] Verify US1: `cargo build -p async-opcua --features pubsub`; `cargo test -p async-opcua` (pubsub + fx_spike integration tests green); re-run the T001 footprint grep on a default build and confirm still empty.

## Phase 4: User Story 2 — Use SQLite Historical Storage Through the Umbrella Crate (P2)

**Standard grounding — OPC 10000-11 (Historical Access)**: exposing the SQLite backend makes a storage
implementation of the Part 11 history surface reachable through the facade — §6.5 (HistoryRead details:
Raw/Modified/Processed/AtTime/Annotation) and §6.9 (HistoryUpdate details: UpdateData/UpdateStructureData/
DeleteRaw/DeleteAtTime/UpdateEvent), served via the Part 4 History Service Set (HistoryRead/HistoryUpdate).
`SqliteHistoryBackend` already implements this contract (feature 032); these tasks change only
reachability, not conformance.

**Goal**: A consumer can enable `history` on `async-opcua` and reach `SqliteHistoryBackend` via `opcua::history`, with no direct sub-crate dependency.

**Independent test**: `cargo build -p async-opcua --features history` compiles; `use opcua::history::SqliteHistoryBackend;` resolves; the umbrella's `tests/integration/hda.rs` passes; default-build footprint grep still empty.

- [x] T007 [US2] In `async-opcua/Cargo.toml`, add `async-opcua-history-sqlite = { path = "../async-opcua-history-sqlite", version = "0.19.0", optional = true }` to `[dependencies]`, and add `history = ["dep:async-opcua-history-sqlite"]` to `[features]`. Do NOT add `history` to `default`. (No feature-forwarding arm — the sub-crate defines no features.)
- [x] T008 [US2] In `async-opcua/src/lib.rs`, add the gated re-export: `#[cfg(feature = "history")]` / `#[doc(inline)]` / `pub use opcua_history_sqlite as history;`.
- [x] T009 [US2] In `async-opcua/Cargo.toml`, append `"history"` to the self-referential `[dev-dependencies] async-opcua` feature list, and remove the standalone `async-opcua-history-sqlite` line from `[dev-dependencies]`. Confirm `tests/integration/hda.rs` still compiles with `use opcua_history_sqlite::…`; fallback to `opcua::history::…` if needed (research R3).
- [x] T010 [US2] Verify US2: `cargo build -p async-opcua --features history`; `cargo test -p async-opcua` (hda integration test green); re-run the footprint grep on a default build and confirm still empty.

## Phase 5: User Story 3 — Footprint and Existing Builds Are Unaffected (P3)

**Goal**: Prove the opt-in features neither enlarge the default footprint nor break any existing feature combination or the test suite.

**Independent test**: the full verification matrix in `quickstart.md` / `contracts/facade-contract.md` all succeeds; footprint grep empty.

- [x] T011 [US3] Footprint invariant (SC-003): `cargo tree -p async-opcua -e no-dev | grep -iE 'pubsub|history|sqlite|lapin|rumqtt|amqp|mqtt|tungstenite'` prints nothing on a default build.
- [x] T012 [US3] Compatibility + crypto-default matrix (SC-004, SC-005): `cargo build -p async-opcua --features pubsub,history`; `cargo build -p async-opcua --no-default-features --features pubsub,aws-lc-rs`; `cargo build -p async-opcua --no-default-features --features history,aws-lc-rs`; `cargo build -p async-opcua --all-features`. All succeed.
- [x] T013 [US3] Regression (SC-004): `cargo test -p async-opcua` full suite green (all previously-supported combos + the three subsystem integration tests).

## Phase 6: Polish & Cross-Cutting

- [x] T014 [P] Docs (FR-009): document the `pubsub` and `history` opt-in features and the `opcua::pubsub` / `opcua::history` paths in the umbrella crate's feature docs — the `README`/`lib.rs` crate docs feature list and the feature-040 minimal-footprint / setup guidance under `docs/`.
- [x] T015 [P] Lint: `cargo clippy -p async-opcua --all-targets --features pubsub,history -- -D warnings`; also run the no-default-features clippy leg per the fork-CI note (`cargo clippy --no-default-features -p async-opcua --all-targets`).
- [x] T016 Update `specs/complexity-cuts-backlog.md` "native" entry (already corrected to reference this feature) and the session handoff to reflect 047 delivered; confirm no debris (Constitution V).

## OPC UA Standard Grounding (per-task)

Grounding an **exposure/packaging** feature: a task is grounded in the standard of the *capability it
makes reachable through the facade*, not in a wire-format clause it implements (it implements none).
Tasks that are pure Cargo/build mechanics are honestly labelled **N/A — no normative clause**; asserting
a Part/§ on them would be a false citation (worse than none, per the grounding discipline).

| Task | Standard basis | Clause(s) |
|------|----------------|-----------|
Column **Kind**: **E** = implementation/editing task (touches a file — the engineer should open the
cited clause); **V** = verification/tooling task (runs a command, no file edit — grounding shown for
context only). Every **E** task has a directly-referenceable clause; section links are in the Reference
Index below.

| Task | Kind | Files edited | Standard basis | Directly-referenceable clause(s) |
|------|------|--------------|----------------|----------------------------------|
| T001 | V | — | footprint baseline (Cargo tooling) | — |
| T002 | E | `async-opcua/Cargo.toml` | OPC 10000-14 — exposes the Subscriber reception path + its config object | **14 §5.4.2** (Message reception), **14 §9.1.8.2** (DataSetReaderType) |
| T003 | E | `async-opcua/src/lib.rs` | OPC 10000-14 — re-export of the whole PubSub surface | **14 §1** (Scope), **14 §5.1** (General → mappings/model), **14 §9** (PubSub info model) |
| T004 | E | `async-opcua/Cargo.toml` | OPC 10000-14 PubSub security + OPC 10000-7 legacy policy profiles | **14 §5.3** (Security), **14 §8.3.2** (GetSecurityKeys), **7** (Basic128Rsa15/Basic256) |
| T005 | E | `async-opcua/Cargo.toml`, `tests/integration/{pubsub,fx_spike}.rs` | OPC 10000-14 — tests exercise reception + config Methods | **14 §5.4.2** (reception), **14 §9.1.6.9** (ReaderGroupType), **14 §9.1.4.3.2** (config Method example) |
| T006 | V | — | verifies US1 exposed surface builds/tests | (14 §5.4.2) |
| T007 | E | `async-opcua/Cargo.toml` | OPC 10000-11 backend serving the Part 4 History Service Set | **4 §5.11.5** (HistoryUpdate service), **11 §6.5** (read details), **11 §6.9** (update details) |
| T008 | E | `async-opcua/src/lib.rs` | OPC 10000-11 — re-export of the history-backend surface | **11 §6.5.1** (HistoryRead overview), **11 §6.9.1** (HistoryUpdate overview) |
| T009 | E | `async-opcua/Cargo.toml`, `tests/integration/hda.rs` | OPC 10000-11 — test reads/writes stored history | **11 §6.5.3.2** (Read raw), **11 §6.9.3** (UpdateStructureData) |
| T010 | V | — | verifies US2 exposed surface builds/tests | (11 §6.5 / §6.9) |
| T011 | V | — | footprint invariant (Cargo tooling) | — |
| T012 | V | — | feature-combination/crypto-default matrix; crypto default ties to OPC 10000-7 fail-closed (Constitution IV) | (7 profiles) |
| T013 | V | — | regression umbrella for US1/US2 | (14 §6.1; 11 §6.5/§6.9) |
| T014 | E | `README` / crate docs / `docs/` | OPC 10000-14 + OPC 10000-11 overviews — docs describe exactly these capabilities | **14 §1** (Scope), **14 §6.1** (Overview), **11 §6.5.1**, **11 §6.9.1** |
| T015 | V | — | clippy/lint (build tooling) | — |
| T016 | E | `specs/*.md` (backlog/handoff) | Internal project tracking — no OPC UA clause (bookkeeping, not a spec-describing edit) | — |

**Every E (editing) task except T016 carries a directly-referenceable OPC UA clause.** T016 is
internal backlog/handoff bookkeeping — it describes *this project's* status, not OPC UA behavior, so a
spec citation would be artificial; it is flagged as such rather than given a false reference.

### Reference Index (direct links for the engineer)

OPC 10000-14 (PubSub):
- §1 Scope — https://reference.opcfoundation.org/specs/OPC-10000-14/1.md
- §5.1 General — https://reference.opcfoundation.org/specs/OPC-10000-14/5.1.md
- §5.3 Security — https://reference.opcfoundation.org/specs/OPC-10000-14/5.3.md
- §5.4.2 Message reception (Subscriber decode/dispatch) — https://reference.opcfoundation.org/specs/OPC-10000-14/5.4.2.md
- §6.1 Overview — https://reference.opcfoundation.org/specs/OPC-10000-14/6.1.md
- §8.3.2 GetSecurityKeys — https://reference.opcfoundation.org/specs/OPC-10000-14/8.3.2.md
- §9 PubSub configuration Information Model — https://reference.opcfoundation.org/specs/OPC-10000-14/9.1.1.md
- §9.1.6.9 ReaderGroupType — https://reference.opcfoundation.org/specs/OPC-10000-14/9.1.6.9.md
- §9.1.8.2 DataSetReaderType — https://reference.opcfoundation.org/specs/OPC-10000-14/9.1.8.2.md

OPC 10000-11 (Historical Access):
- §6.5.1 HistoryRead overview — https://reference.opcfoundation.org/specs/OPC-10000-11/6.5.1.md
- §6.5.3.2 Read raw functionality — https://reference.opcfoundation.org/specs/OPC-10000-11/6.5.3.2.md
- §6.9.1 HistoryUpdate overview — https://reference.opcfoundation.org/specs/OPC-10000-11/6.9.1.md
- §6.9.3 UpdateStructureData — https://reference.opcfoundation.org/specs/OPC-10000-11/6.9.3.1.md

OPC 10000-4 (Services):
- §5.11.5 HistoryUpdate service — https://reference.opcfoundation.org/specs/OPC-10000-4/5.11.5.md

**Summary**: All 8 implementation/editing tasks that touch OPC-UA-relevant files (T002–T005, T007–T009,
T014) carry a directly-referenceable clause from Parts 14, 11, 4, or 7 (verified live against the OPC UA
reference MCP). The only editing task without a clause is T016 (internal backlog bookkeeping). No task
implements or alters wire-format, decode, or crypto behavior — the exposed subsystems already conform
(features 037/026 for PubSub, 032 for history); grounding therefore points at the surface each task
makes reachable so the engineer can consult the exact normative section directly.

## Dependencies & Execution Order

- **T001** (baseline) first.
- **US1 (T002–T006)** then **US2 (T007–T010)** — sequential because both edit `async-opcua/Cargo.toml` and `async-opcua/src/lib.rs`. US1 is the MVP.
- **US3 (T011–T013)** after US1+US2 (validates the combined result).
- **Polish (T014–T016)** last; T014 and T015 are `[P]` (different files: docs vs. lint invocation).

## Implementation Strategy

- **MVP = US1** (PubSub facade exposure) — independently shippable and testable on its own.
- Incrementally add US2 (history), then run US3 as the combined guardrail.
- One task at a time; each build/test command in a task must pass before the next task (Constitution I/III).

## Parallel Opportunities

- Minimal by nature: US1 and US2 mutate the same two files, so they cannot be parallelized.
- Only T014 (docs) and T015 (clippy invocation) are `[P]` relative to each other.
