# Implementation Plan: Instance-Scoped Server State

**Branch**: `049-instance-scoped-state` | **Date**: 2026-07-01 | **Spec**: [spec.md](./spec.md)
**Input**: Feature specification from `/specs/049-instance-scoped-state/spec.md`

## Summary

Relocate three process-global mutable `static`s in `async-opcua-server` onto a single per-server owner —
**`ServerInfo`** — which is already threaded to every call site via `RequestContext.info` and held by
`SessionManager` (`self.info`). The FOTA cleanup registry and the localized-text variant side-table are
NodeId-keyed and genuinely collide across servers (P1 correctness); the session-id counter + per-session
locale map are hygiene (P2). The free functions that read the globals gain a `&ServerInfo` (or use their
existing `RequestContext`) instead. Deliberately-global statics get a documented rationale and stay put.
No request-concurrency change; no new hot-path lock.

## Technical Context

**Language/Version**: Rust 1.75+ workspace
**Primary Dependencies**: existing — `dashmap` (already used), `opcua_core::sync::RwLock`/parking_lot,
`arc-swap`. No new dependency.
**Storage**: in-memory per-server maps on `ServerInfo`.
**Testing**: `cargo test -p async-opcua-server` (all binaries) + a new two-instance isolation test per
relocated item; `clippy await_holding_lock`/`await_holding_refcell_ref` stays clean.
**Target Platform**: Linux CI + dev
**Project Type**: Rust workspace OPC UA server library
**Performance Goals**: neutral — same map/lock/atomic per access, just instance-owned instead of a
`OnceLock` global; no hot-path change.
**Constraints**: single-server behavior byte-for-byte unchanged; preserve session-locale (Part 4 §5.4)
and FOTA cleanup semantics incl. the 3 teardown paths; no guard held across `.await`; no new global.
**Scale/Scope**: 3 relocation targets, one owner (`ServerInfo`), ~4 files touched
(`info.rs`, `fota/cleanup.rs`, `address_space/utils.rs`, `session/manager.rs`) + tests.

## OPC UA Standard Grounding

Behavior-preserving refactor — the exposed semantics are unchanged:
- **Part 4 §5.4** (locale handling): the per-session locale map and the written-LocalizedText side-table
  feed DisplayName/Description/InverseName locale negotiation; behavior must be identical per server.
- **Part 12 / GDS (FOTA)**: session-file cleanup resources are per-session; relocation must preserve
  register/cleanup semantics on session teardown.
No wire format, decode, or crypto is touched.

## Constitution Check

*GATE: pass before Phase 0; re-check after Phase 1.*

- **I. Correctness Over Completion**: PASS. Fixes a real cross-server collision (FOTA + localized-text
  NodeId-keyed maps); "done" requires two-instance isolation tests (red-first) + unchanged single-server
  suite.
- **II. Do It Right Once**: PASS. One owner (`ServerInfo`) for all three, not scattered per-subsystem
  globals-turned-fields; frees the maps from the `OnceLock` global-init idiom cleanly.
- **III. Individual Task Discipline**: PASS. One relocation per task (FOTA registry, localized-text
  side-table, session counter+locale map), each with its own isolation test; plus a docs task.
- **IV. Security Is Paramount**: PASS. No decode/crypto/network change. Removing process-global shared
  maps mildly *improves* isolation between co-hosted servers (no cross-instance data bleed). No new
  guard across `.await`; access patterns (map lock scope) unchanged.
- **V. Leave It Better Than You Found It**: PASS. Documents the deliberately-global statics so they are
  not re-flagged; removes global coupling; adds the missing multi-instance isolation tests.

**Result: PASS.** Complexity Tracking empty.

## Project Structure

### Documentation (this feature)

```text
specs/049-instance-scoped-state/
├── spec.md · plan.md · research.md · data-model.md · quickstart.md
├── contracts/ownership-contract.md   # each static → owner field → accessor threading
├── checklists/requirements.md
└── tasks.md
```

### Source Code (repository root)

```text
async-opcua-server/src/
├── info.rs                     # ServerInfo gains: fota_cleanup, localized_text_variants,
│                               #   session_locale_ids maps + next_session_id counter (+ accessors)
├── fota/cleanup.rs             # register_*/cleanup_session take &ServerInfo instead of the global
├── address_space/utils.rs      # remember_/locale_ids_for_session read the map off ctx.info
├── session/manager.rs          # NEXT_SESSION_ID/SESSION_LOCALE_IDS → self.info fields; teardown
│                               #   paths call cleanup via info
└── (server.rs)                 # ServerInfo construction initializes the new fields
```

**Structure Decision**: `ServerInfo` is the per-server shared-state container already carried by
`Arc<ServerInfo>` in `RequestContext` and owned by `SessionManager`. Putting all four relocated pieces
there means every existing call site can reach them with the context it already has — no new parameter
plumbing beyond swapping a global read for `info.<field>`. (Semantically the localized-text table is
address-space-ish and FOTA cleanup is subsystem-ish, but neither has a single instance threaded to all
call sites the way `ServerInfo` does; a single owner is the least-plumbing, lowest-risk choice.)

## Phase 0 Research Summary

See [research.md](./research.md). Key decisions:

- **R1 — owner = `ServerInfo`** for all three maps + the session-id counter. Reachable via
  `RequestContext.info` (read/write/util paths) and `SessionManager.info` (lifecycle). Rejected: split
  ownership across address-space / FOTA-subsystem / SessionManager (more plumbing, three test surfaces).
- **R2 — counter + locale map move together** (FR-003): the global `NEXT_SESSION_ID` is what makes
  numeric session ids unique across servers today; per-server ids stay unique *within* a server, and the
  locale map keyed by them stays correct because both live on the same `ServerInfo`.
- **R3 — map primitives unchanged**: keep `DashMap` (locale map, localized-text table) and
  `RwLock<HashMap>` (FOTA) as instance fields — same concurrency characteristics, just not `static`. No
  new lock, no `.await` under a guard.
- **R4 — thread via existing context**: free functions gain a `&ServerInfo` param (or read `ctx.info`);
  no public-API redesign except `ServerInfo` construction and any public FOTA entry point that must now
  carry the owner.
- **R5 — leave & document**: `SERIALIZATION_METRICS` (pub, breaking), `TRACE_LOCKS_STATE`/`ENV_LOCK`
  (process config), `TEMP_FILE_COUNTER` (global uniqueness desirable), thread-local scratch, regex
  caches — each gets a one-line rationale comment.

## Phase 1 Design Summary

- [data-model.md](./data-model.md): the four new `ServerInfo` fields, their key/value types, invariants,
  and the accessor surface; the mapping from each removed `static` to its new home.
- [contracts/ownership-contract.md](./contracts/ownership-contract.md): the authoritative
  static→owner→accessor table, the "leave global" list with rationales, and the verification commands.
- [quickstart.md](./quickstart.md): the two-instance isolation test pattern + the single-server
  no-regression check.

**Post-Design Constitution Re-check: PASS** — additive fields on an existing shared-state struct, no
behavior change, no new global, await-holding lints stay clean.

## Complexity Tracking

| Violation | Why Needed | Simpler Alternative Rejected Because |
|-----------|------------|-------------------------------------|
| None | N/A | N/A |
