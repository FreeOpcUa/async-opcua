# Phase 0 Research: Instance-Scoped Server State

Current-code findings (verified 2026-07-01) and decisions.

## Access-pattern findings

**FOTA cleanup registry** (`fota/cleanup.rs`): free fns `register_session_file` (`:46`),
`register_session_file_path` (`:65`), `cleanup_session` (`:79`) over
`static CLEANUP_REGISTRY: OnceLock<RwLock<HashMap<NodeId, Vec<CleanupResource>>>>`. Callers:
`session/manager.rs` teardown (`:667/:809/:823`) and FOTA node-manager registration. Keyed by
**session NodeId** → not globally unique → **cross-server collision (correctness)**.

**Localized-text variant side-table** (`address_space/utils.rs`): free fns
`remember_localized_text_attribute_value` (`:451`, called from write paths `:399/:678`) and
`locale_ids_for_session`/`localized_text_for_session` (read path `:517/:523`) over
`static LOCALIZED_TEXT_ATTRIBUTE_VALUES: OnceLock<DashMap<(NodeId, AttributeId), Vec<LocalizedText>>>`.
**Runtime-mutated** (entry/or_default/remove). Keyed by **(NodeId, AttributeId)** → not globally unique
→ **cross-server collision (correctness)**. (Initially mis-scoped as "leave"; the NodeId key + runtime
mutation reclassify it as a real target.)

**Session identity** (`session/manager.rs`): `static NEXT_SESSION_ID: AtomicU32` (`:41`,
`fetch_add` at `:48`) + `static SESSION_LOCALE_IDS: OnceLock<DashMap<u32, Vec<UAString>>>` (`:42`).
Set at `:1169` (SessionManager), read at `utils.rs:523` (via `context.session_id()`). No key collision
today (global counter keeps ids unique) → **hygiene/isolation, not correctness**.

**Reachability:** `SessionManager` holds `info: Arc<ServerInfo>` (`manager.rs:519`); every read/write/
util call site holds a `RequestContext` whose `.info` is `Arc<ServerInfo>`. So all four pieces are
reachable from one owner: `ServerInfo`.

## R1 — Owner = `ServerInfo`

**Decision**: put all three maps + the session-id counter on `ServerInfo` as fields, with accessors.
`ServerInfo` is the existing per-server shared-state container (already holds `ArcSwap`/`RwLock` state)
and is threaded everywhere via `RequestContext.info` and `SessionManager.info`.

**Rationale**: least plumbing (swap a `static` read for `info.<field>` at each site), single test
surface, single per-server lifetime. Do-It-Right-Once: one owner, not three subsystem-local globals.

**Alternatives rejected**: (a) address-space owns the localized-text table + FOTA subsystem owns cleanup
+ SessionManager owns session state — semantically neater but none of those is threaded to *all* the
call sites, so it needs new parameters in several signatures and three isolation-test setups; (b) keep
globals but key them by `(server_id, NodeId)` — reintroduces a global map (memory + lifecycle coupling)
and needs a server-id anyway.

## R2 — Counter + locale map move together

**Decision**: relocate `NEXT_SESSION_ID` and `SESSION_LOCALE_IDS` in the same change. Per-server
`next_session_id` keeps ids unique *within* a server; the locale map keyed by those ids stays correct.

**Rationale**: decoupling would break the invariant the global counter currently provides (globally
unique numeric ids) and could make the per-server locale map key-collide — the exact hazard we are
removing. They are one unit.

## R3 — Map primitives unchanged

**Decision**: keep the same primitives as instance fields — `DashMap` for the locale map and the
localized-text table, `RwLock<HashMap>` for FOTA cleanup. Only the storage location changes (field vs
`static OnceLock`).

**Rationale**: identical concurrency behavior; no new lock; no guard held across `.await` (the maps are
accessed in short synchronous sections, unchanged). The await-holding lints must stay clean.

## R4 — Threading

**Decision**: free functions take `&ServerInfo` (or use the `RequestContext`/`&self` they already have);
`ServerInfo` construction (`server.rs`) initializes the new fields. Session creation reads
`self.info.next_session_id`.

**Public-API note**: the only outward change is `ServerInfo`'s fields/accessors and any *public* FOTA
entry point that must now receive the owner. Prefer `pub(crate)` accessors to keep the surface internal.

## R5 — Leave & document (intentionally global)

| Static | Why it stays global |
|--------|---------------------|
| `SERIALIZATION_METRICS` (`tcp_codec.rs`, `pub`) | Public API; per-instance is a separate breaking observability decision |
| `TRACE_LOCKS_STATE`, `ENV_LOCK` (`core/lib.rs`) | Process-wide config / env-mutation serialization |
| `TEMP_FILE_COUNTER` (`gds/cache.rs`) | Global uniqueness of temp file names is desirable |
| secure-channel scratch, `COUNTING_ALLOCATOR` | Per-thread (`thread_local!`), not shared |
| regex caches (`redact.rs`, `xml.rs`) | Immutable init-once, no per-server data |
| client `NEXT_SESSION_ID` | Client-side; out of this server-only feature |

Each gets a one-line comment so a future audit does not re-flag it.

## Open items

None — no NEEDS CLARIFICATION. Owner and threading confirmed against current code.
