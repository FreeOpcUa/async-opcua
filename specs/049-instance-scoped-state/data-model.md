# Phase 1 Data Model: Instance-Scoped Server State

The "data" is state ownership. Below: the new `ServerInfo` fields and the static→field mapping.

## Entity: ServerInfo (extended)

New per-server fields (names indicative; `pub(crate)` accessors):

| Field | Type | Replaces (removed static) | Key | Notes |
|-------|------|---------------------------|-----|-------|
| `next_session_id` | `AtomicU32` | `session/manager.rs NEXT_SESSION_ID` | — | per-server session-id allocator (starts at 1) |
| `session_locale_ids` | `DashMap<u32, Vec<UAString>>` | `session/manager.rs SESSION_LOCALE_IDS` | numeric session id | per-session locale ids; cleared on close/expiry/terminate |
| `localized_text_variants` | `DashMap<(NodeId, AttributeId), Vec<LocalizedText>>` | `address_space/utils.rs LOCALIZED_TEXT_ATTRIBUTE_VALUES` | (NodeId, AttributeId) | written LocalizedText variants for locale negotiation on Read |
| `fota_cleanup` | `RwLock<HashMap<NodeId, Vec<CleanupResource>>>` | `fota/cleanup.rs CLEANUP_REGISTRY` | session NodeId | FOTA session-file cleanup resources |

**Invariants**:
- All four are initialized empty at `ServerInfo` construction (`server.rs`).
- Two distinct `ServerInfo` instances share none of this state (SC-001/SC-002).
- `next_session_id` + `session_locale_ids` are consistent: the map is keyed by ids drawn from that same
  counter (R2).

## Entity: Accessor surface (threading)

| Removed free-fn/global read | New form |
|-----------------------------|----------|
| `fota::cleanup::register_session_file(session_id, …)` | takes `&ServerInfo` (or method on the FOTA owner) → `info.fota_cleanup` |
| `fota::cleanup::cleanup_session(session_id)` (called in `manager.rs` teardown) | takes `&ServerInfo`; `SessionManager` passes `&self.info` |
| `remember_localized_text_attribute_value(node, attr, val)` | takes `&ServerInfo` (from the write path's `ctx.info`) |
| `locale_ids_for_session(session_id)` | reads `ctx.info.session_locale_ids` |
| `set_session_locale_ids(id, locales)` | writes `self.info.session_locale_ids` |
| `NEXT_SESSION_ID.fetch_add(1)` | `self.info.next_session_id.fetch_add(1, Relaxed)` |

## Entity: Intentionally-Global Static (documented, unchanged)

`SERIALIZATION_METRICS`, `TRACE_LOCKS_STATE`, `ENV_LOCK`, `TEMP_FILE_COUNTER`, secure-channel
thread-local scratch, `COUNTING_ALLOCATOR`, regex caches, client `NEXT_SESSION_ID` — each carries a
one-line rationale (see contract) and is not moved.

## Cross-cutting invariants

- **Single-server unchanged**: with one server, behavior is byte-for-byte identical (FR-004/SC-003).
- **Teardown preserved**: the 3 session-teardown paths still clear locale state + run FOTA cleanup, now
  against the owning `ServerInfo` (FR-003).
- **No new lock across await**: field access uses the same short synchronous critical sections;
  await-holding lints stay clean (FR-006/SC-004).
