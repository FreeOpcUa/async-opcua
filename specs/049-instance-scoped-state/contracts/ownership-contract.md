# Ownership Contract: Instance-Scoped Server State

Authoritative mapping of each relocated static to its new owner + accessor, and the leave-global list.

## Relocation table (static → owner field → threading)

| # | Removed static (file) | New `ServerInfo` field | Key | Reached via | Priority |
|---|-----------------------|------------------------|-----|-------------|----------|
| 1 | `CLEANUP_REGISTRY` (`fota/cleanup.rs`) | `fota_cleanup: RwLock<HashMap<NodeId, Vec<CleanupResource>>>` | session NodeId | `ctx.info` / `SessionManager.self.info` | **P1 correctness** |
| 2 | `LOCALIZED_TEXT_ATTRIBUTE_VALUES` (`address_space/utils.rs`) | `localized_text_variants: DashMap<(NodeId, AttributeId), Vec<LocalizedText>>` | (NodeId, AttributeId) | `ctx.info` | **P1 correctness** |
| 3a | `NEXT_SESSION_ID` (`session/manager.rs`) | `next_session_id: AtomicU32` | — | `SessionManager.self.info` | P2 hygiene |
| 3b | `SESSION_LOCALE_IDS` (`session/manager.rs`) | `session_locale_ids: DashMap<u32, Vec<UAString>>` | numeric session id | `ctx.info` / `SessionManager.self.info` | P2 hygiene |

Items 1 & 2 are NodeId-keyed → genuinely collide across servers. Items 3a/3b move **together** (R2).

## Behavioral guarantees (→ Success Criteria)

- **SC-001**: two servers sharing a NodeId have isolated `fota_cleanup` and `localized_text_variants`
  (register/remember on A invisible to B; clear on A does not affect B).
- **SC-002**: two servers allocate session ids from independent `next_session_id`s and keep isolated
  `session_locale_ids`; teardown on A does not affect B.
- **SC-003**: single-server behavior + full existing server suite unchanged.
- **SC-004**: `clippy await_holding_lock`/`await_holding_refcell_ref` stay clean; no new hot-path lock.
- **SC-005**: every leave-global static carries a documented rationale.

## Leave-global list (documented, unchanged — FR-007)

| Static | File | Rationale (added as a comment) |
|--------|------|--------------------------------|
| `SERIALIZATION_METRICS` | `core/comms/tcp_codec.rs` | public API; per-instance metrics is a separate breaking observability decision |
| `TRACE_LOCKS_STATE` | `core/lib.rs` | process-wide `OPCUA_TRACE_LOCKS` config cache |
| `ENV_LOCK` | `core/lib.rs` | serializes process env mutation |
| `TEMP_FILE_COUNTER` | `server/gds/cache.rs` | global uniqueness of temp file names is desirable |
| secure-channel scratch | `core/comms/secure_channel.rs` | `thread_local!` per-thread scratch, not shared |
| `COUNTING_ALLOCATOR` | `server/subscriptions/subscription.rs` | `thread_local!` |
| regex caches | `core/logging/redact.rs`, `nodes/xml.rs` | immutable init-once, no per-server data |
| client `NEXT_SESSION_ID` | `client/session/mod.rs` | client-side; out of this server-only feature |

## Verification commands

```bash
# per-relocation isolation tests + full server suite (no single-server regression)
cargo test -p async-opcua-server

# await-holding lints stay clean (no new lock across await)
cargo clippy --workspace --all-features --lib -- -W clippy::await_holding_lock -W clippy::await_holding_refcell_ref

# default build unchanged
cargo build -p async-opcua

# lint
cargo clippy -p async-opcua-server --all-targets -- -D warnings
```

## Non-goals

- Relocating `SERIALIZATION_METRICS` or any leave-global static (beyond docs).
- Any request-concurrency / throughput change.
- Client-side state.
