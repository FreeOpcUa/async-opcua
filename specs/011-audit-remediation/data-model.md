# Data Model: Audit Remediation

Entities introduced or changed. These are internal types unless marked public.

## History continuation cursor (US1) — replaces materialized remainder

Replaces `CachedContinuationPoint { values: Vec<DataValue>, created_at }`.

| Field | Type | Notes |
|-------|------|-------|
| `node_id` | NodeId | the node being read |
| `range_start` / `range_end` | timestamp (ticks) | original requested bounds |
| `chronological` | bool | scan direction |
| `last_timestamp` | timestamp (ticks) | keyset position: resume strictly after this |
| `return_bounds` | bool | whether bounding values were/are included |
| `created_at` | Instant | for TTL eviction (unchanged) |

- **Lifecycle**: created when a read returns more than `num_values_per_node`; consumed/advanced by
  `HistoryReadNext`; evicted by moka TTL/cap or on release.
- **Validation**: `last_timestamp` must lie within `[range_start, range_end]`; an expired/unknown
  token returns the standard "invalid continuation point" status (no panic).

## PubSub decode limits (US3) — extends DecodingOptions/Context

| Field | Type | Default (proposed) | Enforced in |
|-------|------|--------------------|-------------|
| `max_dataset_fields` | usize | accept conformant (e.g. 4096) | `uadp.rs` before `with_capacity(field_count)` |
| `max_dataset_messages` | usize | e.g. 256 | UADP network-message decode |
| `max_secured_payload_len` | usize | e.g. `max_message_size` | `security/codec.rs` before copy/decrypt |

- **Validation rule**: declared count/len `>` limit → decode error before allocation. `0` is NOT
  unlimited for these (fail-closed).

## Browse/Query continuation point (US4) — gains TTL/LRU

Existing per-session token; storage changes from plain `HashMap` to a bounded TTL/LRU cache
(moka), mirroring `history/continuation.rs`.

| Aspect | Before | After |
|--------|--------|-------|
| Storage | `HashMap<token, point>` | moka cache (capacity + TTL) |
| `0` config | unlimited | applies cap/TTL (no unlimited) |
| Reclaim | only on BrowseNext/QueryNext/release/session-close | + TTL eviction of abandoned points |

## Monitored-item reverse-index entry (US4) — lifecycle corrected

Global `monitored_items: Map<(node_id, attribute) → handles>` and `subscription_to_session: Map<sub_id
→ session_id>`. No schema change; the **invariant** changes: entries are now removed for **all**
attributes via one centralized path on both delete and expiry (previously only `EventNotifier` on
delete).

## Config defaults (US5)

| Field | Before | After |
|-------|--------|-------|
| `max_notifications_per_publish` (default) | `0` (unlimited) | bounded non-zero default |
| `max_chunk_count == 0 && max_message_size == 0` | resolves to `usize::MAX` | rejected / hard-ceiled at validation |

## State transitions (history read)

```
Read(range, cap) ──> rows <= cap?  ──yes──> return rows, no continuation
                          │
                          no
                          └──> return first `cap` rows + cursor(last_timestamp)
ReadNext(cursor) ──> query (range, after=last_timestamp) LIMIT cap+1
                          ├─ more ─> return page + advanced cursor
                          └─ done ─> return final page, drop cursor
```
