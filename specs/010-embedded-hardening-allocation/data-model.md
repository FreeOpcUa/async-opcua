# Data Model: Embedded Hardening & Allocation Follow-ups

This is a protocol library; the "data model" is the set of configurable limits, bounded server-side
state, reusable buffers, and shared-ownership relationships the feature introduces or tightens.

## Decoding limits (FR-002, FR-003)

- **DecodingOptions.max_message_size** *(existing)* — negotiated maximum message size.
  - New rule: enforced at frame-header read in `TcpCodec::decode` (reject `message_size > max` before buffering). `MessageHeader::decode` must consult the passed `DecodingOptions`.
- **DecodingOptions.max_decode_depth** *(new field)* — maximum structure nesting depth applied during decode.
  - Default: a safe constant (e.g. 100), documented; configurable.
  - Validation: a per-decode depth counter increments at recursive nesting points; exceeding the limit returns a decode error (no stack overflow). Independent of `max_message_size`.
  - State: transient per-decode (carried in the decode context), not persisted.

## Bounded certificate-management registries (FR-004)

- **GDS push/pull registries** — `signing_requests` (map), `created_requests` / `rejected` / `updated` / `finished` (lists).
  - New rule: each has a configurable cap (and/or TTL). On overflow: FIFO-evict oldest (configurable; reject-when-full alternative documented).
  - Cleanup: eviction on insert when at cap; TTL aging where applicable. Behavior documented (Edge Cases: cap reached).
  - Relationship: bounded the same way as the retransmission queue (cap) and history continuation points (LRU+TTL).

## Notification working buffers (FR-005)

- **DataChangeNotificationVecPool** *(existing)* — bounded free-list of `Vec<MonitoredItemNotification>`, drawn in `make_notification_message`, reclaimed at `NonAckedPublish` drop via `Arc::into_inner` + downcast, cleared on draw and reclaim.
- **EventFieldList pool** *(new, sibling)* — same shape for the `Vec<EventFieldList>` event-notification vector.
  - Invariant (CRITICAL): a reused vector MUST be empty before reuse (clear on draw and on reclaim) — no stale event may leak into a later message.
  - Reclaim: only when `Arc::into_inner` yields sole ownership (graceful drop otherwise); bounded retention.
  - Relationship: escapes into `NotificationMessage` → `Arc` → retransmission queue, reclaimed at the same drop sites as data-change.

## Receive-buffer ownership (FR-007)

- **Shared receive buffer (`Bytes`)** — the connection's decoded bytes.
  - New relationship: `ByteString` / `String` / array decode slice/`split` from the shared `Bytes` instead of copying into a fresh `Vec`, where the decode path has access to the owning `Bytes`.
  - Validation: decoded values MUST be identical to the copy path; where no `Bytes` source is available, fall back to copying (no behavior change).

## Request dispatch (FR-006)

- **Inline read fast-path** — for small single-node-manager Reads, dispatch inline (no per-request `Box`+`tokio::spawn`); otherwise the existing spawned path.
  - Constraint: request isolation preserved (a fast-path panic must not corrupt the connection task beyond dropping the request/connection cleanly).
  - State: no new persistent state; a branch in the dispatch path.

## Non-entities (explicitly unchanged)

- Wire format for well-behaved peers (byte-identical), generated types (untouched — `verify-clean-codegen` green), the security defaults (fail-closed) and secret-handling.
