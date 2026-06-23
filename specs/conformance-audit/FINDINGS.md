# Conformance audit — findings register (the fix list)

The running, ID'd list of spec-vs-impl divergences produced by the [audit units](./PLAN.md). One row
per finding; each row feeds a fix. Severity **S1** security/silent-data-loss · **S2** observable
conformance · **S3** cosmetic/dead-code/doc-drift. Status: open · fixing(feat#) · fixed(feat#) ·
deferred(reason) · verified-conformant.

| ID | Part/§ | Impl location | Divergence | Sev | Fix | Status |
|---|---|---|---|---|---|---|
| P4-SUB-01 | 4 §5.14.1.2 Table 79 rows 4/5 | `subscription.rs:400` | Normal4 guard's first disjunct is `publishing_enabled`; spec says `PublishingEnabled==FALSE`. Flips the test → `Normal5` (ReturnNotifications + ResetLifetimeCounter for enabled+more) is dead code. Masked today by the `IntervalElapsed6` timer tick. | S2 | S | **fixed** (guard → `!publishing_enabled …`; test `part4_table79_normal_publish_rows_4_5`, red-first) |
| P4-SUB-02 | 4 §5.14.7 Table 79 rows 22/23 | `mod.rs::transfer` | TransferSubscriptions never (a) issues `Good_SubscriptionTransferred` StatusChangeNotification to the OLD session, nor (b) resets the lifetime counter. (b) one-liner; (a) needs an old-session delivery mechanism for a sub it no longer holds. | S2 | L | open |
| P4-SUB-03 | 4 §5.13.1.5 | `monitored_item.rs::enqueue_notification` | On first Event discard, no `EventQueueOverflowEventType` Event is placed in the queue (front if discardOldest else end; never itself discarded). Feature missing entirely. | S2 | M | open |

| P4-ATTR-01 | 4 §5.11.2/.4 Tables 49 & 55 | `async-opcua-types/src/numeric_range.rs` (`impl_encoded_as!` / `from_ua_string`) | A malformed `indexRange` string fails **whole-message decode** → `BadDecodingError` ServiceFault for the entire Read/Write. Spec lists `Bad_IndexRangeInvalid` as an **operation-level** code (per-node DataValue.status); one bad range should fail only its own operation, not the batch. `NumericRange` is decoded eagerly and returns a decoding error on parse failure. | S2 | M | open |
| P4-ATTR-02 | 4 §5.11.2 Table 47 (maxAge) | `address_space/utils.rs`, `nodes/src/variable.rs` | `maxAge` (0=read fresh, ≥maxInt32=cached) is ignored — always returns the stored value. Conformant for the in-memory CoreNodeManager (stored value *is* the data source); only matters for a node manager backing a slow external source. | S3 | — | deferred (architecture-dependent; document) |
| P4-ATTR-03 | 4 §5.11.4 (LocalizedText write) | `address_space/utils.rs` write validation | No LocalizedText locale semantics: null-text-deletes-locale, invalid/unsupported locale → `Bad_LocaleNotSupported` not implemented (LocalizedText written as opaque value). Spec marks the deletion rules "Server specific but recommended"; the invalid-locale code is firmer. | S3 | M | deferred (low value) |
| P4-ATTR-04 | 4 §5.11.4 Table 55 (`Bad_OutOfRange`) | write validation | No enumeration/range validation on writes → `Bad_OutOfRange` never returned. Spec permits server-defined restrictions (not mandatory when none defined), so not strictly non-conformant. | S3 | — | deferred (permitted) |

> Read/Write audited (R1–R6, W1–W9 mapped; rest HONORED). **Not yet audited:** HistoryRead (§5.11.3),
> HistoryUpdate (§5.11.5) — the history path delegates to node managers; audit separately.

## Detail

### P4-SUB-01 — Normal4/Normal5 Publish guard
First disjunct `self.publishing_enabled` → `!self.publishing_enabled` so `(enabled, more)` reaches
Normal5 (row 5: `reset_lifetime_counter()` + `ReturnNotifications`). State-machine change — must
re-verify existing lifetime/keep-alive tests (`subscription.rs` ~1538-1639) and add a focused test:
enabled subscription with queued notifications returns them + resets the counter on a Publish request.

### P4-SUB-02 — TransferSubscriptions Good_SubscriptionTransferred + lifetime reset
(b) reset lifetime counter on transfer. (a) per-session list of pending "departed-subscription" status
notifications, drained on the old session's next Publish (the sub + its queued messages have already
moved to the new session). §5.14.7 body: "the Server shall issue a StatusChangeNotification …
Good_SubscriptionTransferred to the old Session." Design the mechanism before coding.

### P4-SUB-03 — EventQueueOverflowEventType
Build the `EventQueueOverflowEventType` EventFieldList per the subscription's event filter; enqueue on
first discard with correct placement; exempt it from discard. Additive, self-contained.

---

*Findings P4-SUB-01..03 carried over from feature 030's AUDIT.md (were #1/#2/D). New findings land here
as each unit is audited.*
