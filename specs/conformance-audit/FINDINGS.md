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

| P4-ATTR-05 | 4 §5.11.3.2 | `session/services/attribute.rs` history_read entry | HistoryRead does NOT validate `timestampsToReturn`. Spec: NEITHER "is not valid… shall return `Bad_TimestampsToReturnInvalid`" (OPC 10000-11 defines exceptions where it's ignored). The Read path validates `Invalid`; HistoryRead validates nothing and passes through to node managers. | S2 | S | open |
| P4-VIEW-01 | 4 §5.9.2 Table 36 | `node_manager/view.rs:291` `allows_reference_type` | Browse with a non-null `referenceTypeId` that is not a ReferenceType returns `false` → result is empty + `Good`, instead of operation-level `Bad_ReferenceTypeIdInvalid`. Silently hides a client error. | S2 | S | open |
| P4-SESS-01 | 4 §5.7.5 (Cancel) | `session/message_handler.rs` catch-all (no Cancel arm); `controller.rs` | Cancel service is unimplemented → falls through to `BadServiceUnsupported`. `docs/compatibility.md` **claims Cancel is supported** (doc drift). Conformant minimal behaviour: return a `CancelResponse` with `cancelCount=0`. | S2 | S | open |
| P4-SESS-02 | 4 §5.7.2 (line 2417) | `session/manager.rs:250` | CreateSession checks only clientNonce *minimum* length; spec requires `Bad_NonceInvalid` if length `< 32` **or `> 128`** bytes. No upper bound enforced (bounded only by max message size). | S2 | S | open |

| P4-METHOD-01 | 4 §5.12 Table 61 | `node_manager/memory/mod.rs:573` | Call checks only `user_executable()` (+ authenticator) → `BadUserAccessDenied`; the base **`Executable`** attribute is never checked. A method with `Executable=false` but user-executable is still callable; spec requires `Bad_NotExecutable`. ✅verified | S2 | S | open |
| P4-METHOD-02 | 4 §5.12 (line 3953) | `node_manager/method.rs:100` | `output_arguments: Some(self.outputs)` returned unconditionally; spec: outputArguments shall be empty when the operation statusCode severity is Bad. ✅verified | S3 | S | open |
| P4-QUERY-01 | 4 Annex B.2.3 Table B.6 | `node_manager/query.rs:59`, `services/query/handlers.rs:153` | QueryFirst does not validate `typeDefinitionNode`; an invalid/non-TypeDefinition node is silently skipped (falls back to full traversal) instead of reporting `Bad_NodeIdInvalid`/`Bad_NodeIdUnknown`/`Bad_NotTypeDefinition` in `parsingResults`. ⚠agent-cited | S2 | M | open |
| P4-NODEMGMT-01 | 4 §5.8 Tables 24/27 | `node_manager/node_management.rs`, `memory/memory_mgr_impl.rs` | Cluster of missing AddNodes/AddReferences validations: hierarchical-ref-type constraint, `typeDefinition` node existence, `Bad_BrowseNameDuplicated`, AddReferences `targetNodeClass` match, duplicate-reference (`Bad_DuplicateReferenceNotAllowed`), `Bad_ReferenceNotAllowed`. Opt-in surface (`clients_can_modify_address_space` default OFF). ⚠agent-cited | S3 | M | open |
| P4-DISC-01 | 4 §5.5.5 Table 7 | `info.rs:209` `apply_register_server` | RegisterServer/RegisterServer2 validate only `Bad_ServerUriInvalid` + `BadTooManyOperations`; missing `Bad_ServerNameMissing`, `Bad_DiscoveryUrlMissing`, `Bad_SemaphoreFileMissing`. LDS-side registry hygiene. ⚠agent-cited | S3 | S | open |

> **Cross-cutting confirmation:** the Query audit independently re-surfaced the NumericRange lazy/lenient
> parse — `Bad_IndexRangeInvalid` deferred to read-time (same root cause as **P4-ATTR-01**). Fixing
> P4-ATTR-01 in the codec should resolve both. Also noted (S3): Query never returns `Bad_QueryTooComplex`
> (no complexity limit — mild DoS-adjacent for a public-ish service).
>
> **Audited:** Read/Write (R1–R6, W1–W9), HistoryRead/HistoryUpdate (§5.11.3/.5 — variants & CP handling
> mostly HONORED), View §5.9 (Browse/BrowseNext/Translate/Register/Unregister), SecureChannel §5.6 +
> Session §5.7 (013/014/025 already hardened most; nonce rotation, sig verify, channel binding HONORED),
> NodeManagement §5.8, Method §5.12, Query Annex B, Discovery §5.5 (mostly HONORED; GetEndpoints/
> FindServers conformant; FindServersOnNetwork = known mDNS stub).
>
> **Unverified candidates** (surfaced by audit agents, NOT yet confirmed against code — verify before
> acting): Browse `browseDirection` out-of-range masked via `from_bits_truncate` instead of
> `Bad_BrowseDirectionInvalid`; CreateSession `Bad_TooManySessions` returned immediately rather than
> closing the oldest unactivated session first (§5.7.2.1); RegisterNodes no up-front structural NodeId
> validation; TranslateBrowsePaths target ordering (type-definition node first); `remainingPathIndex`
> always MAX (external-server refs unsupported — known limitation); maxResponseMessageSize enforcement
> location unconfirmed; Anonymous-token + Sign-mode + new-channel rejection not located. **Cross-cutting
> (→ P4-GENERAL):** `diagnosticInfos` never populated even when `returnDiagnostics` is requested.

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
