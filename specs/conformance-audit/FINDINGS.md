# Conformance audit — consolidated findings register (the fix list)

Merged register of spec-vs-impl divergences from the multi-AI audit: **[C]** = Claude (main audit),
**[A]** = Antigravity/Gemini (`FINDINGS-antigravity.md`), **[X]** = Codex (`FINDINGS-codex.md`). The
per-model raw files are kept alongside for provenance; this file is the deduped, source-tagged,
verification-graded fix list.

**Severity:** S1 security/silent-data-loss · S2 observable conformance · S3 cosmetic/dead-code/narrow.
**Verify:** ✅ = independently verified against spec+code by Claude · ⚠ = model-cited, NOT yet
independently verified (re-verify before fixing — verify-before-fix is mandatory). Found-by lists which
model(s) surfaced it.

| ID | Sev | Found | Verify | Part/§ | Divergence | Status |
|---|---|---|---|---|---|---|
| P4-SUB-01 | — | C | ✅ | §5.14.1.2 T79 r4/5 | Normal4/5 Publish guard flipped; Normal5 was dead | **FIXED** |
| P4-ATTR-01 | S2 | C,A | ✅ | §5.11.2/.4 T49/55 | Malformed `indexRange` → whole-message `BadDecodingError`, not per-op `Bad_IndexRangeInvalid` (NumericRange eager decode). Also hits Query/Write. *Codex missed.* | open |
| P4-ATTR-05 | S2 | C | ✅ | §5.11.3.2 | HistoryRead never validates `timestampsToReturn==NEITHER` → `Bad_TimestampsToReturnInvalid` (10000-11 exceptions). *Codex UNCERTAIN; AG missed.* | open |
| P4-VIEW-01 | S2 | C | ✅ | §5.9.2 T36 | Browse with non-ReferenceType `referenceTypeId` → empty+Good, not `Bad_ReferenceTypeIdInvalid` | open |
| P4-VIEW-02 | S3 | X | ✅ | §5.9.4.2 (3227) | TranslateBrowsePaths treats null final `targetName` as wildcard; spec: last element shall have targetName → `Bad_BrowseNameInvalid`. *Conflict resolved: Codex right, Claude agent wrong.* | open |
| P4-VIEW-03 | S3 | X | ✅ | §5.9.3.2 T37 (3133) | BrowseNext `releaseContinuationPoints=TRUE` returns one BrowseResult per CP; spec: results & diagnosticInfos arrays empty. *Conflict resolved: Codex right.* | open |
| P4-VIEW-04 | S2 | A | ✅ | §5.9.5.2 | RegisterNodes drops unregistered nodes (`into_result()→None`, `filter_map`) → response array shorter than request; spec: size/order matches `nodesToRegister`. *Conflict resolved: AG right, Codex wrong.* | open |
| P4-SESS-01 | S2 | C,A | ✅ | §5.7.5 | Cancel unimplemented → `BadServiceUnsupported`; compatibility.md claims it (doc drift). Min fix: `cancelCount=0`. *Codex UNCERTAIN.* | open |
| P4-SESS-02 | S2 | C,X | ✅ | §5.7.2 (2417) | CreateSession enforces only clientNonce min, not the `>128` max. *AG missed.* | open |
| P4-SESS-03 | S2 | X | ⚠ | §5.6.2.2 T11 | OpenSecureChannel can return `revisedLifetime==0`; spec requires >0 (`min(max,requested)` no lower bound). | open |
| P4-SESS-04 | S3 | X | ⚠ | §5.6.2.3 T12 | OSC Renew before any Issue → `BadUnexpectedError` not `BadSecureChannelIdInvalid`. | open |
| P4-SESS-05 | S2 | A | ⚠ | §5.7.2.1 | Client-cert app-URI check (`is_application_uri_valid`) only inspects the FIRST SAN → false denials / missed URI. | open |
| P4-SESS-06 | S3 | A | ⚠ | §5.7.3.1 | Request on an unactivated session returns a fault but does not close the session. | open |
| P4-SESS-07 | S3 | A | ✅ | §5.7.3.1 | Cross-channel transfer enforces client-cert match (HONORED) but NOT SecurityPolicy/SecurityMode equality (`is_cross_channel_transfer_forbidden` only special-cases None); ClientUserId is re-authed (moot). *Conflict resolved: narrowed to policy/mode equality.* | open |
| P4-SESS-08 | S2 | A | ⚠ | §5.7.3.1 | Anonymous token over a new SecureChannel using Sign mode not rejected. *Claude agent UNCERTAIN.* | open |
| P4-METHOD-01 | S2 | C,X | ✅ | §5.12 T61 | Call checks only `user_executable()` → `BadUserAccessDenied`; base `Executable` attr never checked → non-executable method still callable (should be `Bad_NotExecutable`). *AG missed.* | open |
| P4-METHOD-02 | S3 | C,A | ✅ | §5.12 (3953) | `output_arguments` returned unconditionally; spec: empty when status severity Bad. (AG framed as inputArgumentResults never populated.) | open |
| P4-QUERY-01 | S2 | C,A,X | ✅ | Annex B T B.6 | QueryFirst doesn't validate `typeDefinitionNode` → silent full-traversal vs `Bad_NodeIdInvalid`/`Bad_NotTypeDefinition` in parsingResults. *3-way agreement.* | open |
| P4-NODEMGMT-01 | S3 | C,A | ⚠ | §5.8 T24/27 | AddNodes/AddReferences validation cluster: `Bad_BrowseNameDuplicated`, typeDef existence, hierarchical-ref constraint, targetNodeClass match, duplicate-ref, user-privilege (`Bad_UserAccessDenied` vs global flag). Opt-in surface (default OFF). | open |
| P4-NODEMGMT-02 | S3 | A | ✅ | §5.8.4 | `NodeManager::delete_node_references` trait hook (cross-manager cleanup, node_management.rs:255) is an EMPTY stub in the memory manager → dangling cross-manager refs. *Conflict resolved: within-manager deletion IS honored (Codex right); only the cross-manager hook is stubbed (AG right). Narrow.* | open |
| P4-MONITEM-01 | S2 | X | ⚠ | §5.13.2.3 T64 | CreateMonitoredItems accepts `TimestampsToReturn::Invalid` (no `Bad_TimestampsToReturnInvalid`; treated as Neither). | open |
| P4-MONITEM-02 | S2 | X | ⚠ | §5.13.3.3 T67 | ModifyMonitoredItems accepts `TimestampsToReturn::Invalid`. | open |
| P4-MONITEM-03 | S2 | X | ⚠ | §5.13.4.3 T70 | SetMonitoringMode accepts an invalid MonitoringMode (no `Bad_MonitoringModeInvalid`). | open |
| P4-DISC-01 | S3 | C,X | ✅ | §5.5.5 T7 | RegisterServer/2 validate only `Bad_ServerUriInvalid`+limit; missing `Bad_ServerNameMissing`/`Bad_DiscoveryUrlMissing`/`Bad_SemaphoreFileMissing`. | open |
| P4-DISC-02 | S3 | A | ⚠ | §5.5.2/.4 | GetEndpoints/FindServers return configured `host`, ignoring the client's connect-URL hostname. | open |
| P4-DISC-03 | S2 | A | ⚠ | §5.5.5.1 | RegisterServer accepts registrations without client-cert auth / serverUri↔applicationUri binding. | open |
| P4-ATTR-06 | S3 | A | ⚠ | §5.11.2 | IndexRange parsing hard-capped at 10 dimensions → decode error for higher-dim arrays. | open |
| P4-SUB-02 | S2 | C,A | ✅ | §5.14.7 T79 r22/23 | TransferSubscriptions issues no `Good_SubscriptionTransferred` to old session and doesn't reset lifetime. *Conflict resolved: confirmed (Codex marked HONORED = miss).* | open |
| P4-SUB-03 | S2 | C | ✅ | §5.13.1.5 | First Event discard places no `EventQueueOverflowEventType` in the queue (feature 030 gap). | open |
| P4-ATTR-02 | S3 | C | ✅ | §5.11.2 T47 | `maxAge` (0=fresh, ≥maxInt32=cached) ignored — fine for in-memory; matters for slow external sources. | deferred |
| P4-ATTR-03 | S3 | C | ✅ | §5.11.4 | LocalizedText write locale semantics / `Bad_LocaleNotSupported` not implemented. | deferred |
| P4-ATTR-04 | S3 | C | ✅ | §5.11.4 T55 | No enum/range validation on writes → `Bad_OutOfRange` never returned (spec permits). | deferred |

## Conflict log (resolved + open)
- **DeleteNodes target refs** (A:DIVERGENCE / X:HONORED) → **resolved partial:** within-manager cleanup
  honored via `address_space.delete`→`references.delete_node_references`; only the cross-manager trait
  hook is stubbed → **P4-NODEMGMT-02** (S3 narrow).
- **TransferSubscriptions** (C,A:DIVERGENCE / X:HONORED) → **resolved:** divergence confirmed
  (**P4-SUB-02**); Codex false-negative.
- **TranslateBrowsePaths targetName** (X:DIVERGENCE / C-agent:HONORED) → **resolved:** Codex right
  (§5.9.4.2 line 3227) → **P4-VIEW-02**.
- **BrowseNext release empties** (X:DIVERGENCE / C-agent:HONORED) → **resolved:** Codex right (line 3133)
  → **P4-VIEW-03**.
- **P4-ATTR-01 indexRange** (C,A:DIVERGENCE / X:HONORED) → **resolved:** confirmed earlier; Codex
  false-negative.
- **RegisterNodes array** (A:DIVERGENCE / X:HONORED) → **resolved:** AG right — `into_result()→None`
  filtered out, array shrinks (§5.9.5.2) → **P4-VIEW-04** (S2).
- **Cross-channel re-validation** (A:DIVERGENCE / C-agent:HONORED) → **resolved partial:** cert match
  enforced (C-agent right); SecurityPolicy/SecurityMode equality NOT enforced (AG right) → **P4-SESS-07**
  (S3, narrowed). All 7 conflicts now resolved.

## Detail (key items)
- **P4-SUB-01** (FIXED): `subscription.rs:400` first disjunct `publishing_enabled`→`!publishing_enabled`;
  test `part4_table79_normal_publish_rows_4_5` (red-first). Closed the Table 79 audit.
- **P4-ATTR-01**: `NumericRange` decoded eagerly via `impl_encoded_as!`/`from_ua_string` (numeric_range.rs);
  malformed string → decoding error fails the whole message. Fix is in the codec (lazy/lenient parse →
  per-op `Bad_IndexRangeInvalid`); resolves Read, Write, and Query (P4-QUERY indexRange) together.
- **P4-SUB-02**: `mod.rs::transfer` does remove→insert with no lifetime reset / no StatusChangeNotification.
  (a) reset is a one-liner; (b) needs an old-session "departed-subscription" status delivery mechanism.
- **P4-SUB-03**: build `EventQueueOverflowEventType` EventFieldList, enqueue on first discard, exempt from discard.

---
*Per-model raw audits: `FINDINGS-antigravity.md` (17), `FINDINGS-codex.md` (11). Union ≈ this table.*
