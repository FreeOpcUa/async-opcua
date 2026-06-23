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
| P4-ATTR-01 | S2 | C,A | ✅ | §5.11.2/.4 T49/55 | Malformed `indexRange` → whole-message `BadDecodingError`, not per-op `Bad_IndexRangeInvalid` (NumericRange eager decode). Also hits Query/Write. *Codex missed.* | **FIXED** (lenient `NumericRange::Invalid(raw)` decode; range_of/set_range_of → `BadIndexRangeInvalid` per-op; tests `malformed_numeric_range_decodes_leniently…` (red-first) + e2e `read_invalid_index_range_is_per_operation`. Also resolves the Query-side indexRange abort.) |
| P4-ATTR-05 | S2 | C | ✅ | §5.11.3.2 | HistoryRead never validates `timestampsToReturn==NEITHER` → `Bad_TimestampsToReturnInvalid` (10000-11 exceptions). *Codex UNCERTAIN; AG missed.* | open |
| P4-VIEW-01 | S2 | C | ✅ | §5.9.2 T36 | Browse with non-ReferenceType `referenceTypeId` → empty+Good, not `Bad_ReferenceTypeIdInvalid` | **FIXED** (browse service validates referenceTypeId vs type tree → per-op `BadReferenceTypeIdInvalid`; test `browse_invalid_reference_type_is_bad_reference_type_id_invalid`, red-first) |
| P4-VIEW-02 | S3 | X | ✅ | §5.9.4.2 (3227) | TranslateBrowsePaths null `targetName`. **NOT A BUG — already honored:** `BrowsePathItem::new_root` (view.rs:637) already rejects any null targetName with `Bad_BrowseNameInvalid` upstream of the mod.rs:430 wildcard (which is dead for translate). *Verify-before-fix reversed the earlier conflict ruling: Codex saw the wildcard but missed new_root; the original Claude agent was right.* | **not-a-bug** (lock-in test `translate_browse_path_null_target_name_is_bad_browse_name_invalid`) |
| P4-VIEW-03 | S3 | X | ✅ | §5.9.3.2 T37 (3133) | BrowseNext `releaseContinuationPoints=TRUE` returns one BrowseResult per CP; spec: results & diagnosticInfos arrays empty. *Conflict resolved: Codex right.* | **FIXED** (release branch → empty results; corrected `browse_release_continuation_point` test to assert empty) |
| P4-VIEW-04 | S2 | A | ✅ | §5.9.5.2 | RegisterNodes drops unregistered nodes (`into_result()→None`, `filter_map`) → response array shorter than request; spec: size/order matches `nodesToRegister`. *Conflict resolved: AG right, Codex wrong.* | **FIXED** (`into_result` echoes every input NodeId; `filter_map`→`map`; test `register_nodes_echoes_every_input_node`, red-first) |
| P4-SESS-01 | S2 | C,A | ✅ | §5.7.5 | Cancel unimplemented → `BadServiceUnsupported`; compatibility.md claims it (doc drift). Min fix: `cancelCount=0`. *Codex UNCERTAIN.* | **FIXED** (Cancel handler → `CancelResponse{cancel_count:0}` Good; doc drift resolved; test `cancel_returns_cancel_count_zero`, red-first) |
| P4-SESS-02 | S2 | C,X | ✅ | §5.7.2 (2417) | CreateSession enforces only clientNonce min, not the `>128` max. *AG missed.* | open |
| P4-SESS-03 | S2 | X | ⚠ | §5.6.2.2 T11 | OpenSecureChannel can return `revisedLifetime==0`; spec requires >0 (`min(max,requested)` no lower bound). | open |
| P4-SESS-04 | S3 | X | ⚠ | §5.6.2.3 T12 | OSC Renew before any Issue → `BadUnexpectedError` not `BadSecureChannelIdInvalid`. | open |
| P4-SESS-05 | S3 | A | ✅ | §5.7.2.1 | Client-cert app-URI check uses the FIRST SAN entry. *Reconciled (P2 pass): conventional-correct — the applicationUri is the first SAN by OPC UA convention and the hostname check correctly skips index 0. Likely false-positive; X.509 SAN ordering not strictly guaranteed, so low-priority.* | likely-FP |
| P4-SESS-06 | S3 | A | ⚠ | §5.7.3.1 | Request on an unactivated session returns a fault but does not close the session. | open |
| P4-SESS-07 | S3 | A | ✅ | §5.7.3.1 | Cross-channel transfer enforces client-cert match (HONORED) but NOT SecurityPolicy/SecurityMode equality (`is_cross_channel_transfer_forbidden` only special-cases None); ClientUserId is re-authed (moot). *Conflict resolved: narrowed to policy/mode equality.* | open |
| P4-SESS-08 | S2 | A | ⚠ | §5.7.3.1 | Anonymous token over a new SecureChannel using Sign mode not rejected. *Claude agent UNCERTAIN.* | open |
| P4-METHOD-01 | S2 | C,X | ✅ | §5.12 T61 | Call checks only `user_executable()` → `BadUserAccessDenied`; base `Executable` attr never checked → non-executable method still callable (should be `Bad_NotExecutable`). *AG missed.* | **FIXED** (executable() check before user_executable → `BadNotExecutable`; test `call_non_executable_method_is_bad_not_executable`, red-first) |
| P4-METHOD-02 | S3 | C,A | ✅ | §5.12 (3953) | `output_arguments` returned unconditionally; spec: empty when status severity Bad. (AG framed as inputArgumentResults never populated.) | open |
| P4-QUERY-01 | S2 | C,A,X | ✅ | Annex B T B.6 | QueryFirst doesn't validate `typeDefinitionNode` → silent full-traversal vs `Bad_NodeIdInvalid`/`Bad_NotTypeDefinition` in parsingResults. *3-way agreement.* | **FIXED** (service validates typeDef vs type tree → `BadNotTypeDefinition` in parsingResults + `BadInvalidArgument` service result; test `query_invalid_type_definition_is_rejected`, red-first via repurposed lenient test) |
| P4-NODEMGMT-01 | S3 | C,A | ⚠ | §5.8 T24/27 | AddNodes/AddReferences validation cluster: `Bad_BrowseNameDuplicated`, typeDef existence, hierarchical-ref constraint, targetNodeClass match, duplicate-ref, user-privilege (`Bad_UserAccessDenied` vs global flag). Opt-in surface (default OFF). | open |
| P4-NODEMGMT-02 | S3 | A | ✅ | §5.8.4 | `NodeManager::delete_node_references` trait hook (cross-manager cleanup, node_management.rs:255) is an EMPTY stub in the memory manager → dangling cross-manager refs. *Conflict resolved: within-manager deletion IS honored (Codex right); only the cross-manager hook is stubbed (AG right). Narrow.* | open |
| P4-MONITEM-01 | S2 | X | ✅ | §5.13.2.3 T64 | CreateMonitoredItems accepts `TimestampsToReturn::Invalid` (no `Bad_TimestampsToReturnInvalid`; treated as Neither). | **FIXED** (Invalid check at handler top, mirrors Read; test `monitored_items_reject_invalid_timestamps_to_return`, red-first) |
| P4-MONITEM-02 | S2 | X | ✅ | §5.13.3.3 T67 | ModifyMonitoredItems accepts `TimestampsToReturn::Invalid`. | **FIXED** (same check; covered by the same red-first test) |
| P4-MONITEM-03 | S2 | X | ✅ | §5.13.4.3 T70 | SetMonitoringMode accepts an invalid MonitoringMode. *Verified: `MonitoringMode` enum has no `Invalid` variant + `#[opcua(default)] Disabled`, so an unknown value decodes to Disabled before the service sees it → needs a codec-level fix (strict decode), same class as the enum-default-on-unknown issue. Deferred with P4-ATTR-01-style codec work.* | open |
| P4-DISC-01 | S3 | C,X | ✅ | §5.5.5 T7 | RegisterServer/2 validate only `Bad_ServerUriInvalid`+limit; missing `Bad_ServerNameMissing`/`Bad_DiscoveryUrlMissing`/`Bad_SemaphoreFileMissing`. | **FIXED** (online registration now requires ServerName + DiscoveryUrl → `BadServerNameMissing`/`BadDiscoveryUrlMissing`; test `register_server_missing_name_or_url_is_rejected`, red-first. SemaphoreFile = offline-only, left as-is) |
| P4-DISC-02 | S3 | A | ⚠ | §5.5.2/.4 | GetEndpoints/FindServers return configured `host`, ignoring the client's connect-URL hostname. | open |
| P4-DISC-03 | S2 | A | ⚠ | §5.5.5.1 | RegisterServer accepts registrations without client-cert auth / serverUri↔applicationUri binding. | open |
| P4-GEN-01 | S3 | C,A,X | ✅ | §5.2/5.3 | `returnDiagnostics` never honored: ResponseHeader `serviceDiagnostics` always default, `stringTable` always None, per-op `diagnosticInfos` always None/empty. `set_diagnostic_info()` exists but is never called. 3-way consensus. | open |
| P4-GEN-02 | S3 | C,X | ✅ | §5.3 (1240) | Client's `MaxResponseMessageSize` (from CreateSession) is stored but never enforced; responses bounded only by the server's own `max_message_size`, not the client's declared limit → `Bad_ResponseTooLarge` per client limit not produced. | open |
| P4-GEN-03 | S3 | C,A,X | ✅ | §5.4 | Locale negotiation applied only in Discovery (FindServers/GetEndpoints); session-service LocalizedText (DisplayName/Description) returned ignoring the session's `localeIds`; special `mul`/`qst` locales unhandled and not rejected in Write. | open |
| P4-ATTR-06 | S3 | A | ⚠ | §5.11.2 | IndexRange parsing hard-capped at 10 dimensions → decode error for higher-dim arrays. | open |
| P4-SUB-02 | S2 | C,A | ✅ | §5.14.7 T79 r22/23 | TransferSubscriptions issues no `Good_SubscriptionTransferred` to old session and doesn't reset lifetime. *Conflict resolved: confirmed (Codex marked HONORED = miss).* | open |
| P4-SUB-03 | S2 | C | ✅ | §5.13.1.5 | First Event discard places no `EventQueueOverflowEventType` in the queue (feature 030 gap). | open |
| P4-ATTR-02 | S3 | C | ✅ | §5.11.2 T47 | `maxAge` (0=fresh, ≥maxInt32=cached) ignored — fine for in-memory; matters for slow external sources. | deferred |
| P4-ATTR-03 | S3 | C | ✅ | §5.11.4 | LocalizedText write locale semantics / `Bad_LocaleNotSupported` not implemented. | deferred |
| P4-ATTR-04 | S3 | C | ✅ | §5.11.4 T55 | No enum/range validation on writes → `Bad_OutOfRange` never returned (spec permits). | deferred |

## Part 6 — Mappings (encoding + transport)
**3-of-3 pass:** Claude (binary/JSON DoS + transport) + Codex (`FINDINGS-codex-p6.md`) + Antigravity
(`FINDINGS-antigravity-p6.md`, 16 findings — retry succeeded; original timeout was infra). All three
independently corroborate the headline items (JSON array DoS, bool decode, type IDs 26-31, picoseconds,
JSON Type/Body + NodeId object form, MaxChunkCount 0→1, ECC buffer, SecurityPolicyUri/reason size) →
high confidence. AG-unique add: **P6-TCP-05** — abort (FinalError) chunk clears `pending_chunks` before
security is verified (`transport/tcp.rs:473`) — lets an unauthenticated peer drop a victim's in-progress
reassembly (verify; codex marked abort handling HONORED → soft-conflict).

| ID | Sev | Found | Verify | Part 6 § | Divergence | Status |
|---|---|---|---|---|---|---|
| P6-JSON-01 | **S1** | C,A | ✅ | §5.4.5 | `Vec<T>::JsonDecodable` (json.rs:113) loops `res.push()` with NO `max_array_length` bound (binary path has it) → unbounded allocation / OOM from a malicious JSON array (reachable via JSON PubSub). | **FIXED** (bound added to json.rs + variant/json.rs → `BadEncodingLimitsExceeded`; test `json_array_decode_is_bounded_by_max_array_length`, red-first) |
| P6-BIN-01 | S2 | A,X | ✅ | §5.2.2.1 (1543) | Boolean decode `read_u8()? == 1` → bytes 2–255 decode as **false**; spec: decoders shall treat any non-zero as true. (`basic_types.rs:46`) | **FIXED** (`!= 0`; test `decode_bool_any_nonzero_is_true`, red-first) |
| P6-BIN-02 | S2 | A,X | ⚠ | §5.2.2.16 (2005) | Variant decode rejects reserved built-in type IDs 26–31 with `BadDecodingError`; spec: accept as ByteString(s) and pass to app. | open |
| P6-BIN-03 | S3 | X | ⚠ | §5.2.2.17 (2077) | DataValue picoseconds not clamped — spec: values ≥10000 decode as 9999. | open |
| P6-JSON-02 | S2 | X | ⚠ | §5.4.2.3 (3032) | JSON Int64/UInt64 emitted as JSON numbers; spec requires decimal **strings** (precision/interop). | open |
| P6-JSON-03 | S2 | X | ⚠ | §5.4.2.10/.11 | JSON NodeId/ExpandedNodeId use 1.04 object form, not the on-disk **1.05.07 string form**. *Version decided 2026-06-23: target specs-on-disk → confirmed real fix (interop-affecting; coordinate with client side).* | open |
| P6-JSON-04 | S2 | X | ⚠ | §5.4.2.17 | JSON Variant uses 1.04 `Type`/`Body`; on-disk 1.05.07 uses `UaType`/`Value`. *Target = specs-on-disk → confirmed real fix.* | open |
| P6-JSON-05 | S3 | X | ⚠ | §5.4.2.16 | JSON ExtensionObject `UaBody`/null handling diverges; duplicate JSON field names not rejected (spec: decode error). | open |
| P6-TCP-01 | S2 | A,X | ⚠ | §7.1.2.3 (5275) | `MaxChunkCount==0` (= unlimited per spec) computes an effective inbound limit of **1** when max_message_size is also 0 → rejects legit multi-chunk messages. (`transport/tcp.rs:116`) | open |
| P6-TCP-02 | S3 | C,X | ⚠ | §7.1.2.3 (5262) | Hello buffer-size min always 8192; spec allows 1024 when an ECC SecurityPolicy is intended. | open |
| P6-TCP-03 | S3 | X | ⚠ | §6.7.2.3 (4222) | Asymmetric SecurityHeader `SecurityPolicyUri` decoded as general UAString; spec caps at 255 bytes (invalid → close channel). | open |
| P6-TCP-04 | S2 | C | ⚠ | §7.1.2.2 | Pre-Hello / ERR / ACK frames may not be bounded by `max_message_size` at the TcpCodec layer (pre-negotiation allocation). **Soft-conflict: Codex marked the codec size-check HONORED (tcp_codec.rs:93) — reconcile.** | conflict |
| P6-TCP-05 | S2 | A | ⚠ | §6.7.3 (4412) | Abort (FinalError) chunk clears `pending_chunks` before its security is verified (`transport/tcp.rs:473`) → an unauthenticated/forged abort could drop a victim's in-progress reassembly. **Soft-conflict: Codex marked abort handling HONORED — reconcile.** | conflict |

> Binary path is otherwise solid (String/ByteString/Array/ExtensionObject bounds all enforced; NodeId
> 4-encodings, Variant matrix dims, DiagnosticInfo/DataValue depth-locks HONORED — 017/018/025 paid off).
> The DoS gap migrated to the **JSON** path (P6-JSON-01). **Version decision (user, 2026-06-23): target
> the specs on disk** (Part 6 = 1.05.07) → the JSON field-form findings P6-JSON-02/03/04 are confirmed
> real fixes (the repo currently emits 1.04 forms). These are wire-format + interop-affecting, so they
> need coordinated client+server changes and likely a compat note — sequence after the safe fixes.

## Part 3 — Address Space Model
**3-of-3 pass:** Claude (attributes + references) + Codex (`FINDINGS-codex-p3.md`, 5) + Antigravity
(`FINDINGS-antigravity-p3.md`, 8). The model is largely sound — Base mandatory attrs, standard
ReferenceType hierarchy, `includeSubtypes`/`is_subtype_of`, no-self-reference, Method
`user_executable()=executable&&user_executable`, AccessLevel bits all HONORED. The gaps are **missing
validation on mutation** (ValueRank/ArrayDimensions/abstract/symmetric), mostly reachable via the
opt-in writable address space (AddNodes, default OFF) or programmatic node construction → overlaps
P4-NODEMGMT-01.

| ID | Sev | Found | Verify | Part 3 § | Divergence | Status |
|---|---|---|---|---|---|---|
| P3-01 | S2 | C,A,X | ✅ | §5.6 (2704) | ValueRank setters (`set_value_rank`, variable.rs:805 / variable_type.rs:275) store any i32 — no check against {-3,-2,-1,0,≥1}. A `value_rank.rs::new_checked` helper exists but the node setters bypass it. | open |
| P3-02 | S2 | C,A,X | ⚠ | §5.6 (2719) | ArrayDimensions↔ValueRank consistency not enforced: spec requires `len==ValueRank` when ValueRank>0 and null when ≤0; setters + AddNodes builder accept them independently. | open |
| P3-03 | S2 | C,A,X | ✅ | §5.6/§6 (3091) | AddNodes does not check the typeDefinition's `IsAbstract` → abstract ObjectType/VariableType can be instantiated (no `is_abstract` anywhere in memory_mgr_impl.rs). Overlaps P4-NODEMGMT-01. | open |
| P3-04 | S2 | C,A,X | ⚠ | §5.3.1 (2227) | AddReferences does not check the ReferenceType's `IsAbstract` → abstract ReferenceTypes usable directly. | open |
| P3-05 | S3 | C,A | ✅ | §5.3.2 (2274) | Symmetric ReferenceType + InverseName not prohibited (independent `symmetric`/`inverse_name` fields, no validation); spec: symmetric → InverseName omitted. (Standard generated nodes are correct; affects custom ref types.) | open |
| P3-06 | S3 | C | ⚠ | §7.13 (5317) | `HasTypeDefinition` exactly-one-per-Object/Variable not enforced on insert. | open |
| P3-07 | S3 | C | ⚠ | §6.2.8 | Type-refinement subtype rules not enforced: a subtype's DataType/ValueRank may only further-restrict the supertype's; setters accept arbitrary changes. | open |
| P3-08 | S3 | A | ⚠ | §5.2 | Base optional attrs `RolePermissions`/`UserRolePermissions`/`AccessRestrictions` un-modeled (relevant to Part 18 role security). | open |
| P3-09 | S3 | C | ⚠ | §5.6 | Variable `AccessLevelEx` optional attribute not modeled. | open |

## Part 2 — Security Model (+ Part 4 §6.1 mechanisms)
**2-of-3 pass:** Claude (cert validation + SecureChannel crypto) + Codex (`FINDINGS-codex-p2.md`, 4).
**Antigravity timed out during the file WRITE** (narrated ~6, no file) — retry optional. Strongly
reassuring: the crypto is well-hardened — all 11 §6.1.3 cert-validation steps (chain/signature/validity/
keyUsage/EKU/URI/hostname/CRL revocation, correct status codes + suppressibility) HONORED, and nonce
length/CSPRNG, P-SHA1/256 + ECC-HKDF key derivation, and CreateSession/ActivateSession signatures (over
cert‖nonce, algorithm-matched) all HONORED (Claude + Codex agree). The real gaps are about **WHERE
validation is invoked**, not the crypto itself:

| ID | Sev | Found | Verify | § | Divergence | Status |
|---|---|---|---|---|---|---|
| P2-SEC-01 | S2 | X | ✅ | P4 §6.1.4/§6.1.3 | OpenSecureChannel verifies proof-of-possession (asym signature) + nonce length but does NOT run §6.1.3 trust-chain validation; `validate_or_reject_application_instance_cert` is called only at CreateSession (manager.rs:268). An untrusted/expired/revoked cert can establish a SecureChannel. | **FIXED** (OSC now validates client-cert trust for secured policies → `BadSecurityChecksFailed`; applicationUri stays a CreateSession check. Verified: full RSA+ECC secured matrix incl. renewal still connects.) |
| P2-SEC-02 | S3 | X | ✅ | P4 §6.1.7 | SecureChannel Renew does not re-run ApplicationInstanceCertificate verification. | **FIXED** (with P2-SEC-01: `open_secure_channel` handles both Issue and Renew, so the new validation runs on every renewal; `ecc_nistp256_channel_renewal` confirms renewal still works). |
| P2-SEC-03 | S3 | X | ⚠ | P4 §6.1.3 | Suppressed cert-validation failures are logged `warn!` but emit no `AuditCertificate*` event; §6.1.3 says suppressed errors are always reported via auditing. *Matches the known feature-013 deferral (typed AuditCertificate events).* | open |
| P2-SEC-04 | S2 | X | ⚠ | P4 §6.1.8 | X.509 user-token signature is verified before any §6.1.3 validation of the user signing certificate; authentication then checks only the configured thumbprint. Spec: don't verify a signature before validating the signing cert. | open |

> Net: security is the strongest area audited — no crypto/algorithm/key-derivation gaps. The four
> findings are validation-invocation/ordering + audit-event emission. P2-SEC-01 is the notable one.

## Parts 5 / 8 / 11 / 12 / 14 — companion / claimed surface
**P5 + P8 audited 3-of-3** (Claude ×2, Codex `FINDINGS-codex-p58.md` 6, Antigravity
`FINDINGS-antigravity-p58.md` 7). Strongly conformant: **ServerStatus** (all fields, live),
**ServerCapabilities OperationLimits** (exposed AND consistent with the limits services actually
enforce — verified), **NamespaceArray**, and **DataAccess deadband** (Absolute + Percent fully
implemented, EURange correctly required → `BadDeadbandFilterInvalid` when absent, array + non-numeric
handling, integration-tested — compatibility.md claim accurate). Findings are low-severity:

| ID | Sev | Found | Verify | § | Divergence | Status |
|---|---|---|---|---|---|---|
| P8-01 | S2 | A | ⚠ | P8 §7.2 | `modify_monitored_items` doesn't fetch the node's EURange (only the create path does) → modifying a monitored item to add a Percent deadband fails with `BadDeadbandFilterInvalid` even on a valid AnalogItem. | open |
| P8-02 | S3 | A | ⚠ | P8 §5.3.2 | No `SemanticsChanged` status bit / no dynamic EURange refresh — monitored items cache EURange at create and don't update if EURange changes. | open |
| P5-01 | S3 | C,A | ✅ | P5 §6.3.2 | Mandatory `ServerCapabilities.LocaleIdArray` and `SoftwareCertificates` are not populated (return static empty); LocaleIdArray should reflect configured locale_ids. | **FIXED** (LocaleIdArray now reads config.locale_ids; test `server_capabilities_locale_id_array_is_populated`, red-first. SoftwareCertificates empty = correct when none configured.) |
| P5-02 | S3 | A | ⚠ | P5 §6.3.2 | `MinSupportedSampleRate` returned as u32; spec datatype is `Duration` (Double). *Claude agent marked it HONORED — soft-conflict, re-verify the Variant type.* | conflict |
| P5-03 | S3 | A | ⚠ | P5 §6.3.14 | NamespaceMetadata property nodes report `NodeClass::Object` instead of `Variable` on the NodeClass attribute read. | open |
| P5-04 | S3 | A | ⚠ | P5 §6.3.7 | `ServerDiagnosticsType` missing mandatory `EnabledFlag` / `SubscriptionDiagnosticsArray` / `SessionsDiagnosticsSummary` (only if the server claims the diagnostics facet). | open |

> **P11 (Historical Access):** covered by the P4-ATTR HistoryRead/Update pass (variants + CP handling
> HONORED; gap P4-ATTR-05 NEITHER). **P12 (Discovery/GDS):** covered by P4-DISC (RegisterServer
> findings) + feature 026 (GetSecurityKeys/SKS). **P14 (PubSub):** covered by feature 026 (secured
> UADP) + the **P6-JSON-01 S1 DoS lands on the JSON PubSub path**. No separate deep pass — these are
> already-implemented features with their gaps captured above.

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
