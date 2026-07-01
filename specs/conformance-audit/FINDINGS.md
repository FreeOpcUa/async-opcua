# Conformance audit — consolidated findings register (the fix list)

> ## Reconciliation pass — 2026-07-01 (verify-before-fix, 6 parallel agents + spot-checks)
> Every `open`/`deferred`/`conflict` row was re-verified against current code. **The register was
> heavily stale** — a large remediation push (notably `da395291b` "Remediate OPC UA audit findings",
> the JSON 1.05.07 migration, TCP hardening, RBAC feature 031, and features 032/046) closed most of it.
> Per-row Status cells below have been updated. **Genuinely still open after reconciliation:**
>
> | ID | Reconciled status | Narrowed scope |
> |---|---|---|
> | P4-NODEMGMT-01 | PARTIAL | 4/6 validations done; missing full hierarchical-reference rules + `targetNodeClass` match |
> | P4-GEN-01 | PARTIAL | ResponseHeader diagnostics + per-op for Read/Call/Write/NodeMgmt done; per-op `diagnosticInfos` still `None` for HistoryRead/Update, Browse/BrowseNext, 4× MonitoredItems, Query |
> | P4-ATTR-06 | OPEN | `NumericRange` `MAX_INDICES=10` cap (`numeric_range.rs:227`); >10 dims → `Invalid`. No spec basis |
> | P8-02 | OPEN (documented deferral) | EURange cached at create; no dynamic refresh / `SemanticsChanged` bit (`monitored_item.rs:365` ponytail note) |
> | P5-04 | OPEN | `ServerDiagnosticsType` mandatory `EnabledFlag`/`SubscriptionDiagnosticsArray`/`SessionsDiagnosticsSummary` absent |
> | P3-03 | PARTIAL | abstract-typeDef check works for address-space types; fails for type_tree-only standard types (TypeTree lacks abstractness) |
> | P3-05 | OPEN | symmetric ReferenceType + InverseName not cross-checked |
> | P3-06 | UNCERTAIN | HasTypeDefinition [1..1] cardinality not enforced across different targets |
> | P3-07 | OPEN | type-refinement subtype rules (DataType/ValueRank further-restriction) unvalidated |
> | P3-09 | OPEN | `AccessLevelEx` optional Variable attribute not modeled |
> | P4-ATTR-02/03/04 | DEFERRED (unchanged) | maxAge, LocalizedText-write locale, write range/enum validation |
>
> **Likely NOT-A-BUG:** P5-03 (NamespaceMetadata NodeClass) — code is correct (ObjectType→Object; Property children→Variable); finding appears inverted.
> **Newly confirmed FIXED (were open):** P4-SESS-07, P4-SESS-08, P4-DISC-02, P4-NODEMGMT-02, P4-MONITEM-03, P4-ATTR-05, P4-GEN-02, P4-GEN-03, P8-01, P6-JSON-02/03/04/05, P6-TCP-02/03/04, P3-02, P3-04, P3-08.

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
| P4-ATTR-05 | S2 | C | ✅ | §5.11.3.2 | HistoryRead never validates `timestampsToReturn==NEITHER` → `Bad_TimestampsToReturnInvalid` (10000-11 exceptions). *Codex UNCERTAIN; AG missed.* | **FIXED** (2026-07-01 reconcile: `attribute.rs:100-104` rejects `Invalid`\|`Neither` → `BadTimestampsToReturnInvalid`; test `history_read_neither_timestamps_returns_bad_timestamps_to_return_invalid`) |
| P4-VIEW-01 | S2 | C | ✅ | §5.9.2 T36 | Browse with non-ReferenceType `referenceTypeId` → empty+Good, not `Bad_ReferenceTypeIdInvalid` | **FIXED** (browse service validates referenceTypeId vs type tree → per-op `BadReferenceTypeIdInvalid`; test `browse_invalid_reference_type_is_bad_reference_type_id_invalid`, red-first) |
| P4-VIEW-02 | S3 | X | ✅ | §5.9.4.2 (3227) | TranslateBrowsePaths null `targetName`. **NOT A BUG — already honored:** `BrowsePathItem::new_root` (view.rs:637) already rejects any null targetName with `Bad_BrowseNameInvalid` upstream of the mod.rs:430 wildcard (which is dead for translate). *Verify-before-fix reversed the earlier conflict ruling: Codex saw the wildcard but missed new_root; the original Claude agent was right.* | **not-a-bug** (lock-in test `translate_browse_path_null_target_name_is_bad_browse_name_invalid`) |
| P4-VIEW-03 | S3 | X | ✅ | §5.9.3.2 T37 (3133) | BrowseNext `releaseContinuationPoints=TRUE` returns one BrowseResult per CP; spec: results & diagnosticInfos arrays empty. *Conflict resolved: Codex right.* | **FIXED** (release branch → empty results; corrected `browse_release_continuation_point` test to assert empty) |
| P4-VIEW-04 | S2 | A | ✅ | §5.9.5.2 | RegisterNodes drops unregistered nodes (`into_result()→None`, `filter_map`) → response array shorter than request; spec: size/order matches `nodesToRegister`. *Conflict resolved: AG right, Codex wrong.* | **FIXED** (`into_result` echoes every input NodeId; `filter_map`→`map`; test `register_nodes_echoes_every_input_node`, red-first) |
| P4-SESS-01 | S2 | C,A | ✅ | §5.7.5 | Cancel unimplemented → `BadServiceUnsupported`; compatibility.md claims it (doc drift). Min fix: `cancelCount=0`. *Codex UNCERTAIN.* | **FIXED** (Cancel handler → `CancelResponse{cancel_count:0}` Good; doc drift resolved; test `cancel_returns_cancel_count_zero`, red-first) |
| P4-SESS-02 | S2 | C,X | ✅→❌ | §5.7.2 (2417) | CreateSession enforces only clientNonce min, not the `>128` max. *AG missed.* | **NOT A BUG** (spec line 990 mandates only the minimum-length check, which manager.rs:249 already does → BadNonceInvalid; no 128-byte max is required for conformance). |
| P4-SESS-03 | S2 | X | ✅ | §5.6.2.2 (2612) | OpenSecureChannel can return `revisedLifetime==0`; spec requires >0 (`min(max,requested)` no lower bound). | **FIXED** (revise_secure_channel_lifetime: requested 0 → configured max, plus a >0 backstop; spec line 2612 'The Server shall provide a lifetime greater than 0'. Unit test `revised_secure_channel_lifetime_is_never_zero`, red-first.) |
| P4-SESS-04 | S3 | X | ✅ | §5.6.2 T12 | OSC Renew before any Issue → `BadUnexpectedError` not `BadSecureChannelIdInvalid`. | **FIXED** (renew-before-issue now returns BadSecureChannelIdInvalid; trivial spec-determined code change, verified by spec + OSC-renew no-regression — error path unreachable from a normal client). |
| P4-SESS-05 | S2 | A | ✅ | §5.7.2.1 / P6 §6.2.2 | Client-cert app-URI check uses the FIRST SAN entry. *Audit reconciled this as "conventional-correct" (likely-FP) — **the node-opcua interop harness disproved that**: node-opcua orders DNS/IP before the URI, so secured sessions were rejected with Bad_CertificateUriInvalid. Real interop bug; upgraded S3→S2.* | **FIXED** (is_application_uri_valid matches the applicationUri in ANY subjectAltName position; test `application_uri_valid_in_any_san_position`, red-first; validated end-to-end by the interop harness). Lesson: interop testing caught what spec-reading + 3-AI audit rationalised away. |
| P4-SESS-06 | S3 | A | ✅→❌ | §5.7.2 (2766) | Request on an unactivated session returns a fault but does not close the session. | **NOT A BUG** (spec lines 2766-2771 require only that an unactivated session not be *used* — already enforced via BadSessionNotActivated — plus closing the *oldest* unactivated session at the limit (max_unactivated_sessions_per_channel) and timeout cleanup (unactivated_session_timeout_ms), both present; it does NOT mandate closing the session on a wrong request). |
| P4-SESS-07 | S3 | A | ✅ | §5.7.3.1 | Cross-channel transfer enforces client-cert match (HONORED) but NOT SecurityPolicy/SecurityMode equality (`is_cross_channel_transfer_forbidden` only special-cases None); ClientUserId is re-authed (moot). *Conflict resolved: narrowed to policy/mode equality.* | **FIXED** (2026-07-01 reconcile: `manager.rs:963-985` enforces cross-channel SecurityMode + SecurityPolicy equality pre-auth; tests `activate_session_rejects_cross_channel_security_{mode,policy}_mismatch_before_authentication`) |
| P4-SESS-08 | S2 | A | ⚠ | §5.7.3.1 | Anonymous token over a new SecureChannel using Sign mode not rejected. *Claude agent UNCERTAIN.* | **FIXED** (2026-07-01 reconcile: `manager.rs:1001-1012` rejects anonymous cross-channel transfer to a Sign channel when prior identity non-anonymous → `BadIdentityTokenRejected`; test `activate_session_rejects_anonymous_transfer_to_new_sign_channel_before_authentication`) |
| P4-METHOD-01 | S2 | C,X | ✅ | §5.12 T61 | Call checks only `user_executable()` → `BadUserAccessDenied`; base `Executable` attr never checked → non-executable method still callable (should be `Bad_NotExecutable`). *AG missed.* | **FIXED** (executable() check before user_executable → `BadNotExecutable`; test `call_non_executable_method_is_bad_not_executable`, red-first) |
| P4-METHOD-02 | S3 | C,A | ✅ | §5.12 (3953) | `output_arguments` returned unconditionally; spec: empty when status severity Bad. | **FIXED** (returns None when status is Bad; was `Some([])`; test `failed_method_call_has_no_output_arguments`, red-first) |
| P4-QUERY-01 | S2 | C,A,X | ✅ | Annex B T B.6 | QueryFirst doesn't validate `typeDefinitionNode` → silent full-traversal vs `Bad_NodeIdInvalid`/`Bad_NotTypeDefinition` in parsingResults. *3-way agreement.* | **FIXED** (service validates typeDef vs type tree → `BadNotTypeDefinition` in parsingResults + `BadInvalidArgument` service result; test `query_invalid_type_definition_is_rejected`, red-first via repurposed lenient test) |
| P4-NODEMGMT-01 | S3 | C,A | ⚠ | §5.8 T24/27 | AddNodes/AddReferences validation cluster: `Bad_BrowseNameDuplicated`, typeDef existence, hierarchical-ref constraint, targetNodeClass match, duplicate-ref, user-privilege (`Bad_UserAccessDenied` vs global flag). Opt-in surface (default OFF). | **PARTIAL** (2026-07-01 reconcile: 4/6 done — browsename-dup `memory_mgr_impl.rs:154`, typeDef-existence `:160`, duplicate-ref `:386`, per-node RBAC `:128/:307`; STILL MISSING: full hierarchical-reference structural rules (only HasProperty→Variable) + `targetNodeClass` match) |
| P4-NODEMGMT-02 | S3 | A | ✅ | §5.8.4 | `NodeManager::delete_node_references` trait hook (cross-manager cleanup, node_management.rs:255) is an EMPTY stub in the memory manager → dangling cross-manager refs. *Conflict resolved: within-manager deletion IS honored (Codex right); only the cross-manager hook is stubbed (AG right). Narrow.* | **FIXED** (2026-07-01 reconcile: `memory_mgr_impl.rs:1408-1421` implements `delete_node_references`; test `delete_node_references_cleans_cross_manager_references_without_unrelated_deletes`) |
| P4-MONITEM-01 | S2 | X | ✅ | §5.13.2.3 T64 | CreateMonitoredItems accepts `TimestampsToReturn::Invalid` (no `Bad_TimestampsToReturnInvalid`; treated as Neither). | **FIXED** (Invalid check at handler top, mirrors Read; test `monitored_items_reject_invalid_timestamps_to_return`, red-first) |
| P4-MONITEM-02 | S2 | X | ✅ | §5.13.3.3 T67 | ModifyMonitoredItems accepts `TimestampsToReturn::Invalid`. | **FIXED** (same check; covered by the same red-first test) |
| P4-MONITEM-03 | S2 | X | ✅ | §5.13.4.3 T70 | SetMonitoringMode accepts an invalid MonitoringMode. *Verified: `MonitoringMode` enum has no `Invalid` variant + `#[opcua(default)] Disabled`, so an unknown value decodes to Disabled before the service sees it → needs a codec-level fix (strict decode), same class as the enum-default-on-unknown issue. Deferred with P4-ATTR-01-style codec work.* | **FIXED** (2026-07-01 reconcile: `MonitoringMode` now has `Invalid(i32)` variant; `monitored_items.rs:444` rejects → `BadMonitoringModeInvalid`) |
| P4-DISC-01 | S3 | C,X | ✅ | §5.5.5 T7 | RegisterServer/2 validate only `Bad_ServerUriInvalid`+limit; missing `Bad_ServerNameMissing`/`Bad_DiscoveryUrlMissing`/`Bad_SemaphoreFileMissing`. | **FIXED** (online registration now requires ServerName + DiscoveryUrl → `BadServerNameMissing`/`BadDiscoveryUrlMissing`; test `register_server_missing_name_or_url_is_rejected`, red-first. SemaphoreFile = offline-only, left as-is) |
| P4-DISC-02 | S3 | A | ⚠ | §5.5.2/.4 | GetEndpoints/FindServers return configured `host`, ignoring the client's connect-URL hostname. | **FIXED** (2026-07-01 reconcile: `info.rs` mirrors the client endpointUrl hostname into endpoint descriptions + FindServers discovery_urls; commit `da395291b`) |
| P4-DISC-03 | S2 | A | ✅ | §5.5.5.1 / P12 §7.5 | RegisterServer accepts registrations without client-cert auth / serverUri↔applicationUri binding → spoofing + unregister-DoS. | **FIXED** (RegisterServer/RegisterServer2 now require a secured channel whose client-cert applicationUri matches the registered serverUri; mismatch→BadServerUriInvalid, unsecured→BadSecurityChecksFailed. Discovery test suite reworked to register over a secured channel; new negative test `register_server_rejects_uri_not_bound_to_caller_certificate`. Behavioral change: rejects previously-permitted unsecured/mismatched registrations.) |
| P4-GEN-01 | S3 | C,A,X | ✅ | §5.2/5.3 | `returnDiagnostics` never honored: ResponseHeader `serviceDiagnostics` always default, `stringTable` always None, per-op `diagnosticInfos` always None/empty. `set_diagnostic_info()` exists but is never called. 3-way consensus. | **PARTIAL** (2026-07-01 reconcile: ResponseHeader `serviceDiagnostics`/`stringTable` now honored `response.rs:230-283`; per-op `diagnosticInfos` done for Read/Call/Write/NodeMgmt; STILL `None` for HistoryRead/Update, Browse/BrowseNext, 4× MonitoredItems `monitored_items.rs:311/426/499/557`, Query) |
| P4-GEN-02 | S3 | C,X | ✅ | §5.3 (1240) | Client's `MaxResponseMessageSize` (from CreateSession) is stored but never enforced; responses bounded only by the server's own `max_message_size`, not the client's declared limit → `Bad_ResponseTooLarge` per client limit not produced. | **FIXED** (2026-07-01 reconcile: feature 046 — CreateSession `max_response_message_size` → `manager.rs:refresh_client_response_body_limit_for_channel` → `SecureChannel::set_client_response_body_limit` → enforced `buffer.rs:237` → `BadResponseTooLarge`) |
| P4-GEN-03 | S3 | C,A,X | ✅ | §5.4 | Locale negotiation applied only in Discovery (FindServers/GetEndpoints); session-service LocalizedText (DisplayName/Description) returned ignoring the session's `localeIds`; special `mul`/`qst` locales unhandled and not rejected in Write. | **FIXED** (2026-07-01 reconcile: `read_node_value` applies `apply_session_locale_to_localized_text` `utils.rs:623`; write locale validated `:484`; `mul`/`qst` handled `manager.rs:108`) |
| P4-ATTR-06 | S3 | A | ⚠ | §5.11.2 | IndexRange parsing hard-capped at 10 dimensions → decode error for higher-dim arrays. | open (2026-07-01 reconcile: CONFIRMED — `numeric_range.rs:227` `MAX_INDICES=10`, `:256` `really????` comment; >10 dims → `Invalid`, no spec basis) |
| P4-SUB-02 | S2 | C,A | ✅ | §5.14.7 T79 r22/23 | TransferSubscriptions issues no `Good_SubscriptionTransferred` to old session and doesn't reset lifetime. *Conflict resolved: confirmed (Codex marked HONORED = miss).* | **FIXED** (old session now receives a Good_SubscriptionTransferred StatusChangeNotification via a session-level pending_status_changes queue delivered in tick; test `transfer_subscriptions_notifies_old_session`, red-first. Lifetime-reset on the NEW session was already handled.) |
| P4-SUB-03 | S2 | C | ✅ | §5.13.2 | First Event discard places no `EventQueueOverflowEventType` in the queue (feature 030 gap). | **FIXED** (on the first overflow-discard for an event MonitoredItem with queue_size>1, an EventQueueOverflowEventType is placed as an extra queue entry — front when discardOldest=TRUE, end otherwise; never itself discarded. Test `event_queue_overflow_inserts_overflow_event`, red-first.) |
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
| P6-BIN-02 | S2 | A,X | ✅ | §5.2.2.16 (3518) | Variant decode rejects reserved built-in type IDs 26–31 with `BadDecodingError`; spec: accept as ByteString(s) and pass to app. | **FIXED** (Variant::decode normalises element masks 26–31 → ByteString; scalar path previously returned Empty consuming 0 bytes, array path errored. Test `variant_decode_reserved_builtin_ids_as_bytestring`, red-first.) |
| P6-BIN-03 | S3 | X | ✅ | §5.2.2.17 (3666) | DataValue picoseconds not clamped — spec: values ≥10000 decode as 9999. | **FIXED** (binary decode clamps source/server picoseconds with `.min(9999)`; spec line 3666 'The decoder shall treat values greater than or equal to 10 000 as the value 9999'. Test `datavalue_decode_clamps_out_of_range_picoseconds`, red-first.) |
| P6-JSON-02 | S2 | X | ⚠ | §5.4.2.3 (3032) | JSON Int64/UInt64 emitted as JSON numbers; spec requires decimal **strings** (precision/interop). | **FIXED** (2026-07-01 reconcile: `json.rs:271` `json_enc_decimal_string_number!(i64/u64)` → decimal strings) |
| P6-JSON-03 | S2 | X | ⚠ | §5.4.2.10/.11 | JSON NodeId/ExpandedNodeId use 1.04 object form, not the on-disk **1.05.07 string form**. *Version decided 2026-06-23: target specs-on-disk → confirmed real fix (interop-affecting; coordinate with client side).* | **FIXED** (2026-07-01 reconcile: `node_id/json.rs:31-74` + `expanded_node_id.rs:135-166` emit/decode 1.05.07 string form, object form rejected) |
| P6-JSON-04 | S2 | X | ⚠ | §5.4.2.17 | JSON Variant uses 1.04 `Type`/`Body`; on-disk 1.05.07 uses `UaType`/`Value`. *Target = specs-on-disk → confirmed real fix.* | **FIXED** (2026-07-01 reconcile: `variant/json.rs:79/89` emit `UaType`/`Value`; legacy `Type`/`Body` decode is opt-in via `VariantJsonFieldMode::LegacyTypeBodyCompatibility`) |
| P6-JSON-05 | S3 | X | ⚠ | §5.4.2.16 | JSON ExtensionObject `UaBody`/null handling diverges; duplicate JSON field names not rejected (spec: decode error). | **FIXED** (2026-07-01 reconcile: duplicate keys rejected by the struson reader; test `extension_object_duplicate_json_field_names_are_rejected` passes) |
| P6-TCP-01 | S2 | A,X | ⚠ | §7.1.2.3 (5275) | `MaxChunkCount==0` (= unlimited per spec) computes an effective inbound limit of **1** when max_message_size is also 0 → rejects legit multi-chunk messages. (`transport/tcp.rs:116`) | **NOT A LIVE BUG** (the both-zero case that hits the `1` fallback is rejected by server config validation server.rs:523; `revise()` can't drive either limit to 0; the realistic max_chunk_count=0+max_message_size>0 path derives a generous ceiling) |
| P6-TCP-02 | S3 | C,X | ⚠ | §7.1.2.3 (5262) | Hello buffer-size min always 8192; spec allows 1024 when an ECC SecurityPolicy is intended. | **FIXED** (2026-07-01 reconcile: `tcp_types.rs:44-56` `minimum_buffer_size_for_security_policy` → 1024 for ECC, 8192 otherwise; test passes) |
| P6-TCP-03 | S3 | X | ⚠ | §6.7.2.3 (4222) | Asymmetric SecurityHeader `SecurityPolicyUri` decoded as general UAString; spec caps at 255 bytes (invalid → close channel). | **FIXED** (2026-07-01 reconcile: `security_header.rs:21-46` caps at 255 → `BadEncodingLimitsExceeded`; test passes) |
| P6-TCP-04 | S2 | C | ⚠ | §7.1.2.2 | Pre-Hello / ERR / ACK frames may not be bounded by `max_message_size` at the TcpCodec layer (pre-negotiation allocation). **Soft-conflict: Codex marked the codec size-check HONORED (tcp_codec.rs:93) — reconcile.** | **FIXED / HONORED** (2026-07-01 reconcile: `tcp_codec.rs:218-249` `validate_declared_message_size` bounds pre-negotiation frames before allocation; tests `pre_hello_ack_and_err_declared_message_sizes_*`. Codex was right.) |
| P6-TCP-05 | S2 | A | ✅ | §6.7.3 (7115) | Abort (FinalError) chunk clears `pending_chunks` before its security is verified (`transport/tcp.rs:473`) → an unauthenticated/forged abort could drop a victim's in-progress reassembly. **Conflict resolved: confirmed — spec line 7115 "shall check the security on the abort MessageChunk before processing it" (Codex HONORED = miss).** | **FIXED** (process_message verifies the abort chunk via verify_and_remove_security_server before clearing pending_chunks; verified by spec + no-regression on the secured RSA+ECC matrix; adversarial case not black-box observable, as with P2-SEC-01/02) |

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
| P3-01 | S2 | C,A,X | ✅ | §5.6 (2704) | ValueRank setters (`set_value_rank`, variable.rs:805 / variable_type.rs:275) store any i32 — no check against {-3,-2,-1,0,≥1}. A `value_rank.rs::new_checked` helper exists but the node setters bypass it. | **FIXED** (set_value_rank on Variable + VariableType normalises ranks < -3 to ANY (-2) per Part 3 §5.6; was storing raw i32. Test `set_value_rank_normalises_invalid_ranks`, red-first.) [P3-01 only; the P3-02 ArrayDimensions↔ValueRank consistency check is separate — see below.] |
| P3-02 | S2 | C,A,X | ⚠ | §5.6 (2719) | ArrayDimensions↔ValueRank consistency not enforced: spec requires `len==ValueRank` when ValueRank>0 and null when ≤0; setters + AddNodes builder accept them independently. | **FIXED** (2026-07-01 reconcile: `variable.rs:875-887` `value_rank_matches_array_dimensions()` enforced on both setters + `is_valid()`; commit `da395291b`) |
| P3-03 | S2 | C,A,X | ✅ | §5.6/§6 (3091) | AddNodes does not check the typeDefinition's `IsAbstract` → abstract ObjectType/VariableType can be instantiated (no `is_abstract` anywhere in memory_mgr_impl.rs). Overlaps P4-NODEMGMT-01. | **PARTIAL** (2026-07-01 reconcile: `memory_mgr_impl.rs:584-592` checks `is_abstract()` for typeDefs present in the address space; GAP `:600-607` — type_tree-only standard types can't be checked (TypeTree stores NodeClass, not abstractness)) |
| P3-04 | S2 | C,A,X | ⚠ | §5.3.1 (2227) | AddReferences does not check the ReferenceType's `IsAbstract` → abstract ReferenceTypes usable directly. | **FIXED** (2026-07-01 reconcile: `memory_mgr_impl.rs:332-340` `reference_type_is_abstract()` (address space + `standard_reference_type_is_abstract` fallback) → `BadReferenceTypeIdInvalid`) |
| P3-05 | S3 | C,A | ✅ | §5.3.2 (2274) | Symmetric ReferenceType + InverseName not prohibited (independent `symmetric`/`inverse_name` fields, no validation); spec: symmetric → InverseName omitted. (Standard generated nodes are correct; affects custom ref types.) | open (2026-07-01 reconcile: CONFIRMED — `reference_type.rs:94-126/218-240` set symmetric + inverse_name independently, no cross-check) |
| P3-06 | S3 | C | ⚠ | §7.13 (5317) | `HasTypeDefinition` exactly-one-per-Object/Variable not enforced on insert. | open/UNCERTAIN (2026-07-01 reconcile: AddNodes creates exactly one `memory_mgr_impl.rs:189-202`; AddReferences blocks same-target dupes `:386` but not a *second* HasTypeDefinition to a *different* target → [1..1] cardinality not strictly enforced) |
| P3-07 | S3 | C | ⚠ | §6.2.8 | Type-refinement subtype rules not enforced: a subtype's DataType/ValueRank may only further-restrict the supertype's; setters accept arbitrary changes. | open (2026-07-01 reconcile: CONFIRMED — no subtype-refinement validation in variable_type.rs/object_type.rs/memory_mgr_impl.rs) |
| P3-08 | S3 | A | ⚠ | §5.2 | Base optional attrs `RolePermissions`/`UserRolePermissions`/`AccessRestrictions` un-modeled (relevant to Part 18 role security). | **FIXED** (2026-07-01 reconcile: feature 031 RBAC — `base.rs:31-33/81-95/118-124` models RolePermissions + AccessRestrictions on the base node, readable via `AttributeId::{RolePermissions,AccessRestrictions}`) |
| P3-09 | S3 | C | ⚠ | §5.6 | Variable `AccessLevelEx` optional attribute not modeled. | open (2026-07-01 reconcile: CONFIRMED — `variable.rs` has `access_level`/`user_access_level` only; no `access_level_ex` field or `AttributeId::AccessLevelEx` handling) |

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
| P2-SEC-03 | S3 | X | ✅ | P4 §6.1.3 | Suppressed cert-validation failures are logged `warn!` but emit no `AuditCertificate*` event; §6.1.3 says suppressed errors are always reported via auditing. *Matches the known feature-013 deferral (typed AuditCertificate events).* | **FIXED for X.509 user identity certificates** (user-token certificate validation now returns suppressed findings to the session layer, which emits matching `AuditCertificate*` events carrying the certificate bytes. Existing application-certificate validation remains unchanged except for the already typed certificate-audit support.) |
| P2-SEC-04 | S2 | X | ✅ | P4 §6.1.8 | X.509 user-token signature is verified before any §6.1.3 validation of the user signing certificate; authentication then checks only the configured thumbprint. Spec: don't verify a signature before validating the signing cert. | **FIXED** (`X509IdentityToken` authentication now validates the presented certificate through `CertificateStore::validate_user_identity_cert` before user-token signature verification and thumbprint mapping; configured thumbprints no longer bypass trust-chain, validity, usage, policy, or revocation checks. Valid certificates with bad user-token signatures still return `BadUserSignatureInvalid`.) |

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
| P8-01 | S2 | A | ⚠ | P8 §7.2 | `modify_monitored_items` doesn't fetch the node's EURange (only the create path does) → modifying a monitored item to add a Percent deadband fails with `BadDeadbandFilterInvalid` even on a valid AnalogItem. | **FIXED** (2026-07-01 reconcile: `monitored_items.rs:333-374` modify path now fetches EURange via `get_eu_range`, mirroring create) |
| P8-02 | S3 | A | ⚠ | P8 §5.3.2 | No `SemanticsChanged` status bit / no dynamic EURange refresh — monitored items cache EURange at create and don't update if EURange changes. | open — DOCUMENTED DEFERRAL (2026-07-01 reconcile: `monitored_item.rs:365` explicit ponytail note — EURange read once at create, not re-resolved per sample, to avoid a node read per sample; not a bug, an intentional tradeoff) |
| P5-01 | S3 | C,A | ✅ | P5 §6.3.2 | Mandatory `ServerCapabilities.LocaleIdArray` and `SoftwareCertificates` are not populated (return static empty); LocaleIdArray should reflect configured locale_ids. | **FIXED** (LocaleIdArray now reads config.locale_ids; test `server_capabilities_locale_id_array_is_populated`, red-first. SoftwareCertificates empty = correct when none configured.) |
| P5-02 | S3 | A | ✅ | P5 §6.3.2 | `MinSupportedSampleRate` returned as u32; spec datatype is `Duration` (Double). *Conflict resolved: AG right — verified at runtime Value=UInt32(100) but DataType=NodeId(290)=Duration.* | **FIXED** (expose the f64 directly via .into() → Double; the old `as u32` truncated; test `min_supported_sample_rate_value_matches_duration_datatype`, red-first) |
| P5-03 | S3 | A | ⚠ | P5 §6.3.14 | NamespaceMetadata property nodes report `NodeClass::Object` instead of `Variable` on the NodeClass attribute read. | **likely NOT-A-BUG** (2026-07-01 reconcile: `diagnostics/node_manager.rs:178` — the NamespaceMetadata *instance* is an ObjectType→`Object` (correct); its Property children ARE `Variable` `:197`. Finding appears inverted; verify against a specific node before any fix) |
| P5-04 | S3 | A | ⚠ | P5 §6.3.7 | `ServerDiagnosticsType` missing mandatory `EnabledFlag` / `SubscriptionDiagnosticsArray` / `SessionsDiagnosticsSummary` (only if the server claims the diagnostics facet). | open (2026-07-01 reconcile: CONFIRMED — nodes 2294/2290/3706 have zero refs in server impl; `diagnostics/server.rs` exposes only ServerDiagnosticsSummary) |

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
