# Lock Optimization Traceability Contract

**Scope**: Scoped evidence map for `044-hot-path-lock-optimization`.

This contract adapts the spec-to-code-compliance workflow to a performance implementation spec. It is not a full repository-wide compliance audit. It maps audit findings and source locations to implementation requirements so future tasks can stay evidence-grounded.

## Spec-IR

```yaml
- id: HPL-SPEC-001
  spec_excerpt: "Server read/write/method callbacks run while address-space, type-tree, or callback-registry guards are held."
  source_section: "docs/HOT_PATH_LOCK_AUDIT_2026-06-30.md: Findings - Change First / P1 Server Callbacks"
  source_document: "docs/HOT_PATH_LOCK_AUDIT_2026-06-30.md"
  semantic_type: "hot_path_lock_scope"
  normalized_form: "Server extension callbacks must be invoked after internal guards are released."
  confidence: 0.96

- id: HPL-SPEC-002
  spec_excerpt: "Client subscription callbacks run while the client subscription-state mutex is held."
  source_section: "docs/HOT_PATH_LOCK_AUDIT_2026-06-30.md: Findings - Change First / P1 Client Subscription Callbacks"
  source_document: "docs/HOT_PATH_LOCK_AUDIT_2026-06-30.md"
  semantic_type: "callback_delivery_lock_scope"
  normalized_form: "Client notification delivery callbacks must execute outside subscription_state."
  confidence: 0.95

- id: HPL-SPEC-003
  spec_excerpt: "`SyncSampler` holds its sampler map mutex while executing sampler callbacks and notification fanout."
  source_section: "docs/HOT_PATH_LOCK_AUDIT_2026-06-30.md: Findings - Change First / P1 SyncSampler"
  source_document: "docs/HOT_PATH_LOCK_AUDIT_2026-06-30.md"
  semantic_type: "timer_hot_path_lock_scope"
  normalized_form: "Sampling callbacks and notification fanout must occur after releasing the sampler-map mutex."
  confidence: 0.96

- id: HPL-SPEC-004
  spec_excerpt: "Subscription notification helpers hold the global subscription-cache read guard while sampling and while routing work to per-session actors."
  source_section: "docs/HOT_PATH_LOCK_AUDIT_2026-06-30.md: Findings - Change First / P1 Subscription Notification Fanout"
  source_document: "docs/HOT_PATH_LOCK_AUDIT_2026-06-30.md"
  semantic_type: "fanout_lock_scope"
  normalized_form: "Notification routing must snapshot routes under the cache guard and enqueue after unlock."
  confidence: 0.94

- id: HPL-SPEC-005
  spec_excerpt: "SessionManager read guard is wider than necessary."
  source_section: "docs/HOT_PATH_LOCK_AUDIT_2026-06-30.md: Findings - Shrink or Measure / P2 SessionManager"
  source_document: "docs/HOT_PATH_LOCK_AUDIT_2026-06-30.md"
  semantic_type: "request_dispatch_lock_scope"
  normalized_form: "Normal request dispatch must scope SessionManager read guard to lookup-only data collection."
  confidence: 0.86

- id: HPL-SPEC-006
  spec_excerpt: "CreateSession holds manager write lock around nontrivial work."
  source_section: "docs/HOT_PATH_LOCK_AUDIT_2026-06-30.md: Findings - Shrink or Measure / P2 CreateSession"
  source_document: "docs/HOT_PATH_LOCK_AUDIT_2026-06-30.md"
  semantic_type: "exclusive_lock_scope"
  normalized_form: "CreateSession should move validation/crypto/construction outside manager write lock and re-check limits at commit."
  confidence: 0.84

- id: HPL-SPEC-007
  spec_excerpt: "Secure-channel renewal single-flight holds Tokio mutex across network await."
  source_section: "docs/HOT_PATH_LOCK_AUDIT_2026-06-30.md: Findings - Shrink or Measure / P2 Secure-Channel Renewal"
  source_document: "docs/HOT_PATH_LOCK_AUDIT_2026-06-30.md"
  semantic_type: "measurement_gated_refactor"
  normalized_form: "Renewal locking is intentional single-flight and must be measured before design changes."
  confidence: 0.88

- id: HPL-SPEC-008
  spec_excerpt: "Use versioned immutable snapshots rather than raw seqlocks for read-mostly rich Rust data."
  source_section: "docs/HOT_PATH_LOCK_AUDIT_2026-06-30.md: Seqlock-Inspired Snapshot Opportunities"
  source_document: "docs/HOT_PATH_LOCK_AUDIT_2026-06-30.md"
  semantic_type: "architecture_constraint"
  normalized_form: "Snapshot follow-ups must publish immutable Arc snapshots and avoid raw seqlock mutation."
  confidence: 0.90

- id: HPL-SPEC-009
  spec_excerpt: "Per-session actors, bounded rings, and chunked refresh draining are the right direction."
  source_section: "docs/HOT_PATH_LOCK_AUDIT_2026-06-30.md: Keep - Do Not Rewrite Blindly"
  source_document: "docs/HOT_PATH_LOCK_AUDIT_2026-06-30.md"
  semantic_type: "preserve_architecture"
  normalized_form: "Existing subscription actor/ring architecture must be preserved while shortening guard lifetimes."
  confidence: 0.88

- id: HPL-SPEC-010
  spec_excerpt: "More worker threads without these fixes can increase contention by piling more tasks onto the same locks."
  source_section: "docs/HOT_PATH_LOCK_AUDIT_2026-06-30.md: Executive Summary"
  source_document: "docs/HOT_PATH_LOCK_AUDIT_2026-06-30.md"
  semantic_type: "implementation_ordering"
  normalized_form: "Lock-scope reductions must precede broader multi-threaded processing changes."
  confidence: 0.87
```

## Code-IR

```yaml
- id: HPL-CODE-001
  file: "async-opcua-server/src/node_manager/memory/simple.rs"
  functions:
    - "read_values"
    - "write"
    - "call"
  lines: "192-207, 303-309, 343-355"
  visibility: "trait implementation methods"
  behavior:
    preconditions:
      - "Read/Write/Call request reaches in-memory node-manager implementation."
    state_reads:
      - "address_space read guard at line 192"
      - "read callback registry guard at line 193"
      - "address_space, type_tree, and write callback registry guards at lines 303-305"
      - "method callback registry guards at lines 343-344"
    external_calls:
      - "read_node_value is called while read guards are live at lines 198-205"
      - "write_node_value is called while write guards are live at line 308"
      - "method callbacks are invoked while registry guards are live at lines 347 and 355"
    postconditions:
      - "request values or statuses are populated"
  invariants_enforced:
    - "Callbacks must see request/node metadata consistent with current locked lookup."
    - "Callback return statuses and outputs must remain unchanged after refactor."
  confidence: 0.95

- id: HPL-CODE-002
  file: "async-opcua-server/src/node_manager/memory/core.rs"
  functions:
    - "method call path"
  lines: "691-693"
  visibility: "internal node-manager path"
  behavior:
    state_reads:
      - "method_with_context_cbs registry read guard at line 691"
    external_calls:
      - "context-aware method callback invoked at line 693"
    postconditions:
      - "call outputs/statuses are populated"
  invariants_enforced:
    - "Context-aware method callbacks must preserve object id and arguments."
  confidence: 0.90

- id: HPL-CODE-003
  file: "async-opcua-client/src/session/services/subscriptions/service.rs"
  functions:
    - "Publish response handling path"
  lines: "2367-2369"
  visibility: "client subscription service"
  behavior:
    state_reads:
      - "subscription_state mutex locked at line 2367"
    state_writes:
      - "handle_notification mutates subscription state at line 2368"
    postconditions:
      - "more_notifications is returned at line 2369"
  invariants_enforced:
    - "Acknowledgements for notification data must still be queued."
    - "Publish response processing must preserve current return behavior."
  confidence: 0.93

- id: HPL-CODE-004
  file: "async-opcua-client/src/session/services/subscriptions/state.rs"
  functions:
    - "handle_notification"
  lines: "219-232"
  visibility: "pub(crate)"
  behavior:
    state_writes:
      - "acknowledgement added at line 229 when notification data exists"
      - "subscription lookup and mutation at lines 231-232"
    external_calls:
      - "sub.on_notification invoked at line 232"
  invariants_enforced:
    - "Notifications with data produce acknowledgements."
    - "Unknown subscriptions are warned about without losing acknowledgement handling."
  confidence: 0.92

- id: HPL-CODE-005
  file: "async-opcua-client/src/session/services/subscriptions/mod.rs"
  functions:
    - "Subscription::on_notification"
  lines: "347-351"
  visibility: "pub(crate)"
  behavior:
    external_calls:
      - "user callback object receives notification at lines 348-351"
    computations:
      - "MonitoredItemMap is created from monitored_items and client_handles at line 350"
  invariants_enforced:
    - "Callback must receive notification and monitored-item lookup view."
  confidence: 0.93

- id: HPL-CODE-006
  file: "async-opcua-server/src/node_manager/utils/sync_sampler.rs"
  functions:
    - "SyncSampler loop"
  lines: "181-199"
  visibility: "internal async task"
  behavior:
    state_reads:
      - "sampler map mutex locked at line 181"
    state_writes:
      - "sampler.last_sample updated at line 196"
    external_calls:
      - "sampler callback invoked at line 195"
      - "subscriptions.notify_data_change invoked at line 199"
  invariants_enforced:
    - "Disabled samplers are skipped."
    - "Sampling interval is respected before invoking sampler callback."
  confidence: 0.96

- id: HPL-CODE-007
  file: "async-opcua-server/src/subscriptions/mod.rs"
  functions:
    - "data_notifier"
    - "notify_data_change"
    - "maybe_notify"
  lines: "634-635, 665-668, 675-687"
  visibility: "public subscription cache methods"
  behavior:
    state_reads:
      - "cache read guard created at line 635"
    external_calls:
      - "maybe_notify sample closure invoked at lines 684-686 while notifier is live"
    postconditions:
      - "notifications are batched in notifier"
  invariants_enforced:
    - "Only matching monitored items receive data-change notifications."
  confidence: 0.92

- id: HPL-CODE-008
  file: "async-opcua-server/src/subscriptions/notify.rs"
  functions:
    - "Drop for SubscriptionDataNotifier"
  lines: "129-140"
  visibility: "Drop implementation"
  behavior:
    state_reads:
      - "subscription_to_session lookup at lines 132-135"
    external_calls:
      - "per-session actor handle receives push_notification at line 140"
    postconditions:
      - "batched data work is sent to session actors"
  invariants_enforced:
    - "Notification fanout must preserve subscription to session routing."
  confidence: 0.91

- id: HPL-CODE-009
  file: "async-opcua-server/src/session/controller.rs"
  functions:
    - "request dispatch"
  lines: "786-794"
  visibility: "internal controller path"
  behavior:
    state_reads:
      - "SessionManager read guard acquired at line 786"
      - "session, actor_sender, and closed-token state read at lines 787-790"
    computations:
      - "validation begins at line 792 while the excerpt shows guard still in scope"
  invariants_enforced:
    - "Authentication token lookup must remain consistent for validation."
  confidence: 0.84

- id: HPL-CODE-010
  file: "async-opcua-server/src/session/controller.rs"
  functions:
    - "CreateSession dispatch"
  lines: "523-532"
  visibility: "internal controller path"
  behavior:
    state_reads:
      - "SessionManager write guard acquired at line 525"
    external_calls:
      - "mgr.create_session invoked at lines 526-532"
  invariants_enforced:
    - "Session manager limits and commit must remain exclusive."
  confidence: 0.86

- id: HPL-CODE-011
  file: "async-opcua-server/src/session/manager.rs"
  functions:
    - "create_session"
  lines: "399-430"
  visibility: "pub(crate)"
  behavior:
    state_reads:
      - "session limit checked at lines 407-420"
      - "endpoint descriptions built at lines 423-426"
    postconditions:
      - "endpoint URL empty path returns BadTcpEndpointUrlInvalid at lines 428-430"
  invariants_enforced:
    - "Session limits must be re-checked when moving work outside the write lock."
    - "Endpoint and certificate status behavior must remain unchanged."
  confidence: 0.84

- id: HPL-CODE-012
  file: "async-opcua-client/src/transport/channel.rs"
  functions:
    - "renew_secure_channel"
  lines: "190-212"
  visibility: "internal async method"
  behavior:
    state_reads:
      - "issue_channel_lock awaited at line 195"
      - "secure_channel read at lines 196-199"
    external_calls:
      - "renew request send awaited at line 209"
      - "close_channel awaited at line 212 on send error"
  invariants_enforced:
    - "Renewal remains single-flight."
    - "Failure path closes channel as current behavior requires."
  confidence: 0.88
```

## Alignment-IR

```yaml
- id: HPL-ALIGN-001
  spec_ref: HPL-SPEC-001
  code_ref:
    - HPL-CODE-001
    - HPL-CODE-002
  spec_claim: "Server callbacks must not execute while internal guards are live."
  code_behavior: "Current code invokes read/write/method callbacks through paths where guards are live."
  match_type: "code_weaker_than_spec"
  confidence: 0.95
  reasoning: "The implementation spec requires post-unlock invocation; current code evidence shows callback invocation inside guarded scopes."
  evidence:
    spec_quote: "Clone Arc callback handles and required node metadata while locked, release guards, then invoke callbacks."
    code_locations:
      - "simple.rs lines 192-207"
      - "simple.rs lines 303-309"
      - "simple.rs lines 343-355"
      - "core.rs lines 691-693"

- id: HPL-ALIGN-002
  spec_ref: HPL-SPEC-002
  code_ref:
    - HPL-CODE-003
    - HPL-CODE-004
    - HPL-CODE-005
  spec_claim: "Client subscription callbacks must run outside subscription_state."
  code_behavior: "Current Publish path locks subscription_state, calls handle_notification, and reaches callback delivery."
  match_type: "code_weaker_than_spec"
  confidence: 0.93
  reasoning: "The current call chain combines state mutation and callback delivery under one mutex scope."
  evidence:
    spec_quote: "Release the mutex, then invoke callbacks on a separate delivery path."
    code_locations:
      - "service.rs lines 2367-2369"
      - "state.rs lines 219-232"
      - "mod.rs lines 347-351"

- id: HPL-ALIGN-003
  spec_ref: HPL-SPEC-003
  code_ref:
    - HPL-CODE-006
  spec_claim: "Sampler callbacks and notification fanout must not run under sampler-map mutex."
  code_behavior: "Current sampler loop holds samplers.lock() while invoking sampler callback and notify_data_change."
  match_type: "code_weaker_than_spec"
  confidence: 0.96
  reasoning: "The lock is acquired before iterator creation and remains in scope through sampling and notification."
  evidence:
    spec_quote: "Collect due sampler work or sampled values, release the sampler mutex, then notify."
    code_locations:
      - "sync_sampler.rs lines 181-199"

- id: HPL-ALIGN-004
  spec_ref: HPL-SPEC-004
  code_ref:
    - HPL-CODE-007
    - HPL-CODE-008
  spec_claim: "Subscription fanout must snapshot routes and enqueue outside the global cache guard."
  code_behavior: "Current notifier holds a cache read guard while sampling through maybe_notify and pushing work in Drop."
  match_type: "code_weaker_than_spec"
  confidence: 0.91
  reasoning: "Current notifier lifetime couples route lookup, sample closure execution, and drop-time fanout to the cache guard."
  evidence:
    spec_quote: "Snapshot matching routes under the cache guard, then release it before sampling and before pushing work to actor queues."
    code_locations:
      - "subscriptions/mod.rs lines 634-635"
      - "subscriptions/mod.rs lines 675-687"
      - "subscriptions/notify.rs lines 129-140"

- id: HPL-ALIGN-005
  spec_ref: HPL-SPEC-005
  code_ref:
    - HPL-CODE-009
  spec_claim: "SessionManager read guard should be lookup-only on normal dispatch."
  code_behavior: "Current code acquires manager read guard, performs lookup, then proceeds into validation while guard appears in scope."
  match_type: "code_weaker_than_spec"
  confidence: 0.84
  reasoning: "The excerpt supports a wider-than-lookup scope, but implementation should confirm exact drop point before refactor."
  evidence:
    spec_quote: "Scope the guard only around lookup, then drop it before validation and dispatch."
    code_locations:
      - "session/controller.rs lines 786-794"

- id: HPL-ALIGN-006
  spec_ref: HPL-SPEC-006
  code_ref:
    - HPL-CODE-010
    - HPL-CODE-011
  spec_claim: "CreateSession should split expensive work from short locked commit."
  code_behavior: "Current controller holds manager write guard while invoking create_session; create_session performs limit checks and endpoint work."
  match_type: "partial_match"
  confidence: 0.82
  reasoning: "Some work requires exclusivity, but evidence shows nontrivial work under the manager write lock. Task planning must separate safe outside-lock work from commit-time re-checks."
  evidence:
    spec_quote: "Use a two-phase create path where validation and crypto happen outside the manager write lock where semantics allow."
    code_locations:
      - "session/controller.rs lines 523-532"
      - "session/manager.rs lines 399-430"

- id: HPL-ALIGN-007
  spec_ref: HPL-SPEC-007
  code_ref:
    - HPL-CODE-012
  spec_claim: "Secure-channel renewal is intentional single-flight and must be measured before change."
  code_behavior: "Current code holds an async mutex across network await to serialize renewal."
  match_type: "partial_match"
  confidence: 0.88
  reasoning: "The current design satisfies single-flight semantics but may serialize waiters behind network I/O; measurement decides whether to change it."
  evidence:
    spec_quote: "Measure before changing."
    code_locations:
      - "transport/channel.rs lines 190-212"

- id: HPL-ALIGN-008
  spec_ref: HPL-SPEC-008
  code_ref: []
  spec_claim: "Snapshot follow-ups must use immutable versioned publication instead of raw seqlocks."
  code_behavior: "No implementation selected yet."
  match_type: "missing_in_code"
  confidence: 0.86
  reasoning: "This is an architectural constraint for future tasks, not a current code defect by itself."
  evidence:
    spec_quote: "Prefer versioned immutable snapshots over raw seqlocks."
    code_locations: []

- id: HPL-ALIGN-009
  spec_ref: HPL-SPEC-009
  code_ref:
    - HPL-CODE-008
  spec_claim: "Existing subscription actor/ring architecture should be preserved."
  code_behavior: "Current fanout pushes NotificationWorkItem to per-session actor handles."
  match_type: "full_match"
  confidence: 0.86
  reasoning: "The architecture exists and should be retained while changing route snapshot timing."
  evidence:
    spec_quote: "Per-session actors, bounded rings, and chunked refresh draining are the right direction."
    code_locations:
      - "subscriptions/notify.rs lines 138-140"

- id: HPL-ALIGN-010
  spec_ref: HPL-SPEC-010
  code_ref:
    - HPL-CODE-001
    - HPL-CODE-003
    - HPL-CODE-006
    - HPL-CODE-007
  spec_claim: "Lock-scope fixes must precede broader multi-threaded processing."
  code_behavior: "Multiple hot paths still hold guards across callback/fanout work."
  match_type: "code_weaker_than_spec"
  confidence: 0.87
  reasoning: "Broader concurrency would increase pressure on these guarded sections before the scoped refactors land."
  evidence:
    spec_quote: "Before adding broader multi-threaded request processing, shorten these lock scopes."
    code_locations:
      - "simple.rs lines 192-207"
      - "service.rs lines 2367-2369"
      - "sync_sampler.rs lines 181-199"
      - "subscriptions/mod.rs lines 675-687"
```

## Divergence Summary

```yaml
- id: HPL-DIV-001
  severity: "high"
  title: "Server extension callbacks execute under internal locks"
  spec_claim: "Callbacks should execute after internal guard release."
  code_finding: "Read, Write, and Call paths invoke callback-capable functions while guards are live."
  match_type: "code_weaker_than_spec"
  confidence: 0.95
  remediation: "Clone callback handles and immutable metadata under lock; release guards; invoke callbacks; add reentrant callback tests."

- id: HPL-DIV-002
  severity: "high"
  title: "Client subscription callbacks execute under subscription_state"
  spec_claim: "Callback delivery should run outside subscription_state."
  code_finding: "Publish handling combines state mutation and callback delivery under one mutex scope."
  match_type: "code_weaker_than_spec"
  confidence: 0.93
  remediation: "Split notification handling into state mutation plus delivery packets; invoke callbacks after unlock; add reentrant callback tests."

- id: HPL-DIV-003
  severity: "high"
  title: "Sampler callbacks and notification fanout execute under sampler-map mutex"
  spec_claim: "Sampling and fanout should occur after sampler lock release."
  code_finding: "SyncSampler invokes sampler callback and notify_data_change while sampler lock remains in scope."
  match_type: "code_weaker_than_spec"
  confidence: 0.96
  remediation: "Collect due sampler work or sampled values, update last_sample under lock, then sample/notify after unlock with tests for concurrent sampler mutation."

- id: HPL-DIV-004
  severity: "high"
  title: "Subscription fanout holds global cache guard too broadly"
  spec_claim: "Fanout should snapshot routes then enqueue outside cache guard."
  code_finding: "Notifier carries cache read guard through sample closure and drop-time actor pushes."
  match_type: "code_weaker_than_spec"
  confidence: 0.91
  remediation: "Introduce route snapshots or owned route batches; release cache guard before sampling and actor enqueue."
```
