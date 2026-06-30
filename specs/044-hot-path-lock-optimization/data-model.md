# Data Model: Hot Path Lock Optimization

## Entity: LockBoundary

Represents one protected critical section identified by the audit.

Fields:

- `id`: Stable boundary identifier used by tasks.
- `owner_file`: Source file that owns the guard.
- `guard`: Lock or mutex being narrowed.
- `protected_invariant`: State consistency rule that still requires the guard.
- `work_to_move`: Callback, sampling, fanout, validation, or construction work that must happen after unlock.
- `opcua_reference`: OPC UA MCP section constraining externally visible behavior.

Validation rules:

- A boundary may be changed only by one task at a time.
- The task must prove the protected invariant still holds.
- The task must prove `work_to_move` no longer executes while the guard is live.

## Entity: CallbackHandleSnapshot

Represents a callback handle plus immutable metadata captured under lock and invoked after unlock.

Fields:

- `callback`: Owned or reference-counted callback handle.
- `node_id`: Node or method identifier used for lookup.
- `request_context`: Existing request context reference or immutable data needed by the callback.
- `arguments_or_value`: Read, Write, or Call input data passed to callback.
- `status_mapping`: Existing success/failure status behavior to preserve.

Validation rules:

- Snapshot capture must not call user code.
- Callback invocation must not require callback-registry, address-space, or type-tree guards.
- Callback return values must map to the same public statuses and outputs as before.

## Entity: ClientDeliveryPacket

Represents notification data produced under `subscription_state` and delivered to user callbacks after unlock.

Fields:

- `subscription_id`: Server-assigned subscription identifier.
- `sequence_number`: Notification sequence number.
- `notification`: Notification payload or owned notification data.
- `acknowledgement_effect`: Whether an acknowledgement was queued.
- `monitored_item_view`: Stable monitored-item/client-handle view for callback delivery.

Validation rules:

- Publish acknowledgements must be recorded before callback delivery.
- Callback delivery must not hold `subscription_state`.
- The monitored-item view must not borrow from state guarded by `subscription_state` after unlock.

## Entity: SamplerWorkItem

Represents due sampling work captured from `SyncSampler`.

Fields:

- `node_id`: Node being sampled.
- `attribute_id`: Attribute being sampled.
- `sampling_interval`: Configured interval used for due/not-due decision.
- `last_sample_update`: Scheduling update performed under lock.
- `sampler`: Callback or handle invoked after unlock.

Validation rules:

- Disabled samplers are skipped under the lock.
- Due/not-due decisions and `last_sample` updates stay coherent.
- Sampler callback execution and subscription notification happen after sampler lock release.

## Entity: NotificationRouteSnapshot

Represents a stable list of destinations for data-change or event fanout.

Fields:

- `source_node`: Node that produced data or event notification.
- `attribute_id`: Attribute being reported.
- `routes`: Subscription/session/monitored-item target list.
- `index_range`: Numeric range required for sampled values.
- `data_encoding`: Data encoding required for sampled values.
- `snapshot_version`: Optional version if a future versioned route index is introduced.

Validation rules:

- Route lookup occurs under the subscription-cache guard.
- Sampling closures and actor queue pushes occur after the guard is released.
- Create/modify/delete monitored-item races are covered by tests and documented behavior.
- Empty route snapshots avoid sampling closure execution and actor queue pushes.

## Entity: SessionDispatchLookup

Represents the small immutable result collected from `SessionManager` for normal request dispatch.

Fields:

- `authentication_token`: Request token from `RequestHeader`.
- `session`: Located session handle, if any.
- `actor_sender`: Located session actor sender, if any.
- `session_was_closed`: Closed-token status.
- `return_diagnostics`: Diagnostics flags copied before dispatch.

Validation rules:

- Lookup occurs under the manager read guard.
- Validation, audit-context setup, and service dispatch occur after the read guard is released.
- The lookup result must preserve OPC UA authentication token and closed-session status behavior.

## Entity: CreateSessionDraft

Represents CreateSession work prepared outside the manager write lock before a short commit.

Fields:

- `request`: CreateSession request data.
- `secure_channel_id`: SecureChannel identity used for association checks.
- `endpoint_selection`: Endpoint descriptions or selection result.
- `certificate_validation`: Certificate validation result or prepared context.
- `server_signature`: Prepared signature result, where semantics allow outside-lock work.
- `commit_limits`: Session limits that must be re-checked under the manager write lock.

Validation rules:

- Manager-wide session limits are checked before expensive work and re-checked at commit.
- Public CreateSession statuses remain unchanged.
- No session is published until commit succeeds.

## Entity: VersionedMetadataSnapshot

Represents a future immutable read-mostly metadata snapshot.

Fields:

- `version`: Monotonic version number or equivalent publication marker.
- `data`: Immutable `Arc` snapshot payload.
- `writer`: Lock or actor responsible for building new versions.
- `readers`: Hot paths that load the snapshot without a broad lock.

Validation rules:

- Readers never observe partially-mutated data.
- Writers publish only complete snapshots.
- Raw seqlock-style mutation over complex Rust-owned data is not allowed.

## Entity: QueueLane

Represents a future bounded SPSC or actor queue lane.

Fields:

- `producer`: Single producer or majordomo owner.
- `consumer`: Single consumer or target actor.
- `capacity`: Explicit queue bound.
- `backpressure_policy`: Await, reject, coalesce, or drop policy.
- `ordering_scope`: Protocol scope whose ordering must be preserved.

Validation rules:

- Queue capacity must be explicit.
- Backpressure behavior must be tested.
- SecureChannel response writing remains single-owner and ordered.

## State Transitions

```text
Guard-bound work selected
  -> OPC UA reference confirmed
       -> Regression/proof test added
            -> Guard captures snapshot only
                 -> Guard released
                      -> Callback/sampling/fanout executes
                           -> Public status/notification/session behavior verified
```

```text
CreateSession request received
  -> Pre-check manager limits
       -> Prepare endpoint/certificate/signature work outside write lock where safe
            -> Acquire manager write lock
                 -> Re-check limits and channel/session invariants
                      -> Commit session or return original public status
```

```text
Future snapshot candidate selected
  -> P1 guard-scope fix complete
       -> Benchmark or lock trace baseline recorded
            -> Immutable snapshot prototype
                 -> Stale-version race tests pass
                      -> Snapshot design accepted
```
