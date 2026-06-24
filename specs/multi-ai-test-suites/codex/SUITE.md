# Codex Independent Coverage Gaps for async-opcua

Scope: these are novel tests relative to the listed interop/error-mode/MITM/fuzz/session coverage and the current integration files inspected under `async-opcua/tests/integration/`. Concrete candidate code lives in this directory and is intentionally not wired into the repo because the exercise forbids editing outside `specs/multi-ai-test-suites/codex/`.

## P0 - SetTriggering Delivers Queued Sampling Items

**What it tests:** Create two monitored items in one subscription: a trigger item in `Reporting` and a linked item in `Sampling`. Add the link with `SetTriggering`, change only the linked value and verify no publish occurs, then change the trigger and verify both values are emitted.

**Why this may catch a missed bug:** Existing tests cover unknown monitored-item IDs, `SetMonitoringMode`, publishing enabled/disabled, and unit-level trigger bookkeeping, but not the positive server-to-client `SetTriggering` delivery path. This exercises the server trigger list, queued sampled values, publish batching, and client notification callback path together.

**Spec reference:** OPC UA Part 4 §5.12.5 `SetTriggering`; Part 4 §5.13.1.2 monitored-item modes.

**Implementation sketch:** Rust integration test using `setup()`, two test variables, `session.create_monitored_items`, `session.set_triggering`, and `ChannelNotifications`. Candidate code: `subscription_triggering_edges.rs`.

## P0 - SetTriggering Link Removal Stops Triggered Delivery

**What it tests:** After adding a trigger link, remove it with `SetTriggering(linksToRemove)`, change the linked item, then change the trigger. The linked item must not be delivered after removal.

**Why this may catch a missed bug:** Remove paths often update only the client cache or only one side of the server data structure. A stale trigger link would pass unknown-ID error tests and simple mode tests but still leak queued sampling data on later publishes.

**Spec reference:** OPC UA Part 4 §5.12.5 `SetTriggering`.

**Implementation sketch:** Rust integration test using the same fixture as the positive trigger test, asserting the post-remove publish contains only the trigger value. Candidate code: `subscription_triggering_edges.rs`.

## P0 - DataChange Queue Overflow Bit Survives Publish Assembly

**What it tests:** Create a data-change monitored item with `queueSize=2` and `discardOldest=true`, disable publishing so the queue fills, enqueue more values than fit, re-enable publishing, then assert the published `DataChangeNotification` retains the last two values and marks exactly the oldest retained value with the Overflow info bit.

**Why this may catch a missed bug:** The repo has local `MonitoredItem` overflow unit tests and event-overflow integration coverage, but the service-level data-change path still has room for regressions in `DataChangeNotification` batching, pooled vector reuse, raw `Publish` response construction, or client-side notification extraction.

**Spec reference:** OPC UA Part 4 §5.13.1.5 monitored-item queue overflow; Part 4 §5.13.2 monitored-item notifications.

**Implementation sketch:** Raw `CreateSubscription`, `CreateMonitoredItems`, `SetPublishingMode`, and `Publish` calls so no automatic publish loop drains the queue. Candidate code: `datachange_queue_overflow.rs`.

## P0 - SecureChannelId Confusion Inside a Valid MSG

**What it tests:** A MITM proxy rewrites bytes 8..12, the `SecureChannelId`, in the first service `MSG` chunk while leaving the TCP header and message type valid. The server must reject the poisoned channel/request and continue serving a clean connection.

**Why this may catch a missed bug:** Existing adversarial transport tests cover replayed sequence numbers, signed-body tamper, oversized message headers, and invalid message type. This is a distinct routing/authentication confusion case: a syntactically plausible chunk names the wrong secure channel.

**Spec reference:** OPC UA Part 6 §6.7.2 message chunks; Part 6 §6.7.4 secure-channel message header.

**Implementation sketch:** Adapt the existing adversarial proxy style, mutate the first client-to-server `MSG`, then assert client failure plus server survival. Candidate code: `adversarial_chunk_edges.rs`.

## P0 - Client Abort Chunk During Service Request Assembly

**What it tests:** After a secure channel is established, rewrite the first service chunk's chunk type to `A` (Abort). The server should abandon that in-flight request/channel as appropriate and remain healthy for later clients.

**Why this may catch a missed bug:** Abort chunks are not equivalent to bad message types or oversized frames. They exercise partial-request cleanup and request assembler state that fuzzing may not reach with an established secure-channel context.

**Spec reference:** OPC UA Part 6 §6.7.2 chunk types `F`, `C`, and `A`.

**Implementation sketch:** MITM raw transport test like `adversarial.rs`, but mutate the chunk-type byte on the first `MSG`. Candidate code: `adversarial_chunk_edges.rs`.

## P1 - Sampling to Reporting Delivers Only Queued Latest Semantics

**What it tests:** Create an item in `Sampling`, update it several times while it is not reporting, then switch it to `Reporting`. Assert the first reported value follows queue semantics, not a stale creation value and not all intermediate values unless queue policy says so.

**Why this may catch a missed bug:** Current tests inspect mode fields and cover publishing-disabled behavior, but the pure `Sampling -> Reporting` transition can reveal stale `last_data_value`, missing queued value, and queue-size mishandling bugs.

**Spec reference:** OPC UA Part 4 §5.12.4 `SetMonitoringMode`; Part 4 §5.13.1.2 monitoring modes.

**Implementation sketch:** Rust raw subscription test using `CreateMonitoredItems` in `Sampling`, several `set_value` calls, `SetMonitoringMode(Reporting)`, and a single raw `Publish` assertion.

## P1 - Structured ExtensionObject Binary Round-Trip Matrix

**What it tests:** Round-trip a matrix of nested generated structures through binary `ExtensionObject`, including null arrays, empty arrays, nested diagnostic info, localized text with null text, variant arrays, and `DataValue` timestamp/status combinations.

**Why this may catch a missed bug:** Fuzzing stresses decoders with arbitrary bytes, and custom-type integration tests cover selected application paths, but they do not assert semantic preservation for valid edge-shaped generated structures. Bugs here can silently corrupt real server metadata or structured method arguments.

**Spec reference:** OPC UA Part 6 §5.2 binary encoding; Part 6 §5.2.2.15 `ExtensionObject`; Part 3/4 data-type payload definitions as applicable.

**Implementation sketch:** Rust property-style unit/integration candidate that builds valid structures, encodes with `BinaryEncodable`, decodes with `BinaryDecodable`, and asserts equality plus exact byte consumption. Keep cases deterministic so failures are reproducible.

## P1 - UserName IdentityToken PolicyId and Empty Secret Edges

**What it tests:** Activate a session with a valid username but wrong `policyId`, an empty password, a null password, and a username token encrypted against a stale server nonce after a reconnect/reactivation boundary.

**Why this may catch a missed bug:** Existing suites cover wrong password and unknown user, and ECC tests cover happy-path password wrapping. Policy-id routing, empty secret normalization, and nonce freshness can fail before or after authenticator dispatch and produce incorrect acceptance or misleading status codes.

**Spec reference:** OPC UA Part 4 §5.6.3 `ActivateSession`; Part 4 §7.41 user identity tokens.

**Implementation sketch:** Raw `ActivateSessionRequest` builder on a secured channel so token fields can be malformed deliberately. Assert `BadIdentityTokenInvalid` or `BadIdentityTokenRejected` as appropriate and verify a subsequent clean activation still works.

## P2 - RegisterServer Online/Offline Race and Registry Replacement

**What it tests:** Concurrently register the same `serverUri` online with one product/name while another request marks it offline or updates it. `FindServers` should observe either the old or new valid state, never duplicates or a half-deleted entry.

**Why this may catch a missed bug:** Current discovery tests cover happy path, idempotent update, missing fields, secure-channel requirement, spoofed URI, and mDNS unsupported. They do not stress concurrent registry mutation, which is relevant to LDS behavior under restart storms.

**Spec reference:** OPC UA Part 4 §5.4.5 `RegisterServer`; Part 12 §7.5 LDS registration.

**Implementation sketch:** Spawn several secured clients against one test server, synchronize repeated `register_server(true/false)` calls with a barrier, then poll `find_servers` for duplicate `serverUri`/`productUri` entries and invalid transitional data.

## P2 - AddNodes Rollback and Reference Consistency on Mixed Batch

**What it tests:** Submit a batch where one `AddNodesItem` succeeds, another has a bad type definition, and a third references the first item as parent or target. Verify the returned per-item statuses and resulting address space do not contain dangling references or partially applied dependent nodes.

**Why this may catch a missed bug:** Existing NodeManagement tests cover single-operation success, duplicate IDs, missing parents, gate-off rejection, limits, and delete-with-references. Mixed dependent batches can expose ordering, rollback, and address-space consistency bugs.

**Spec reference:** OPC UA Part 4 §5.7 `NodeManagement` services; Part 3 address-space reference consistency rules.

**Implementation sketch:** Rust integration test against `SimpleNodeManager` with `clients_can_modify_address_space=true`, then browse/read all involved IDs after the batch to assert final graph invariants.
