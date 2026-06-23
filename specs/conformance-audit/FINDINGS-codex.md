# OPC UA Part 4 1.05.07 Server Conformance Findings

Scope: static audit of the Rust server crate against OPC UA Part 4 "Services" v1.05.07 using `/tmp/part4.txt` as authoritative text. Existing `FINDINGS*.md` files were not read. No build, test, or git commands were run.

## Candidate Divergence Summary

1. **RegisterServer does not validate required ServerName, discoveryUrls, or semaphoreFile fields.** Part 4 Table 7 defines `Bad_ServerNameMissing`, `Bad_DiscoveryUrlMissing`, and `Bad_SemaphoreFileMissing`; implementation only rejects missing `server_uri` and capacity before inserting/removing registrations.
2. **RegisterServer2 inherits the same missing RegisteredServer validation.** Part 4 Table 9 repeats the RegisterServer validation result codes, but `RegisterServer2` delegates to the same `apply_register_server` path.
3. **OpenSecureChannel may return a zero revisedLifetime.** Part 4 §5.6.2.2 requires the Server to provide a lifetime greater than 0; implementation uses `min(config_max, requested_lifetime)` with no lower bound.
4. **OpenSecureChannel Renew before Issue returns an unexpected/internal error path instead of the SecureChannel-specific invalid-id result.** Part 4 Table 12 defines `Bad_SecureChannelIdInvalid`; implementation returns `BadUnexpectedError` for a RENEW on a channel that has never issued a token.
5. **CreateSession does not enforce the Part 4 clientNonce upper bound.** Part 4 Table 16 requires `Bad_NonceInvalid` if client nonce length is less than 32 bytes or greater than 128 bytes; implementation checks only a configurable lower bound for non-None security policies.
6. **BrowseNext with releaseContinuationPoints=TRUE returns one BrowseResult per continuation point.** Part 4 Table 37 says passed continuation points are released and the `results` and `diagnosticInfos` arrays are empty.
7. **TranslateBrowsePathsToNodeIds accepts a RelativePath element with a missing targetName as a wildcard.** Part 4 Table 40 says the last RelativePath element shall have a targetName and the Server shall return `Bad_BrowseNameInvalid` if missing.
8. **Call maps non-executable Methods to `Bad_UserAccessDenied` instead of `Bad_NotExecutable`.** Part 4 Table 61 reserves `Bad_NotExecutable` for the executable Attribute not allowing execution.
9. **CreateMonitoredItems accepts `TimestampsToReturn::Invalid`.** Part 4 Table 64 defines `Bad_TimestampsToReturnInvalid`; implementation passes the value into monitored items, where `Invalid` is treated like `Neither`.
10. **ModifyMonitoredItems accepts `TimestampsToReturn::Invalid`.** Part 4 Table 67 defines `Bad_TimestampsToReturnInvalid`; implementation updates monitored items with the invalid enum without service-level rejection.
11. **SetMonitoringMode accepts an invalid MonitoringMode.** Part 4 Table 70 defines `Bad_MonitoringModeInvalid`; implementation stores the supplied mode without validation.

## Discovery Service Set

| Rule | Spec §/Table | Impl file:line | Status | Notes |
|---|---|---|---|---|
| FindServers shall ignore authenticationToken and return servers filtered by endpointUrl, localeIds, and serverUris. | §5.5.2.2 Table 3 | async-opcua-server/src/session/controller.rs:467 | HONORED | Handler builds local + registered server descriptions, applies endpoint/locale matching via `matches_find_servers_filters`, then applies `server_uris` filtering at controller.rs:483. Authentication token is not consulted in this discovery path. |
| GetEndpoints shall filter by endpointUrl, localeIds, and profileUris and can return empty list if no match. | §5.5.4.2 Table 5 | async-opcua-server/src/session/controller.rs:449 | HONORED | Controller calls `endpoints_with_filters` with endpoint URL, profile URIs, and locale IDs and returns `GetEndpointsResponse`. |
| RegisterServer service result codes include `Bad_ServerNameMissing`, `Bad_DiscoveryUrlMissing`, and `Bad_SemaphoreFileMissing`. | §5.5.5.3 Table 7 | async-opcua-server/src/info.rs:209 | DIVERGENCE | `apply_register_server` validates only `server_uri` null/empty and registry capacity, then inserts the server at info.rs:228. No validation of server name, discovery URLs, or semaphore file is present in this path. |
| RegisterServer2 service result codes include RegisterServer validation plus per-configuration `Bad_NotSupported`. | §5.5.6.3 Table 9; §5.5.6.4 Table 10 | async-opcua-server/src/session/controller.rs:548 | DIVERGENCE | Controller delegates registered-server validation to `apply_register_server` at controller.rs:550, so it misses the same required field checks. It does return `BadNotSupported` per discovery configuration at controller.rs:551. |

## SecureChannel Service Set

| Rule | Spec §/Table | Impl file:line | Status | Notes |
|---|---|---|---|---|
| OpenSecureChannel shall reject invalid security mode. | §5.6.2.3 Table 12 | async-opcua-server/src/session/controller.rs:858 | HONORED | Invalid `MessageSecurityMode` returns a ServiceFault with `BadSecurityModeRejected` at controller.rs:860. |
| OpenSecureChannel shall check nonce length for non-None SecurityPolicy and duplicate nonce on Renew. | §5.6.2.3 Table 12 | async-opcua-server/src/session/controller.rs:835; async-opcua-core/src/comms/secure_channel.rs:480 | HONORED | Duplicate nonce on Renew returns `BadNonceInvalid`; nonce length is delegated to `validate_secure_channel_nonce_length`, which compares against policy nonce length for non-None policies. |
| Revised SecurityToken lifetime shall be greater than 0. | §5.6.2.2 Table 11 | async-opcua-server/src/session/controller.rs:881 | DIVERGENCE | `revised_lifetime` is `max_secure_channel_token_lifetime_ms.min(request.requested_lifetime)` and is returned directly at controller.rs:916. A request lifetime of 0 can produce a 0 revised lifetime. |
| Renew for an invalid/non-issued SecureChannel shall return SecureChannel-specific invalid-id status. | §5.6.2.3 Table 12 | async-opcua-server/src/session/controller.rs:848 | DIVERGENCE | If a RENEW arrives before any token was issued, implementation returns `Err(StatusCode::BadUnexpectedError)` at controller.rs:851, not `BadSecureChannelIdInvalid`. |
| CloseSecureChannel terminates the channel. | §5.6.3 | async-opcua-server/src/session/controller.rs:396 | HONORED | CloseSecureChannel maps directly to `RequestProcessResult::Close`. Signature verification is in the transport/security stack and was not fully audited here. |

## Session Service Set

| Rule | Spec §/Table | Impl file:line | Status | Notes |
|---|---|---|---|---|
| CreateSession shall reject too many sessions. | §5.7.2.3 Table 16 | async-opcua-server/src/session/manager.rs:214 | HONORED | Session count and unactivated-per-channel limits return `BadTooManySessions`. |
| CreateSession shall return `Bad_NonceInvalid` if client nonce length is less than 32 bytes or greater than 128 bytes. | §5.7.2.3 Table 16 | async-opcua-server/src/session/manager.rs:249 | DIVERGENCE | Code checks only `request.client_nonce.len() < self.info.config.session_nonce_length` for non-None policies. Default is 32 at config/server.rs:457, but there is no upper-bound rejection for values greater than 128. |
| ActivateSession shall prove same client application and rotate server nonce. | §5.7.3.1; Table 18 | async-opcua-server/src/session/manager.rs:611; async-opcua-server/src/session/manager.rs:704 | HONORED | Non-None security verifies client signature before activation and `session.activate` stores a new nonce. |
| User identity changes shall cause permissions of all MonitoredItems to be re-evaluated. | §5.7.3.1 | async-opcua-server/src/session/manager.rs:765; async-opcua-server/src/session/message_handler.rs:489 | HONORED | On user change, handler revalidates monitored items and deletes items that become `BadUserAccessDenied` or `BadNotReadable`. |
| CloseSession before activation shall reject if SecureChannel differs from CreateSession channel. | §5.7.4.1; Table 20 | async-opcua-server/src/session/manager.rs:523 | HONORED | Inactive sessions with mismatched channel return `BadSecureChannelIdInvalid`. |
| Cancel shall cancel outstanding service requests and return cancelCount. | §5.7.5 | async-opcua-server/src/session/message_handler.rs | UNCERTAIN | The scoped dispatch excerpt did not show a `CancelRequest` handler in `message_handler.rs`; this audit did not prove whether cancellation is implemented elsewhere in the controller or transport. |

## NodeManagement Service Set

| Rule | Spec §/Table | Impl file:line | Status | Notes |
|---|---|---|---|---|
| AddNodes/AddReferences/DeleteNodes/DeleteReferences shall return `Bad_NothingToDo` and `Bad_TooManyOperations` as service results. | Tables 23, 26, 29, 33 | async-opcua-server/src/session/services/mod.rs:1 | HONORED | `take_service_items!` returns `BadNothingToDo` for null/empty lists and `BadTooManyOperations` for configured limit excess. |
| AddNodes operation-level result list size/order shall match request list. | §5.8.2.2 Table 22 | async-opcua-server/src/session/services/node_management.rs:37 | HONORED | Wrapper maps each input into `AddNodeItem`, delegates per owning node manager, then `consume_results` preserves result collection. |
| DeleteNodes shall attempt to delete target references when requested. | §5.8.4.2 Table 28 | async-opcua-server/src/session/services/node_management.rs:243; async-opcua-server/src/address_space/mod.rs:489 | HONORED | After successful node deletion, wrapper calls `delete_node_references`; address-space delete receives `delete_target_references`. |
| Full operation-level code coverage for all node management table entries. | Tables 24, 27, 30, 34 | async-opcua-server/src/node_manager/memory/memory_mgr_impl.rs:56 | UNCERTAIN | The service wrappers preserve operation-level results, but this static pass did not enumerate every memory node-manager validation branch for every table code. |

## View And Query Service Sets

| Rule | Spec §/Table | Impl file:line | Status | Notes |
|---|---|---|---|---|
| Browse shall return view-specific service errors for unsupported/unknown ViewDescription. | §5.9.2.3 Table 35 | async-opcua-server/src/session/services/view.rs:31 | HONORED | Non-null view id or timestamp returns `BadViewIdUnknown`. |
| BrowseNext releaseContinuationPoints=TRUE shall release points and return empty results and diagnosticInfos arrays. | §5.9.3.2 Table 37 | async-opcua-server/src/session/services/view.rs:199 | DIVERGENCE | Code removes points first and then returns a `BrowseResult` per requested continuation point, with `Good` for valid points or `BadContinuationPointInvalid` for missing ones. |
| TranslateBrowsePathsToNodeIds shall reject missing final targetName with `Bad_BrowseNameInvalid`. | §5.9.4.2 Table 40; Table 42 | async-opcua-server/src/node_manager/memory/mod.rs:423 | DIVERGENCE | Translation accepts `element.target_name.is_null()` as a match condition, effectively treating missing targetName as wildcard instead of operation-level `BadBrowseNameInvalid`. |
| RegisterNodes shall not validate unknown NodeIds and shall return the input NodeId if no optimization is supported. | §5.9.5.1 | async-opcua-server/src/session/services/view.rs:495; async-opcua-server/src/session/services/view.rs:521 | HONORED | Items are initialized for every input and only owned nodes are optimized; final response uses each item result, allowing unchanged input NodeIds for unsupported optimization. |
| QueryFirst invalid filter/nodeTypes shall return Service result plus parsing/filter results. | Annex B Table B.5/B.6 | async-opcua-server/src/session/services/query.rs:44; async-opcua-server/src/session/services/query.rs:56 | HONORED | Parser accumulates node-type parsing results and content-filter result; bad status returns `QueryFirstResponse` with service result and those diagnostics. |
| QueryNext releaseContinuationPoint=TRUE should return empty array parameters. | Annex B Table B.7 | async-opcua-server/src/session/services/query.rs:156 | UNCERTAIN | Code removes the continuation point before checking release and returns `query_data_sets: None` at query.rs:169. Whether this encodes as an empty array for this generated type was not verified. |

## Attribute Service Set

| Rule | Spec §/Table | Impl file:line | Status | Notes |
|---|---|---|---|---|
| Read service result codes include `Bad_NothingToDo`, `Bad_TooManyOperations`, `Bad_MaxAgeInvalid`, and `Bad_TimestampsToReturnInvalid`. | §5.11.2.3 Table 48 | async-opcua-server/src/session/services/attribute.rs:24; async-opcua-server/src/session/services/attribute.rs:29 | HONORED | Wrapper uses `take_service_items!`, rejects negative maxAge, and rejects invalid timestampsToReturn. Actor path repeats these checks at message_handler.rs:625. |
| Read operation-level errors include node id, attribute id, index range, readability, user access, and security mode errors. | §5.11.2.4 Table 49 | async-opcua-server/src/address_space/mod.rs:455; async-opcua-server/src/address_space/utils.rs:91 | HONORED | Address-space validation maps missing node to `BadNodeIdUnknown`; utils validate access, attribute/data encoding/range, and return DataValue status codes per operation. |
| Read DataValue timestamps follow TimestampsToReturn for Variable Value Attribute. | §5.11.2.2 Table 47 | async-opcua-server/src/address_space/utils.rs:355 | HONORED | Only Variable Value reads attach source/server timestamps according to Source/Server/Both/Neither. |
| Write service result codes include `Bad_NothingToDo` and `Bad_TooManyOperations`; operation-level write validation includes type and writability. | §5.11.4 Tables 53-55 | async-opcua-server/src/session/message_handler.rs:721; async-opcua-server/src/address_space/utils.rs:256 | HONORED | Actor write path checks request list and limits; address-space utils validate writable attribute, index-range support for non-Value attributes, and value type. |
| HistoryRead rejects invalid timestampsToReturn including Neither. | §5.11.3.2 Table 50; Table 51 | async-opcua-server/src/session/services/attribute.rs:95 | UNCERTAIN | The wrapper validates list/detail/limits but no explicit `TimestampsToReturn::Neither` or `Invalid` rejection was found in the shown handler before dispatch to node managers. |
| History access respects AccessLevel/EventNotifier bits. | §5.11.3.1; §5.11.5.1 | async-opcua-server/src/node_manager/memory/mod.rs:455; async-opcua-server/src/node_manager/memory/mod.rs:507 | HONORED | History read/write validators check event notifier bits for events and `HISTORY_READ`/`HISTORY_WRITE` user access levels for variables. |

## Method Service Set

| Rule | Spec §/Table | Impl file:line | Status | Notes |
|---|---|---|---|---|
| Call service result codes include `Bad_NothingToDo` and `Bad_TooManyOperations`. | §5.12.2.3 Table 60 | async-opcua-server/src/session/services/method.rs:17 | HONORED | `take_service_items!` handles null/empty/limit. |
| Method must be a HasComponent of the object/object type. | §5.12.2.2 Table 59; Table 61 | async-opcua-server/src/node_manager/memory/mod.rs:550 | HONORED | Validator searches HasComponent references from object to method and returns `BadMethodInvalid` if not found or target is not a Method. |
| Non-executable Method shall return `Bad_NotExecutable`. | §5.12.2.4 Table 61 | async-opcua-server/src/node_manager/memory/mod.rs:573 | DIVERGENCE | If `user_executable` is false or authenticator denies execution, code returns `BadUserAccessDenied`. The executable Attribute case should be `BadNotExecutable`; user permission denial can remain `BadUserAccessDenied`. |
| Too many input arguments shall return `Bad_TooManyArguments`. | §5.12.2.4 Table 61 | async-opcua-server/src/node_manager/memory/mod.rs:646 | HONORED | If the client provides more arguments than defined, validator sets `BadTooManyArguments`. |
| Missing non-optional input arguments and per-argument result detail. | §5.12.2.4 Tables 61-62 | async-opcua-server/src/node_manager/method.rs:40 | UNCERTAIN | `MethodCall` supports `set_argument_error`, but the generic memory validator did not show optional/non-optional argument metadata handling in this pass. |

## MonitoredItem Service Set

| Rule | Spec §/Table | Impl file:line | Status | Notes |
|---|---|---|---|---|
| Create/Modify/Delete/SetMonitoringMode shall return `Bad_NothingToDo` and `Bad_TooManyOperations` for empty or excessive item lists. | Tables 64, 67, 70, 76 | async-opcua-server/src/session/services/monitored_items.rs:154; async-opcua-server/src/session/services/monitored_items.rs:310 | HONORED | Service wrappers use `take_service_items!` for monitored-item lists. |
| CreateMonitoredItems shall reject invalid timestampsToReturn. | §5.13.2.3 Table 64 | async-opcua-server/src/session/services/monitored_items.rs:193; async-opcua-server/src/subscriptions/monitored_item.rs:547 | DIVERGENCE | Wrapper does not check `request.request.timestamps_to_return`; monitored-item notification handling treats `TimestampsToReturn::Invalid` like `Neither`. |
| ModifyMonitoredItems shall reject invalid timestampsToReturn. | §5.13.3.3 Table 67 | async-opcua-server/src/session/services/monitored_items.rs:320; async-opcua-server/src/subscriptions/monitored_item.rs:368 | DIVERGENCE | Wrapper passes invalid timestamp mode into `modify_monitored_items`; item stores it and later treats invalid as `Neither`. |
| SetMonitoringMode shall reject invalid monitoring mode. | §5.13.4.3 Table 70 | async-opcua-server/src/session/services/monitored_items.rs:382; async-opcua-server/src/subscriptions/monitored_item.rs:739 | DIVERGENCE | The supplied enum is passed through and assigned to each item with no `BadMonitoringModeInvalid` check. |
| Queue overflow shall set Overflow bit for data queues larger than one and ignore discard policy for queue size one. | §5.13.1.5 | async-opcua-server/src/subscriptions/monitored_item.rs:594 | HONORED | Queue full path sets overflow bit on retained/new data notification only when `queue_size > 1`; queue size one skips overflow bit and behaves as newest-value buffer. |
| SetTriggering shall remove links before adding links and return per-link invalid monitored item IDs. | §5.13.5; Table 73 | async-opcua-server/src/subscriptions/session_subscriptions.rs:434; async-opcua-server/src/subscriptions/monitored_item.rs:665 | HONORED | Links are pre-filtered to `BadMonitoredItemIdInvalid`; `set_triggering` removes before adding. |

## Subscription Service Set

| Rule | Spec §/Table | Impl file:line | Status | Notes |
|---|---|---|---|---|
| CreateSubscription revises publishing interval, lifetime count, keep-alive count and returns revised values. | §5.14.2 Tables 77-80 | async-opcua-server/src/subscriptions/session_subscriptions.rs:181 | HONORED | `revise_subscription_values` is used and response returns revised fields. |
| ModifySubscription resets lifetime/keep-alive counters and updates parameters. | Table 79 row 18; ModifySubscription tables | async-opcua-server/src/subscriptions/session_subscriptions.rs:220 | HONORED | Code updates interval, keep-alive, lifetime, priority, max notifications and resets counters. |
| SetPublishingMode resets lifetime counter and clears/handles publish mode per subscription. | Table 79 row 19 | async-opcua-server/src/subscriptions/session_subscriptions.rs:246 | HONORED | Each valid subscription updates publishing mode and resets lifetime counter. MoreNotifications reset is not directly visible and remains a residual uncertainty. |
| Publish acknowledgements delete acked NotificationMessages and return per-ack results. | §5.14.1.1; Publish tables | async-opcua-server/src/subscriptions/session_subscriptions.rs:917 | HONORED | Acks are processed when Publish is enqueued; valid ack reclaims the retransmission queue entry, invalid subscription/sequence return specific status. |
| Republish returns stored NotificationMessage or `Bad_MessageNotAvailable`. | Table 79 rows 20-21 | async-opcua-server/src/subscriptions/session_subscriptions.rs:275; async-opcua-server/src/subscriptions/session_subscriptions.rs:885 | HONORED | Republish resets lifetime counter and retrieves message from retransmission queue, otherwise returns `BadMessageNotAvailable`. |
| TransferSubscriptions validates equivalent user/session and moves queued NotificationMessages. | §5.14 TransferSubscriptions; Table 95 | async-opcua-server/src/subscriptions/mod.rs:743 | HONORED | Transfer checks current owner, validates equivalent transfer key/user token, removes from old session, inserts in new session, preserves available sequence numbers, and optionally resends data. |
| Table 79 lifetime/keep-alive state machine is implemented. | §5.14.1.2 Table 79 | async-opcua-server/src/subscriptions/subscription.rs:387 | HONORED | `get_state_transition` and `handle_state_transition` encode Normal/Late/KeepAlive transitions, lifetime expiry, keep-alive, and notification return paths. |
| DeleteSubscriptions deletes monitored items and per-subscription retransmission state. | Table 79 row 25; DeleteSubscriptions tables | async-opcua-server/src/session/services/subscriptions.rs:47; async-opcua-server/src/subscriptions/session_subscriptions.rs:506 | HONORED | Service deletes subscription, drains monitored item refs for node-manager cleanup, and removes retransmission queue entries. |

