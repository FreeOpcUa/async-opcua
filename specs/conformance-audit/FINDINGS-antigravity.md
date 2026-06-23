# OPC UA Part 4 "Services" Conformance Audit Findings (v1.05.07)

This audit evaluates the conformance of the Rust server implementation in `async-opcua` against the normative requirements of OPC UA Part 4 "Services" version 1.05.07. 

---

## Numbered Summary of Actionable Candidate Divergences

1. **Discovery URL Hostname Hardcoding**: The server hardcodes `self.config.tcp_config.host` for returned endpoint descriptions, ignoring the connect URL hostname provided by the client in `GetEndpoints` and `FindServers` (diverging from §5.5.2.1/§5.5.4.1).
2. **RegisterServer / RegisterServer2 Client Certificate Authentication Bypass**: Registrations are accepted in `apply_register_server` without checking client authentication or validating that the `serverUri` matches the `applicationUri` in the client certificate (diverging from §5.5.5.1/§5.5.6.1).
3. **Session Limit Denies New Connections Instead of Reclaiming Unactivated Sessions**: The server returns `BadTooManySessions` immediately when the session limit is hit, failing to terminate the oldest unactivated session as required (diverging from §5.7.2.1).
4. **Brittle SAN Validation in Client Certificates**: Client certificate URI verification in `is_application_uri_valid` only checks the *first* Subject Alternative Name (SAN), triggering false mismatches/denials if other SANs are present (diverging from §5.7.2.1).
5. **Session is Not Closed on Unactivated Request**: The server returns a service fault error for requests on unactivated sessions but fails to close the session (diverging from §5.7.3.1).
6. **Cross-Channel Transfer Validation Gaps**: When transferring a session to a new secure channel, the server fails to verify that the `ClientUserId` matches the current session token, and that the `SecurityPolicy` and `SecurityMode` match the original channel (diverging from §5.7.3.1).
7. **Anonymous Token Cross-Channel Transfer Signing Check Bypass**: Anonymous transfer over a new secure channel is not rejected when the new channel uses `Sign` mode (diverging from §5.7.3.1).
8. **Cancel Service Unimplemented**: The `Cancel` request is not implemented and falls back to a wildcard unsupported service handler (diverging from §5.7.5.1).
9. **AddNodes BrowseName Uniqueness Validation Missing**: Sibling `BrowseName` duplicates under the same parent/relationship are not validated or rejected with `Bad_BrowseNameDuplicated` (diverging from §5.8.2.4 Table 24).
10. **AddNodes Lacks User Privilege Checks**: The server only checks a global `clients_can_modify_address_space` flag, failing to perform user role/token privilege checks and return `Bad_UserAccessDenied` (diverging from §5.8.2.4 Table 24).
11. **DeleteNodes Target Reference Deletion Stubbed**: The `delete_node_references` method is an empty stub, meaning target references pointing to a deleted node are not cleaned up, violating target reference deletion rules (diverging from §5.8.4.1).
12. **RegisterNodes Response Array Size/Order Mismatch**: Unregistered nodes are filtered out of the response list, producing a shorter/mismatched array instead of returning the original `NodeId` for unoptimized nodes (diverging from Table 43).
13. **QueryFirst Lack of TypeDefinition Validation**: The server does not validate if `typeDefinitionNode` in `NodeTypeDescription` refers to a valid type definition, silently falling back to full traversal instead of returning `Bad_NotTypeDefinition` / `Bad_NodeIdUnknown` in `parsingResults` (diverging from Table B.6).
14. **IndexRange Parsing Failures abort entire Read/Write Request**: `NumericRange` syntax parsing is performed at the binary struct decoding level; a malformed string (e.g. "invalid-range") causes a decoding error that aborts the entire request instead of returning `Bad_IndexRangeInvalid` at the operation level (diverging from Table 49 / Table 55).
15. **IndexRange Multi-dimensional Hardcoded Limit**: Slicing is artificially limited to arrays with at most 10 dimensions, causing decoding errors for higher-dimensional arrays (diverging from §5.11.2).
16. **Call Service inputArgumentResults is Never Populated**: Per-argument status codes (e.g., `Bad_TypeMismatch` or `Bad_OutOfRange`) are not returned in the `inputArgumentResults` array; the typed method adapter reports argument mismatches as operation-level `BadInvalidArgument` errors (diverging from Table 61/62).
17. **TransferSubscriptions Good_SubscriptionTransferred and Lifetime Reset Missing**: The server does not issue a `StatusChangeNotification` with `Good_SubscriptionTransferred` to the old session, and the lifetime counter is not reset upon a successful transfer (diverging from §5.14.7.1).

---

## Service-Set Conformance Tables

### 1. Discovery Service Set
| Rule | Spec §/Table | Impl file:line | Status | Notes (spec-vs-code) |
| :--- | :--- | :--- | :--- | :--- |
| **GetEndpoints URL match** | §5.5.4.1 | [info.rs:472-478](file:///home/quackdcs/async-opcua/async-opcua-server/src/info.rs#L472-L478) | **DIVERGENCE** | Configured `host` is hardcoded in base endpoint rather than adapting to client's connect URL. |
| **FindServers URL match** | §5.5.2.1 | [info.rs:472-478](file:///home/quackdcs/async-opcua/async-opcua-server/src/info.rs#L472-L478) | **DIVERGENCE** | Same URL hardcoding as `GetEndpoints`. |
| **RegisterServer validation** | §5.5.5.1 | [info.rs:209-230](file:///home/quackdcs/async-opcua/async-opcua-server/src/info.rs#L209-L230) | **DIVERGENCE** | No client authentication/certificate validation is performed against the `serverUri`. |
| **RegisterServer2 validation** | §5.5.6.1 | [info.rs:209-230](file:///home/quackdcs/async-opcua/async-opcua-server/src/info.rs#L209-L230) | **DIVERGENCE** | Same lack of client certificate verification as `RegisterServer`. |

### 2. SecureChannel Service Set
| Rule | Spec §/Table | Impl file:line | Status | Notes (spec-vs-code) |
| :--- | :--- | :--- | :--- | :--- |
| **Nonce Length Check** | §5.6.2.3 Table 12 | [secure_channel.rs:481-503](file:///home/quackdcs/async-opcua/async-opcua-core/src/comms/secure_channel.rs#L481-L503) | **HONORED** | Nonce length validated against the security policy's required length. |
| **Duplicate Nonce Check** | §5.6.2.3 Table 12 | [controller.rs:837-846](file:///home/quackdcs/async-opcua/async-opcua-server/src/session/controller.rs#L837-L846) | **HONORED** | Renewal requests verify that the client nonce has not been reused. |
| **CloseSecureChannel** | §5.6.3 | [controller.rs:396](file:///home/quackdcs/async-opcua/async-opcua-server/src/session/controller.rs#L396) | **HONORED** | Socket is closed immediately without sending a response, conforming to TCP binary mapping. |

### 3. Session Service Set
| Rule | Spec §/Table | Impl file:line | Status | Notes (spec-vs-code) |
| :--- | :--- | :--- | :--- | :--- |
| **Session Reclaim** | §5.7.2.1 | [manager.rs:214-216](file:///home/quackdcs/async-opcua/async-opcua-server/src/session/manager.rs#L214-L216) | **DIVERGENCE** | Returns `BadTooManySessions` directly instead of closing the oldest unactivated session. |
| **Client Description URI match** | §5.7.2.1 | [x509.rs:1149](file:///home/quackdcs/async-opcua/async-opcua-crypto/src/x509.rs#L1149) | **DIVERGENCE** | Only compares client URI against the *first* Subject Alternative Name (SAN) of the certificate. |
| **Unactivated Session Request** | §5.7.3.1 | [controller.rs:593-616](file:///home/quackdcs/async-opcua/async-opcua-server/src/session/controller.rs#L593-L616) | **DIVERGENCE** | Returns an error but fails to close the session upon receiving a request before activation. |
| **Cross-channel transfer validation** | §5.7.3.1 | [manager.rs:670-699](file:///home/quackdcs/async-opcua/async-opcua-server/src/session/manager.rs#L670-L699) | **DIVERGENCE** | Does not verify matching `ClientUserId`, security policy, or security mode. |
| **Anonymous Token Mode Check** | §5.7.3.1 | [manager.rs:670-699](file:///home/quackdcs/async-opcua/async-opcua-server/src/session/manager.rs#L670-L699) | **DIVERGENCE** | Anonymous session transfer is not checked/prevented from using `Sign` mode. |
| **Cancel Service** | §5.7.5 | [message_handler.rs:355](file:///home/quackdcs/async-opcua/async-opcua-server/src/session/message_handler.rs#L355) | **DIVERGENCE** | Entirely unimplemented, falling back to wildcard `BadServiceUnsupported`. |

### 4. NodeManagement Service Set
| Rule | Spec §/Table | Impl file:line | Status | Notes (spec-vs-code) |
| :--- | :--- | :--- | :--- | :--- |
| **BrowseName Uniqueness** | §5.8.2.4 Table 24 | [memory_mgr_impl.rs:56-130](file:///home/quackdcs/async-opcua/async-opcua-server/src/node_manager/memory/memory_mgr_impl.rs#L56-L130) | **DIVERGENCE** | Dup BrowseNames among siblings under the same relationship are not validated/rejected. |
| **User Authorization** | §5.8.2.4 Table 24 | [memory_mgr_impl.rs:61](file:///home/quackdcs/async-opcua/async-opcua-server/src/node_manager/memory/memory_mgr_impl.rs#L61) | **DIVERGENCE** | Privilege checks are missing; relies purely on a global configuration flag. |
| **Delete Target References** | §5.8.4.1 | [memory_mgr_impl.rs:821-827](file:///home/quackdcs/async-opcua/async-opcua-server/src/node_manager/memory/memory_mgr_impl.rs#L821-L827) | **DIVERGENCE** | `delete_node_references` is an empty stub; target references are not cleaned up. |

### 5. View Service Set
| Rule | Spec §/Table | Impl file:line | Status | Notes (spec-vs-code) |
| :--- | :--- | :--- | :--- | :--- |
| **Browse** | §5.9.2 | [view.rs:21-100](file:///home/quackdcs/async-opcua/async-opcua-server/src/session/services/view.rs#L21-L100) | **HONORED** | Dispatches to node managers and handles continuation points. |
| **BrowseNext** | §5.9.3 | [view.rs:163](file:///home/quackdcs/async-opcua/async-opcua-server/src/session/services/view.rs#L163) | **HONORED** | Browses next batch using stored continuation points. |
| **TranslateBrowsePathsToNodeIds** | §5.9.4 | [view.rs:374-475](file:///home/quackdcs/async-opcua/async-opcua-server/src/session/services/view.rs#L374-L475) | **HONORED** | Resolves relative paths through address space; notes lack of external server references. |
| **RegisterNodes Array Size/Order** | §5.9.5 Table 43 | [view.rs:521](file:///home/quackdcs/async-opcua/async-opcua-server/src/session/services/view.rs#L521) / [view.rs:744-751](file:///home/quackdcs/async-opcua/async-opcua-server/src/node_manager/view.rs#L744-L751) | **DIVERGENCE** | Drops unregistered/unoptimized nodes from response list, producing size/order mismatches. |
| **UnregisterNodes** | §5.9.6 | [view.rs:533-582](file:///home/quackdcs/async-opcua/async-opcua-server/src/session/services/view.rs#L533-L582) | **HONORED** | Unregisters nodes from node managers without erroring for unknown/unregistered inputs. |

### 6. Query Service Set
| Rule | Spec §/Table | Impl file:line | Status | Notes (spec-vs-code) |
| :--- | :--- | :--- | :--- | :--- |
| **QueryFirst Type Validation** | Annex B.2.3 Table B.6 | [handlers.rs:153-180](file:///home/quackdcs/async-opcua/async-opcua-server/src/services/query/handlers.rs#L153-L180) | **DIVERGENCE** | Fails to validate `typeDefinitionNode`; silently falls back to full traversal instead of returning `Bad_NotTypeDefinition` or `Bad_NodeIdUnknown`. |
| **QueryNext** | Annex B.2.4 | [query.rs:151-214](file:///home/quackdcs/async-opcua/async-opcua-server/src/session/services/query.rs#L151-L214) | **HONORED** | Resumes query from continuation points or releases them. |

### 7. Attribute Service Set
| Rule | Spec §/Table | Impl file:line | Status | Notes (spec-vs-code) |
| :--- | :--- | :--- | :--- | :--- |
| **IndexRange Validation** | §5.11.2.4 Table 49 / Table 55 | [numeric_range.rs:94](file:///home/quackdcs/async-opcua/async-opcua-types/src/numeric_range.rs#L94) | **DIVERGENCE** | Malformed IndexRange strings abort the entire request during decoding instead of returning `Bad_IndexRangeInvalid` at the operation level. |
| **IndexRange Dimensions** | §5.11.2 | [numeric_range.rs:222-253](file:///home/quackdcs/async-opcua/async-opcua-types/src/numeric_range.rs#L222-L253) | **DIVERGENCE** | Restricts multi-dimensional array index ranges to 10 dimensions. |
| **Read / Write** | §5.11.2 / §5.11.4 | [attribute.rs:15](file:///home/quackdcs/async-opcua/async-opcua-server/src/session/services/attribute.rs#L15) / [attribute.rs:114](file:///home/quackdcs/async-opcua/async-opcua-server/src/session/services/attribute.rs#L114) | **HONORED** | Reads and writes values from/to address space. |
| **HistoryRead** | §5.11.3 | [attribute.rs:232](file:///home/quackdcs/async-opcua/async-opcua-server/src/session/services/attribute.rs#L232) | **HONORED** | Delegates history reads to node managers. |
| **HistoryUpdate** | §5.11.5 | [attribute.rs:290](file:///home/quackdcs/async-opcua/async-opcua-server/src/session/services/attribute.rs#L290) | **HONORED** | Delegates history updates to node managers. |

### 8. Method Service Set
| Rule | Spec §/Table | Impl file:line | Status | Notes (spec-vs-code) |
| :--- | :--- | :--- | :--- | :--- |
| **inputArgumentResults** | §5.12.2.4 Table 61/62 | [method.rs:95](file:///home/quackdcs/async-opcua/async-opcua-server/src/node_manager/method.rs#L95) / [method_typed.rs](file:///home/quackdcs/async-opcua/async-opcua-server/src/node_manager/method_typed.rs) | **DIVERGENCE** | `inputArgumentResults` is never populated; argument mismatches are reported as operation-level status codes only. |

### 9. MonitoredItem Service Set
| Rule | Spec §/Table | Impl file:line | Status | Notes (spec-vs-code) |
| :--- | :--- | :--- | :--- | :--- |
| **Queue Overflow Discard Policy** | §5.13.1.5 | [monitored_item.rs:596-624](file:///home/quackdcs/async-opcua/async-opcua-server/src/subscriptions/monitored_item.rs#L596-L624) | **HONORED** | Respects discard policy and sets overflow status bit on oldest remaining element. |
| **SetTriggering** | §5.13.5 | [message_handler.rs:570-590](file:///home/quackdcs/async-opcua/async-opcua-server/src/session/message_handler.rs#L570-L590) | **HONORED** | Updates linking of triggering items. |
| **Create/Modify/Delete** | §5.13.2-§5.13.4 | [monitored_items.rs](file:///home/quackdcs/async-opcua/async-opcua-server/src/session/services/monitored_items.rs) | **HONORED** | Manages monitored item lifecycles. |

### 10. Subscription Service Set
| Rule | Spec §/Table | Impl file:line | Status | Notes (spec-vs-code) |
| :--- | :--- | :--- | :--- | :--- |
| **TransferSubscriptions old-session Notification** | §5.14.7.1 | [mod.rs:743-830](file:///home/quackdcs/async-opcua/async-opcua-server/src/subscriptions/mod.rs#L743-L830) | **DIVERGENCE** | Never sends a `Good_SubscriptionTransferred` `StatusChangeNotification` to the old session. |
| **TransferSubscriptions Lifetime Reset** | §5.14.7.1 | [mod.rs:743-830](file:///home/quackdcs/async-opcua/async-opcua-server/src/subscriptions/mod.rs#L743-L830) / [session_subscriptions.rs:96-109](file:///home/quackdcs/async-opcua/async-opcua-server/src/subscriptions/session_subscriptions.rs#L96-L109) | **DIVERGENCE** | Lifetime counter is not reset on subscription transfer. |
| **State Table** | §5.14.1.2 Table 79 | [subscription.rs:387-497](file:///home/quackdcs/async-opcua/async-opcua-server/src/subscriptions/subscription.rs#L387-L497) | **HONORED** | State machine transitions correspond to Table 79. |
| **Create/Modify/Delete** | §5.14.2-§5.14.4 | [session_subscriptions.rs](file:///home/quackdcs/async-opcua/async-opcua-server/src/subscriptions/session_subscriptions.rs) | **HONORED** | Manages subscription parameters and limits. |
| **Publish / Republish** | §5.14.5-§5.14.6 | [session_subscriptions.rs:888](file:///home/quackdcs/async-opcua/async-opcua-server/src/subscriptions/session_subscriptions.rs#L888) / [retransmission_queue.rs](file:///home/quackdcs/async-opcua/async-opcua-server/src/subscriptions/retransmission_queue.rs) | **HONORED** | Manages publishing of notifications and retransmission queue sequence numbers. |
