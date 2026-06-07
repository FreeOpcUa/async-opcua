# Advanced OPC UA Compliance

This page documents the server service surface added for advanced OPC UA compliance: PubSub security keys, subscription event filtering, encrypted session secrets, and graph queries.

## Service Summary

| Area | OPC UA entry point | Rust modules | Notes |
| --- | --- | --- | --- |
| PubSub key distribution | `GetSecurityKeys` | `async-opcua-server/src/services/security.rs` | Returns current and future security keys for a registered PubSub security group. |
| Event filtering | `CreateMonitoredItems` with `EventFilter` | `async-opcua-server/src/services/subscription/` | Applies `SelectClauses` and `WhereClause` predicates before event notification. |
| Encrypted credentials | `ActivateSession` | `async-opcua-server/src/session/negotiate.rs` | Decrypts RSA-OAEP encrypted identity-token secrets and tarpits failed validation. |
| Graph queries | `QueryFirst`, `QueryNext` | `async-opcua-server/src/services/query/` | Filters address-space nodes by type, properties, and related-node joins with pagination. |

## PubSub `GetSecurityKeys`

`GetSecurityKeys` is backed by `SecurityKeyService`, an in-memory registry keyed by PubSub security group id. Register group material with `SecurityKeyService::register_security_group` before handling requests.

Request fields:

- `security_group_id`: security group identifier.
- `starting_token_id`: first requested token id; `CURRENT_SECURITY_TOKEN_ID` (`0`) requests the current key.
- `requested_key_count`: number of keys requested.

Response fields:

- `security_policy_uri`: policy URI for the returned key material.
- `first_token_id`: token id associated with the first returned key.
- `keys`: ordered key bytes beginning at `first_token_id`.
- `time_to_next_key`: milliseconds until the current key expires.
- `key_lifetime`: key validity period in milliseconds.

Failure behavior:

- Empty group ids or `requested_key_count == 0` return `BadInvalidArgument`.
- Unknown groups or token ids outside the registered range return `BadNotFound`.
- If fewer keys are available than requested, the response returns the available suffix.

```rust
use std::time::Duration;

use opcua_server::services::security::{
    GetSecurityKeysRequest, SecurityGroupKeys, SecurityKeyService, CURRENT_SECURITY_TOKEN_ID,
};
use opcua_types::ByteString;

let service = SecurityKeyService::new();
let group = SecurityGroupKeys::new(
    "http://opcfoundation.org/UA/SecurityPolicy#Aes128_Sha256_RsaOaep",
    7,
    vec![ByteString::from(vec![0; 16]), ByteString::from(vec![1; 16])],
    Duration::from_secs(3600),
)?;

service.register_security_group("group-1", group)?;
let response = service.get_security_keys(GetSecurityKeysRequest::new(
    "group-1",
    CURRENT_SECURITY_TOKEN_ID,
    2,
))?;
```

## Subscription `EventFilter`

Event filtering is exposed through `CreateMonitoredItems` by placing an OPC UA `EventFilter` extension object in `MonitoredItemCreateRequest.requested_parameters.filter`.

Supported behavior:

- `SelectClauses` extract event fields in client-requested order.
- `WhereClause` evaluation supports the parsed `ContentFilter` boolean and comparison operators used by event predicates, including `And`, `Or`, `Not`, `GreaterThan`, `GreaterThanOrEqual`, and `Equals`.
- `InView` and `RelatedTo` are rejected for subscription event filters.
- Unsupported filter types return `BadFilterNotAllowed`.
- Invalid select clauses return per-clause statuses and `BadMonitoredItemFilterUnsupported`.
- Unsupported where operators return `BadFilterOperatorUnsupported` in the content-filter result and map to `BadMonitoredItemFilterUnsupported`.

Field access is validated against the event type tree. Unauthorized selected fields are returned as `BadUserAccessDenied` values in the event field list. Unauthorized fields used in a where clause prevent the event from being delivered.

## `ActivateSession` Encrypted Secrets

`ActivateSession` accepts identity-token secrets encrypted with standard RSA-OAEP algorithms. This extends the existing service; it is not a separate OPC UA endpoint.

Handling rules:

- An empty encryption algorithm keeps the secret as raw bytes.
- Legacy OPC UA encrypted secrets are still handled by the legacy decrypt path.
- RSA-OAEP encrypted secrets are accepted when the algorithm URI matches the asymmetric encryption algorithm for `Basic256Sha256`, `Aes128Sha256RsaOaep`, or `Aes256Sha256RsaPss`.
- Deprecated secure-channel policies return `BadSecurityPolicyRejected` unless legacy crypto is explicitly enabled.
- Failed encrypted identity-token validation waits 100 ms with `tokio::time::sleep` and then returns `BadUserAccessDenied`.

## Graph Query Services

`QueryFirst` and `QueryNext` execute address-space graph queries over node managers that implement query support.

`QueryFirst` request fields:

- `view`: current implementation rejects non-default views with `BadViewIdUnknown`.
- `node_types`: optional `NodeTypeDescription` list used to match type definitions and subtypes.
- `filter`: OPC UA `ContentFilter` used for node property criteria and relationship joins.
- `max_data_sets_to_return`: `0` uses the server operational limit.
- `max_references_to_return`: `0` uses the server operational limit.

`QueryFirst` behavior:

- Parses node type descriptions and returns `BadInvalidArgument` with parsing results if they are invalid.
- Parses the content filter and returns the filter result if parsing fails.
- Matches nodes by type, property filters, and `RelatedTo` graph joins.
- Enforces read authorization before returning a node.
- Returns selected values as `QueryDataSet` entries; unreadable selected values are represented as status-code variants.
- Returns a continuation point when more matching data sets remain.

`QueryNext` behavior:

- Consumes the continuation point returned by `QueryFirst` or a previous `QueryNext`.
- `release_continuation_point == true` releases server state and returns `Good` with a null continuation point.
- Invalid continuation points return `BadContinuationPointInvalid`.
- A revised continuation point is returned when another page remains.

```rust
let first = client.query_first(QueryFirstRequest {
    node_types: Some(vec![node_type_description]),
    max_data_sets_to_return: 100,
    max_references_to_return: 0,
    ..Default::default()
}).await?;

if !first.continuation_point.is_null() {
    let next = client.query_next(QueryNextRequest {
        release_continuation_point: false,
        continuation_point: first.continuation_point,
        ..Default::default()
    }).await?;
}
```
