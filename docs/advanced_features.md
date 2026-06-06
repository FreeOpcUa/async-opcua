# Advanced OPC UA Features

This repository includes focused support for higher-level OPC UA specifications:

- Alarms and Conditions: condition state machine nodes, event dispatch, and acknowledgment/confirm methods.
- Historical Data Access: backend trait, continuation points, permission checks, and SQLite reference storage.
- PubSub: JSON payloads, UADP messages, MQTT publishing, UDP multicast, and address-space bridge helpers.
- Programs: asynchronous Program state machine execution and client control helpers.
- Aggregates: average, time-weighted average, minimum, maximum, standard deviation, and quality calculation.
- GDS: registration, CSR exchange, cached fallback, and dynamic certificate reload.
- Companion NodeSets: runtime NodeSet loading and codegen tests for DI/PLCopen-style dependencies.
- OAuth2/FOTA: issued JWT validation before authentication and session-bound temporary FileType cleanup.

## OAuth2 JWT Tokens

Servers validate OPC UA `IssuedIdentityToken` values as compact JWTs before passing the normalized token to the configured `AuthManager`.

Validation rejects malformed tokens, `alg=none`, missing subject or expiration claims, expired tokens, not-yet-valid tokens, and future `iat` claims. Signature, issuer, audience, and user mapping remain the responsibility of the configured authenticator.

## Session-Bound FOTA Files

Use `opcua_server::fota::file_node::TemporaryFileNode` to create a temporary `FileType` object with standard properties and method nodes. Register the created node and optional backing file with `opcua_server::fota::cleanup` so close, timeout, or channel-drop cleanup removes session resources.

```rust
use std::sync::Arc;
use opcua_core::sync::RwLock;
use opcua_server::{
    address_space::AddressSpace,
    fota::{
        cleanup::register_session_file,
        file_node::{TemporaryFileNode, TemporaryFileNodeConfig},
    },
};
use opcua_types::NodeId;

let address_space = Arc::new(RwLock::new(AddressSpace::new()));
let session_id = NodeId::new(0, "session-1");

let file_node = {
    let mut space = address_space.write();
    TemporaryFileNode::create(
        &mut space,
        TemporaryFileNodeConfig::new(2, session_id.clone(), "firmware.bin"),
    )?
};

register_session_file(session_id, &address_space, &file_node, None);
```
