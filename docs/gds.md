# Global Discovery Server (GDS) Certificate Management

The OPC UA Global Discovery Server (Part 12) implementation enables automated enrollment, discovery directory registration, and zero-downtime certificate rotation for both client and server applications.

## 1. Server-Side Integration

The server registers GDS push/pull certificate management methods (e.g. `StartSigningRequest`, `FinishSigningRequest`, `GetRejectedList`, `UpdateCertificate`) under a `SimpleNodeManager`:

```rust
use async_opcua_server::gds::register_gds_certificate_management_methods;
use async_opcua_server::node_manager::memory::SimpleNodeManager;

// Register GDS methods under the simple node manager
let registries = register_gds_certificate_management_methods(&node_manager);
```

### Credentials Caching
To ensure the server survives a GDS outage or cold restart, it caches certificates locally using `gds::cache::GdsCredentialCache`. If GDS is unavailable during startup, it falls back to the cached credentials:

```rust
use async_opcua_server::gds::cache::GdsCredentialCache;

let cache = GdsCredentialCache::new("/var/lib/opcua/cache");
if let Ok(creds) = cache.load() {
    // Apply cached certificates
}
```

## 2. Client-Side Usage

Clients enroll with the GDS directory and request certificate signing using `GdsClient`:

```rust
use async_opcua_client::discovery::GdsClient;
use opcua_types::{ApplicationDescription, NodeId, StatusCode};

let gds_client = GdsClient::new();

// 1. Register application with GDS
let app_id = gds_client.register_application(&session, app_desc).await?;

// 2. Start signing request (Push model)
let request_id = gds_client.request_signing_csr(
    &session,
    app_id.clone(),
    NodeId::null(), // Default certificate group
    NodeId::null(), // Default certificate type
    &csr_der,
    false, // Do not regenerate private key
).await?;

// 3. Poll request status
let (cert_der, private_key) = gds_client.poll_signing_request(&session, app_id, request_id).await?;

// 4. Apply renewed credentials dynamically without downtime
gds_client.apply_renewed_certificate(
    session.certificate_store(),
    &cert_der,
    private_key.as_deref(),
)?;
```
