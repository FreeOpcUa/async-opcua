# Quickstart Guide: Complete OPC UA Compliance

This guide shows how to instantiate and configure the new compliant OPC UA features in your application code using the actual crate APIs.

## 1. Setting Up PubSub Connection (UDP Multicast & MQTT)

Using `async-opcua-pubsub` configuration structures and engine:

```rust
use async_opcua_pubsub::{
    PubSubConnectionConfig, WriterGroupConfig, DataSetWriterConfig,
    PublishedDataSetConfig, MessageEncoding, PubSubEngine
};
use opcua_core::sync::RwLock;
use opcua_server::address_space::AddressSpace;
use opcua_types::NodeId;
use std::sync::Arc;

fn start_pubsub() -> Result<(), opcua_types::StatusCode> {
    let address_space = Arc::new(RwLock::new(AddressSpace::new()));

    // 1. Define connection settings
    let connection = PubSubConnectionConfig {
        connection_id: "conn-1".to_string(),
        name: "factory_multicast".to_string(),
        address: "udp://239.0.0.1:4840".to_string(),
        writer_groups: vec![WriterGroupConfig {
            writer_group_id: 101,
            publishing_interval: 100, // Publish every 100ms
            encoding: MessageEncoding::Uadp,
            dataset_writers: vec![DataSetWriterConfig {
                dataset_writer_id: 1,
                dataset_name: "telemetry_sensors".to_string(),
                published_dataset: PublishedDataSetConfig {
                    published_variables: vec![NodeId::new(2, "TemperatureSensor")],
                },
            }],
        }],
    };

    // 2. Start the PubSub engine
    let mut pubsub_engine = PubSubEngine::with_connections(address_space, vec![connection]);
    let _handles = pubsub_engine.start()?;

    Ok(())
}
```

---

## 2. Registering the SQLite History Storage Backend

To enable server-side Historical Data Access (HDA):

```rust
use std::sync::Arc;
use opcua_server::node_manager::memory::SimpleNodeManager;
use opcua_history_sqlite::SqliteHistoryBackend;

fn setup_hda(node_manager: &SimpleNodeManager) -> Result<(), rusqlite::Error> {
    // 1. Instantiate the SQLite storage engine
    let sqlite_backend = Arc::new(SqliteHistoryBackend::new("historical_data.db")?);
    
    // 2. Register the backend with the NodeManager
    node_manager.inner().set_history_backend(sqlite_backend);
    
    Ok(())
}
```

---

## 3. Configuring OAuth2 Session Validation

Configured dynamically via `ServerConfig` and `ServerBuilder`:

```rust
use opcua_server::ServerBuilder;

fn setup_oauth2_server() {
    let server = ServerBuilder::new()
        .allow_legacy_crypto(false) // Reject deprecated security policies by default
        .application_name("Secure Factory Server")
        // The server config file or builder loads IDP details to validate JWTs locally
        .pki_dir("./pki");
}
```

---

## 4. Running standard GDS Certificate Renewal

Updating and reloading cryptographic materials dynamically:

```rust
use async_opcua_client::discovery::GdsClient;
use opcua_client::Session;
use opcua_types::{NodeId, StatusCode};

async fn rotate_certificates(session: &Session, client: &mut GdsClient) -> Result<(), StatusCode> {
    let app_id = NodeId::new(2, "MyApplicationInstance");
    let csr_der = vec![/* DER encoded CSR */];

    // 1. Send signing request to Global Discovery Server
    let request_id = client.request_signing_csr(
        session,
        app_id.clone(),
        NodeId::null(),
        NodeId::null(),
        &csr_der,
        false,
    ).await?;
    
    // 2. Poll for GDS status approval
    let (cert_der, private_key) = client.poll_signing_request(session, app_id, request_id).await?;
    
    // 3. Reload cryptographic materials dynamically without dropping active sessions
    client.apply_renewed_certificate(
        session.certificate_store(),
        &cert_der,
        private_key.as_deref(),
    )?;
    
    Ok(())
}
```
