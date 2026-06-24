//! A server whose variable values **survive a restart**, backed by a persistent store.
//!
//! This demonstrates the flexibility of the node-manager design: the in-memory `SimpleNodeManager`
//! drives all the normal behaviour (reads, writes, subscriptions), and a small snapshot layer on
//! top loads values from a JSON file at startup and writes them back periodically and on shutdown.
//!
//! Try it: run the server, write new values to the variables with any OPC UA client (or let the
//! Counter tick), stop it with Ctrl+C, then start it again — the values come back.
//!
//!   cargo run -p async-opcua-persistent-store-sample
//!
//! The store lives in `persistent-store.json` in the working directory.

use std::collections::HashMap;
use std::io::Cursor;
use std::time::Duration;

use base64::{engine::general_purpose::STANDARD, Engine};
use log::{info, warn};
use opcua::server::address_space::Variable;
use opcua::server::diagnostics::NamespaceMetadata;
use opcua::server::node_manager::memory::{simple_node_manager, SimpleNodeManager};
use opcua::server::{ServerBuilder, ServerEndpoint, ANONYMOUS_USER_TOKEN_ID};
use opcua::types::{
    BinaryDecodable, BinaryEncodable, ContextOwned, DataEncoding, DataValue, MessageSecurityMode,
    NodeId, NumericRange, TimestampsToReturn, UAString, Variant,
};
use opcua::{crypto::SecurityPolicy, nodes::NodeType};

const NAMESPACE: &str = "urn:PersistentStore";
const STORE_PATH: &str = "persistent-store.json";

/// The persistent variables: a string identifier (stable across restarts, independent of the
/// runtime namespace index), a display name, and the value used the very first time the server
/// runs with no store file yet.
fn default_variables() -> Vec<(&'static str, &'static str, Variant)> {
    vec![
        ("Counter", "Counter", 0i32.into()),
        ("Setpoint", "Setpoint", 21.5f64.into()),
        ("Label", "Label", UAString::from("hello").into()),
        ("Enabled", "Enabled", false.into()),
    ]
}

/// Encode a `DataValue` as base64'd OPC UA binary — handles every Variant type with no per-type code.
fn encode_value(dv: &DataValue) -> String {
    let ctx = ContextOwned::default();
    let mut buf = Vec::new();
    // Encoding a DataValue into an in-memory buffer cannot fail.
    dv.encode(&mut buf, &ctx.context())
        .expect("encode DataValue");
    STANDARD.encode(buf)
}

/// Decode a base64'd OPC UA binary `DataValue`, returning `None` on any malformed entry.
fn decode_value(s: &str) -> Option<DataValue> {
    let bytes = STANDARD.decode(s).ok()?;
    let ctx = ContextOwned::default();
    DataValue::decode(&mut Cursor::new(bytes), &ctx.context()).ok()
}

/// Load the persisted `identifier -> DataValue` map, or an empty map if there is no store yet.
fn load_store() -> HashMap<String, DataValue> {
    let Ok(text) = std::fs::read_to_string(STORE_PATH) else {
        info!("no store at {STORE_PATH}, starting from defaults");
        return HashMap::new();
    };
    let raw: HashMap<String, String> = serde_json::from_str(&text).unwrap_or_default();
    raw.into_iter()
        .filter_map(|(k, v)| Some((k, decode_value(&v)?)))
        .collect()
}

/// Read the current value of every persistent variable from the address space and write the store.
fn save_store(node_manager: &SimpleNodeManager, ns: u16) {
    let address_space = node_manager.address_space().read();
    let mut raw: HashMap<String, String> = HashMap::new();
    for (id, _, _) in default_variables() {
        if let Some(node) = address_space.find(&NodeId::new(ns, id)) {
            if let NodeType::Variable(var) = &*node {
                let dv = var.value(
                    TimestampsToReturn::Both,
                    &NumericRange::None,
                    &DataEncoding::Binary,
                    0.0,
                );
                raw.insert(id.to_owned(), encode_value(&dv));
            }
        }
    }
    match serde_json::to_string_pretty(&raw) {
        Ok(text) => {
            if let Err(e) = std::fs::write(STORE_PATH, text) {
                warn!("failed to write {STORE_PATH}: {e}");
            }
        }
        Err(e) => warn!("failed to serialize store: {e}"),
    }
}

#[tokio::main]
async fn main() {
    env_logger::init();

    let (server, handle) = ServerBuilder::new()
        .application_name("Async OPC-UA Persistent Store sample")
        .application_uri("urn:async_opcua_persistent_store")
        .product_uri("urn:async_opcua_persistent_store")
        .create_sample_keypair(true)
        .host("localhost")
        .port(4855)
        .add_endpoint(
            "standard",
            ServerEndpoint::new(
                "/",
                SecurityPolicy::None,
                MessageSecurityMode::None,
                &[ANONYMOUS_USER_TOKEN_ID.to_owned()],
            ),
        )
        .discovery_urls(vec!["opc.tcp://localhost:4855/".to_owned()])
        .with_node_manager(simple_node_manager(
            NamespaceMetadata {
                namespace_uri: NAMESPACE.to_owned(),
                ..Default::default()
            },
            "persistent",
        ))
        .trust_client_certs(true)
        .diagnostics_enabled(true)
        .build()
        .unwrap();

    let node_manager = handle
        .node_managers()
        .get_of_type::<SimpleNodeManager>()
        .unwrap();
    let ns = handle.get_namespace_index(NAMESPACE).unwrap();
    let subscriptions = handle.subscriptions().clone();

    // Create the variables, then overlay any persisted values.
    let store = load_store();
    {
        let address_space = node_manager.address_space();
        let mut address_space = address_space.write();
        let folder = NodeId::new(ns, "PersistentFolder");
        address_space.add_folder(
            &folder,
            "Persistent",
            "Persistent",
            &NodeId::objects_folder_id(),
        );
        address_space.add_variables(
            default_variables()
                .into_iter()
                .map(|(id, name, value)| Variable::new(&NodeId::new(ns, id), name, name, value))
                .collect(),
            &folder,
        );
    }
    // Apply the restored values through the node manager so subscribers (none yet at startup) and
    // the in-memory value both reflect the persisted state.
    let restored: Vec<_> = store
        .into_iter()
        .map(|(id, dv)| (NodeId::new(ns, id), None, dv))
        .collect();
    if !restored.is_empty() {
        info!("restored {} value(s) from {STORE_PATH}", restored.len());
        node_manager
            .set_values(
                &subscriptions,
                restored.iter().map(|(id, r, dv)| (id, *r, dv.clone())),
            )
            .unwrap();
    }

    // A server-driven value: tick the Counter every second to show that programmatic updates
    // persist too (not just client writes).
    {
        let nm = node_manager.clone();
        let subs = subscriptions.clone();
        let counter_id = NodeId::new(ns, "Counter");
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(1));
            let mut value = read_i32(&nm, &counter_id).unwrap_or(0);
            loop {
                interval.tick().await;
                value = value.wrapping_add(1);
                let _ = nm.set_values(
                    &subs,
                    [(&counter_id, None, DataValue::new_now(value))].into_iter(),
                );
            }
        });
    }

    // Periodic snapshot.
    {
        let nm = node_manager.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(5));
            loop {
                interval.tick().await;
                save_store(&nm, ns);
            }
        });
    }

    // Final snapshot on Ctrl+C, then a graceful shutdown.
    let handle_c = handle.clone();
    let nm_c = node_manager.clone();
    tokio::spawn(async move {
        if let Err(e) = tokio::signal::ctrl_c().await {
            warn!("Failed to register CTRL-C handler: {e}");
            return;
        }
        info!("shutting down, writing final snapshot to {STORE_PATH}");
        save_store(&nm_c, ns);
        handle_c.cancel();
    });

    info!("persistent-store server listening on opc.tcp://localhost:4855/ (store: {STORE_PATH})");
    server.run().await.unwrap();
}

/// Read the current `i32` value of a variable, if it is one.
fn read_i32(node_manager: &SimpleNodeManager, id: &NodeId) -> Option<i32> {
    let address_space = node_manager.address_space().read();
    let node = address_space.find(id)?;
    let NodeType::Variable(var) = &*node else {
        return None;
    };
    match var
        .value(
            TimestampsToReturn::Neither,
            &NumericRange::None,
            &DataEncoding::Binary,
            0.0,
        )
        .value
    {
        Some(Variant::Int32(v)) => Some(v),
        _ => None,
    }
}
