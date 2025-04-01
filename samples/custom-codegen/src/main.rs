pub mod generated;

use std::sync::Arc;

pub use generated::node_ids::{DataTypeId, ObjectId};
use log::warn;
use opcua::server::{node_manager::memory::simple_node_manager_imports, ServerBuilder};

#[tokio::main]
async fn main() {
    env_logger::init();

    let (server, handle) = ServerBuilder::new()
        .with_config_from("../server.conf")
        // Simple way to register a node manager containing the generated address space
        .with_node_manager(simple_node_manager_imports(
            vec![Box::new(generated::ProfinetNamespace)],
            "ProfiNet",
        ))
        .trust_client_certs(true)
        .with_type_loader(Arc::new(crate::generated::types::GeneratedTypeLoader))
        .build()
        .unwrap();

    let handle_c = handle.clone();
    tokio::spawn(async move {
        if let Err(e) = tokio::signal::ctrl_c().await {
            warn!("Failed to register CTRL-C handler: {e}");
            return;
        }
        handle_c.cancel();
    });

    server.run().await.unwrap();
}
