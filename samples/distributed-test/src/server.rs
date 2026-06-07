use opcua::server::prelude::*;
use opcua::server::{ServerBuilder};

#[tokio::main]
async fn main() {
    println!("Starting OPC UA Server on PLC03...");
    env_logger::init();
    
    // Minimal config binding to all interfaces
    let mut config = ServerConfig::new("sample_server", "urn:sample_server");
    config.tcp_config.host = "0.0.0.0".into();
    config.tcp_config.port = 4840;
    
    let (server, handle) = ServerBuilder::new()
        .with_config(config)
        .build();
        
    println!("Server built. Running...");
    server.run().await;
}
