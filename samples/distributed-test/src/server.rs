use opcua::server::{ServerBuilder, ServerConfig};

#[tokio::main]
async fn main() {
    println!("Starting OPC UA Server on PLC03...");
    env_logger::init();

    // Minimal config binding to all interfaces
    let mut config = ServerConfig {
        application_name: "sample_server".to_string(),
        application_uri: "urn:sample_server".to_string(),
        ..Default::default()
    };
    config.tcp_config.host = "0.0.0.0".into();
    config.tcp_config.port = 4840;

    let (server, _handle) = ServerBuilder::new()
        .with_config(config)
        .build()
        .expect("Failed to build server");

    println!("Server built. Running...");
    if let Err(e) = server.run().await {
        eprintln!("Server exited with error: {e}");
    }
}
