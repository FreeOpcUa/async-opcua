# Async OPC-UA Server

Part of [async-opcua](https://crates.io/crates/async-opcua), a general purpose OPC-UA library in rust.

This library defines a general purpose OPC-UA server based on tokio. You will need a tokio runtime to run the server, as it depends on tokio for network and I/O.

The OPC-UA Server module contains functionality for defining an OPC-UA server containing custom structures that build on the core namespace. Each connected client is spawned on its own tokio task, and each received message also spawns a task, this is similar in design to how webserver frameworks such as `Axum` work.

To create a server, first build and configure one using the `ServerBuilder`, then run it using `Server::run`. The server, when constructed, returns a `Server` and a `ServerHandle`. The server handle contains references to core server types and can be used to manage the server externally, modifying its contents, stopping it, etc.

## Features

 - `discovery-server-registration`, pulls in the `async-opcua-client` library to act as a client, attempting to register the server on a local discovery server.
 - `generated-address-space`, enabled by default. This feature pulls in the `async-opcua-core-namespace` crate, which contains the entire core OPC-UA namespace. This is used to populate the core OPC-UA namespace. Without this, it is difficult to make a compliant OPC-UA server.
 - `json`, adds support for deserializing and serializing OPC-UA types as JSON.

## Example

```rust
#[tokio::main]
async fn main() {
    // Create an OPC UA server with sample configuration and default node set
    let (server, handle) = ServerBuilder::new()
        .build_info(BuildInfo {
            product_uri: "my:server:uri".into(),
            manufacturer_name: "Me".into(),
            product_name: "My OPC-UA Server".into(),
            // Here you could use something to inject the build time, version, number at compile time
            software_version: "0.1.0".into(),
            build_number: "1".into(),
            build_date: DateTime::now(),
        })
        .with_node_manager(simple_node_manager(
            NamespaceMetadata {
                namespace_uri: "urn:SimpleServer".to_owned(),
                ..Default::default()
            },
            "simple",
        ))
        .application_uri("urn:my-opcua-server")
        .certificate_path("own/cert.der")
        .private_key_path("private/private.pem")
        .pki_dir("./pki")
        // Add an endpoint.
        .add_endpoint(
            "none",
            (
                endpoint_path,
                SecurityPolicy::None,
                MessageSecurityMode::None,
                &[ANONYMOUS_USER_TOKEN_ID] as &[&str],
            ),
        )
        // Add a custom node manager
        .with_node_manager(simple_node_manager(
            NamespaceMetadata {
                namespace_uri: "urn:my-opcua-server".to_owned(),
                ..Default::default()
            },
            "simple",
        ))
        .trust_client_certs(true)
        .create_sample_keypair(true)
        .build()
        .unwrap();
    let node_manager = handle
        .node_managers()
        .get_of_type::<SimpleNodeManager>()
        .unwrap();
    let ns = handle.get_namespace_index("urn:my-opcua-server").unwrap();

    // We can now edit the simple node manager by adding nodes to it...

    // If you don't register a ctrl-c handler, the server will close without
    // informing clients.
    let handle_c = handle.clone();
    tokio::spawn(async move {
        if let Err(e) = tokio::signal::ctrl_c().await {
            warn!("Failed to register CTRL-C handler: {e}");
            return;
        }
        handle_c.cancel();
    });

    // Run the server. This does not ordinarily exit so you must Ctrl+C to terminate
    server.run().await.unwrap();
}

```

For more detailed documentation on the server see [server.md](../docs/server.md) and [advanced_server.md](../docs/advanced_server.md).

The server SDK is _very_ flexible. There are mechanisms to make simple usage easier, but writing an OPC-UA server is never going to be a simple task.
