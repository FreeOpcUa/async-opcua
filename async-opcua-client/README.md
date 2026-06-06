# Async OPC-UA Client

Part of [async-opcua](https://crates.io/crates/async-opcua), a general purpose OPC-UA library in rust.

This library defines a fully capable async OPC-UA client based on tokio. You will need a tokio runtime to use this client at all, as it depends on tokio for network and I/O.

The OPC UA Client module contains the functionality necessary for a client to connect to an OPC UA server, authenticate itself, send messages, receive responses, get values, browse the address space and provide callbacks for things to be propagated to the client.

Once the `Client` is created it can connect to a server by creating a `Session`. Multiple sessions can be created from the same client.

To connect to a session, you can either use one of the `connect_*` methods on the `Client`, or the `SessionBuilder` which is more flexible.

Once connected, you will get a `Session` object, and an `EventLoop`. The event loop must be continuously polled while you use the session, you can do this manually, to monitor the state of the connection, or you can just spawn it on a tokio task using `event_loop.spawn()`.

The `Session` object contains methods for each OPC-UA service as of version 1.05 of the standard. Each service may be called directly with its corresponding method, i.e.

```rust
session.read(...).await?
```

or by using the request builder:

```rust
Read::new(&session).nodes_to_read(...).send(session.channel()).await?
```

By using the request builder, it is also possible to retry requests by using `Session::send_with_retry`.

## Example

```rust
#[tokio::main]
async fn main() {
    let mut client = ClientBuilder::new()
        .application_name("My First Client")
        .application_uri("urn:MyFirstClient")
        .create_sample_keypair(true)
        .trust_server_certs(false)
        .session_retry_limit(3)
        .client().unwrap();
    // Create an endpoint. The EndpointDescription can be made from a tuple consisting of
    // the endpoint url, security policy, message security mode and user token policy.
    let endpoint: EndpointDescription = (
        "opc.tcp://localhost:4855/",
        "None",
        MessageSecurityMode::None,
        UserTokenPolicy::anonymous()
    ).into();
    // Create the session and event loop
    let (session, event_loop) = client.connect_to_matching_endpoint(endpoint, IdentityToken::Anonymous).await.unwrap();
    let handle = event_loop.spawn();
    session.wait_for_connection().await;
    // From here you can call services on the session...
    // It is good practice to exit the session when you are done, since
    // OPC-UA servers may keep clients that exit uncleanly alive for some time.
    let _ = session_c.disconnect().await;
    handle.await.unwrap();
}
```

See [simple client](../samples/simple-client/) for a slightly more elaborate example.
