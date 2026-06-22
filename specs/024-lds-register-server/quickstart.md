# Quickstart: RegisterServer (LDS registration)

```rust
// A server (acting as client) registers itself with an async-opcua LDS:
client.register_server(RegisteredServer {
    server_uri: "urn:my-server".into(),
    product_uri: "urn:my-product".into(),
    server_names: Some(vec![LocalizedText::new("en", "My Server")]),
    server_type: ApplicationType::Server,
    gateway_server_uri: UAString::null(),
    discovery_urls: Some(vec!["opc.tcp://host:4840/".into()]),
    semaphore_file_path: UAString::null(),
    is_online: true,
}).await?;

// A client discovers it via FindServers on the LDS:
let servers = client.find_servers("opc.tcp://lds-host:4840/", None, None).await?;
// -> includes ApplicationDescription { application_uri: "urn:my-server", .. }

// Unregister: same call with is_online: false.
```

`FindServersOnNetwork` returns `BadServiceUnsupported` (multicast/mDNS out of scope).

## Verify
```bash
cargo test -p async-opcua --test integration_tests discovery -- --test-threads=1
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo clippy --locked -p async-opcua --no-default-features -- -D warnings
```
