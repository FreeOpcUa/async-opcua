# Quickstart: Performance Features

## Enabling TSN (Time-Sensitive Networking)
To use the deterministic raw socket driver in `async-opcua-pubsub`, you must run the server as `root` or grant `CAP_NET_RAW` capabilities:
```bash
sudo setcap cap_net_raw+ep ./target/release/async-opcua-server
```

Configure your `server.conf` PubSub transport:
```toml
[pubsub]
transport = "tsn"
interface = "eth0" # Must be a physical TSN-capable interface
```

## OPC-UA Safety Implementation
If you require functional safety (SIL 3), use the new safety APIs to wrap your node data:
```rust
use async_opcua_safety::SpduBuilder;

let spdu = SpduBuilder::new()
    .with_data(emergency_stop_signal)
    .with_timeout(Duration::from_millis(50))
    .build_signed(&safety_keys);
```
