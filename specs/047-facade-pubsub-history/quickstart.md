# Quickstart: PubSub and SQLite History Through async-opcua

## For consumers

### PubSub

```toml
# Cargo.toml
[dependencies]
async-opcua = { version = "0.19", features = ["server", "pubsub"] }
```

```rust
use opcua::pubsub::{PubSubConfigManager, register_pubsub_config_methods};
// ... the full async-opcua-pubsub API is available under opcua::pubsub
```

### SQLite historical storage

```toml
[dependencies]
async-opcua = { version = "0.19", features = ["server", "history"] }
```

```rust
use opcua::history::SqliteHistoryBackend;
// wire into your server's Historical Access as before, no separate crate needed
```

### Notes

- Both features are **opt-in**. A default `async-opcua` dependency pulls neither, so builds that don't
  need PubSub or SQLite history stay small (no AMQP/MQTT/WebSocket, no SQLite native library).
- These features compose with the usual ones (`server`, `client`, `ecc`, `legacy-crypto`, `wss`, …).
- With default features on, the subsystems use the constant-time `aws-lc-rs` crypto backend, same as
  the rest of the stack.

## For maintainers — verification matrix

Run from the repo root. All must succeed; the footprint grep must print nothing.

```bash
# 1. Footprint invariant (SC-003) — MUST be empty on a default build
cargo tree -p async-opcua -e no-dev | grep -iE 'pubsub|history|sqlite|lapin|rumqtt|amqp|mqtt|tungstenite'

# 2. Reachability + compile (SC-001, SC-002, SC-005)
cargo build -p async-opcua --features pubsub
cargo build -p async-opcua --features history
cargo build -p async-opcua --features pubsub,history

# 3. No-default-features legs (existing invariant preserved)
cargo build -p async-opcua --no-default-features --features pubsub,aws-lc-rs
cargo build -p async-opcua --no-default-features --features history,aws-lc-rs

# 4. Existing feature combos + self tests unchanged (SC-004)
cargo build -p async-opcua --all-features
cargo test  -p async-opcua

# 5. Lint clean
cargo clippy -p async-opcua --all-targets --features pubsub,history -- -D warnings
```

Expected: (1) prints nothing; (2)-(5) succeed; the umbrella crate's
`tests/integration/{pubsub,fx_spike,hda}.rs` pass.
