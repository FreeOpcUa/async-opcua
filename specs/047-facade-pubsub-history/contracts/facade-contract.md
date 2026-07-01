# Facade Contract: PubSub and SQLite History Exposure

The authoritative contract for what this feature adds to the `async-opcua` public packaging surface.

## Feature → dependency → re-export table

| Umbrella feature | Enables (optional dep) | Extern crate | Re-export path | In `default` |
|------------------|------------------------|--------------|----------------|--------------|
| `pubsub` | `async-opcua-pubsub` | `opcua_pubsub` | `opcua::pubsub` | No |
| `history` | `async-opcua-history-sqlite` | `opcua_history_sqlite` | `opcua::history` | No |

## Cargo.toml changes (async-opcua/Cargo.toml)

```toml
[features]
# ... existing ...
pubsub  = ["dep:async-opcua-pubsub"]
history = ["dep:async-opcua-history-sqlite"]
legacy-crypto = [
  # ... existing arms ...
  "async-opcua-pubsub?/legacy-crypto",
]
# default UNCHANGED: default = ["aws-lc-rs"]

[dependencies]
async-opcua-pubsub         = { path = "../async-opcua-pubsub", version = "0.19.0", optional = true }
async-opcua-history-sqlite = { path = "../async-opcua-history-sqlite", version = "0.19.0", optional = true }

[dev-dependencies]
# self dev-dep gains "pubsub", "history"; the two standalone dev-deps are removed
async-opcua = { path = ".", features = ["all", "json", "xml", "legacy-crypto", "wss", "pubsub", "history"] }
```

> Note: the exact `optional` dep spec (e.g. whether to add `default-features = false`) is confirmed in
> the implement phase against a green build; the pattern above mirrors the existing optional facade deps.

## lib.rs changes (async-opcua/src/lib.rs)

```rust
#[cfg(feature = "pubsub")]
#[doc(inline)]
pub use opcua_pubsub as pubsub;

#[cfg(feature = "history")]
#[doc(inline)]
pub use opcua_history_sqlite as history;
```

## Behavioral guarantees (map to Success Criteria)

1. **SC-001 / SC-002 — reachability**: With `async-opcua = { features = ["pubsub"] }` (resp.
   `["history"]`) and *no* direct sub-crate dependency, `use opcua::pubsub::…` (resp.
   `opcua::history::…`) compiles and exposes the full sub-crate API.
2. **SC-003 — footprint**: `cargo tree -p async-opcua -e no-dev` on a default build lists none of
   `async-opcua-pubsub`, `async-opcua-history-sqlite`, sqlite, AMQP, MQTT, or WebSocket crates.
3. **SC-004 — no regression**: every previously-supported feature combination and the umbrella crate's
   test suite build and pass unchanged.
4. **SC-005 — crypto default**: `async-opcua = { features = ["pubsub"] }` (default features on) builds
   the subsystem against the constant-time `aws-lc-rs` backend.

## Verification commands (authoritative)

```bash
# footprint (must print nothing)
cargo tree -p async-opcua -e no-dev | grep -iE 'pubsub|history|sqlite|lapin|rumqtt|amqp|mqtt|tungstenite'

# reachability + compile (default features → aws-lc-rs on)
cargo build -p async-opcua --features pubsub
cargo build -p async-opcua --features history
cargo build -p async-opcua --features pubsub,history

# no-default-feature legs still build (existing invariant)
cargo build -p async-opcua --no-default-features --features pubsub,aws-lc-rs
cargo build -p async-opcua --no-default-features --features history,aws-lc-rs

# self tests (reach subsystems through the enabled features)
cargo test -p async-opcua

# lint
cargo clippy -p async-opcua --all-targets --features pubsub,history
```

## Non-goals (contract boundaries)

- No change to PubSub or SQLite-history public APIs, behavior, or internals.
- No addition to `default`.
- No exposure of any other workspace crate.
