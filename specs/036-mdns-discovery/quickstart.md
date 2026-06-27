# Quickstart: mDNS multicast discovery (LDS-ME)

## Enable it (opt-in, behind the `discovery-mdns` feature)

```toml
# Cargo.toml — the feature is OFF by default
async-opcua = { version = "0.19", features = ["server", "discovery-mdns"] }
```

```rust ignore
// Advertise this server on the local network + discover others
let server = ServerBuilder::new()
    .multicast_discovery(true)            // opt-in even when the feature is compiled in
    // mdns server name + advertised capabilities default from the server config
    .build()?;
```

## What happens

- **Advertise (US1)**: the server announces `_opcua-tcp._tcp` on the segment with its discovery URL
  (`opc.tcp://host:port/path`) and capabilities (TXT `path=` / `caps=LDS,DA,…`). Any conformant
  mDNS/DNS-SD browser or OPC UA LDS-ME on the segment sees it. It withdraws the announcement on shutdown.

- **Discover (US2)**: `FindServersOnNetwork` now returns network-discovered servers merged with the
  pull-based registered servers, and a capability filter actually filters:

```text
FindServersOnNetwork(capabilityFilter = [])        → registered + all discovered servers
FindServersOnNetwork(capabilityFilter = ["DA"])    → discovered servers advertising DA  (was: nothing)
```

## Where multicast is blocked (CI, containers, locked-down networks)

Enabling the feature is safe everywhere: if the multicast group is unavailable, advertising/discovery
degrade to a no-op (logged at warn) and the server runs normally — `FindServersOnNetwork` just returns the
pull-based set.

## Unchanged

- With `discovery-mdns` **off** (the default and the minimal `--no-default-features` build): the `mdns-sd`
  dependency is absent and `FindServersOnNetwork` / `RegisterServer` behave exactly as before.
- The pull-based registry and `RegisterServer`/`RegisterServer2` are reused unchanged.
