# Contract: mDNS multicast discovery (LDS-ME)

All under `#[cfg(feature = "discovery-mdns")]` unless noted; with the feature off, none of this compiles
and `find_servers_on_network` is unchanged.

## Feature + dependency (US3)

```text
# async-opcua-server/Cargo.toml
mdns-sd = { version = "0.20", optional = true }
[features]
discovery-mdns = ["dep:mdns-sd"]          # OFF by default

# async-opcua/Cargo.toml (facade)
discovery-mdns = ["async-opcua-server/discovery-mdns"]
```
- `--no-default-features`: mdns-sd ABSENT, behavior byte-identical to today (FR-007).
- `--all-features`: mdns-sd present, feature active (FR-011).
- `cargo deny check advisories bans sources` green in both (FR-010); justified ignore only if a transitive
  advisory appears.

## Part-12 record format (US1, deterministic codec)

```text
service type : "_opcua-tcp._tcp.local."          (Part 12 mDNS record format; verify § via OPC Foundation reference stacks)
instance     : <mdns server name>
SRV          : <host>:<port>
TXT          : path=<discovery path>   caps=<cap1,cap2,...>   (Part 12 §A.1 CapabilityIdentifiers)
discovery_url: opc.tcp://<host>:<port><path>
```
- `encode_txt(path, caps)` → `{path, caps}` (omit empty). `decode_record(ServiceInfo)` → `DiscoveredServer`
  or `None` (skip) on missing host/port; caps/strings length+count bounded (FR-008).

## Responder (US1)

```text
on server start (feature on + config enabled):
  daemon = ServiceDaemon::new()                 // Err → warn + no-op, server keeps running (FR-009)
  daemon.register(ServiceInfo::new("_opcua-tcp._tcp.local.", name, host, ips, port, encode_txt(path,caps)))
on CancellationToken cancel:
  daemon.unregister(fullname)                    // withdraw announcement (FR-002)
```

## Querier + cache (US2)

```text
rx = daemon.browse("_opcua-tcp._tcp.local.")     // Err → warn + no-op (FR-009)
loop on rx.recv_async().await:
  ServiceResolved(info) => if let Some(d) = decode_record(&info) { if d.instance != own { cache.insert(d) } }
  ServiceRemoved(..)    => cache.remove(instance)
cache bounded ≤ MAX_CACHE; entries past expires_at are not returned (FR-006).
```

## FindServersOnNetwork merge (US2 — info.rs:251)

```text
candidates = registered_servers (caps=None) ++ cache_records (caps=Some)   // when cache present
sort by server URI; assign record_id by merged index
filter: non-empty capability_filter → keep registered? NO (no caps); keep discovered iff caps satisfy filter
apply starting_record_id offset + max_records_to_return limit
self-exclude + de-dup by instance_name
```
- Feature off / cache absent → exactly today's behavior (registered only; non-empty filter matches nothing).

## Invariants

- Default + `--no-default-features` builds: mdns-sd absent, zero behavior change (FR-007/SC-004).
- No panic / bounded allocation on malformed announcements; bounded cache (FR-008/SC-006; Part 2 §8.3).
- Multicast unavailable → no crash/hang, empty cache (FR-009/SC-006).
- The pull-based registry, RegisterServer/RegisterServer2, and the `ServerOnNetwork` shape are reused
  unchanged.
