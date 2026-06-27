# Data Model: mDNS multicast discovery (LDS-ME)

All new types are feature-gated (`#[cfg(feature = "discovery-mdns")]`) in
`async-opcua-server/src/discovery/mdns.rs`. No persisted storage.

## DiscoveredServer (new — a cache entry)

```text
struct DiscoveredServer {
    instance_name: String,        // DNS-SD instance (the mDNS server name); de-dup + self-exclusion key
    discovery_url: String,        // opc.tcp://<host>:<port><path>, reconstructed from SRV + TXT path
    server_name: String,          // display name
    capabilities: Vec<String>,    // Part 12 §A.1 CapabilityIdentifiers from TXT `caps`
    expires_at: Instant,          // TTL from the announcement; expired entries are not returned
}
```
- Bounded: capabilities count ≤ MAX_CAPS (e.g. 64), each string length-capped; record dropped (not panic)
  if it has no usable host/port.

## MdnsDiscovery (new — responder + querier + cache, held by ServerInfo)

```text
struct MdnsDiscovery {
    daemon: ServiceDaemon,                              // mdns-sd
    own_instance: String,                               // for self-exclusion
    cache: RwLock<HashMap<String /*instance*/, DiscoveredServer>>,  // bounded ≤ MAX_CACHE (e.g. 4096)
}
```
- `ServerInfo` gains `#[cfg(feature = "discovery-mdns")] mdns: Option<Arc<MdnsDiscovery>>` (None unless the
  feature is on AND multicast discovery is configured on).

## Record codec (pure functions — the unit-tested core)

```text
encode_txt(path: &str, caps: &[String]) -> HashMap<String,String>
    // { "path": path, "caps": caps.join(",") }   (omit empty)

decode_record(info: &ServiceInfo) -> Option<DiscoveredServer>
    // host = first address; port = info.get_port(); path = TXT "path" (default "/")
    // caps = split TXT "caps" on ',', trimmed, bounded
    // discovery_url = format!("opc.tcp://{host}:{port}{path}")
    // None if no address/port (skip, never panic)
```

## ServerOnNetwork mapping (merge into find_servers_on_network)

| ServerOnNetwork field | from registered server (today) | from DiscoveredServer (new) |
|---|---|---|
| record_id | index after sort-by-URI over the MERGED set | same merged numbering |
| server_name | server_names[0] / server_uri | DiscoveredServer.server_name |
| discovery_url | discovery_urls[0] | DiscoveredServer.discovery_url |
| server_capabilities | None (no caps tracked) | Some(DiscoveredServer.capabilities) |

- Capability filter: a non-empty filter excludes registered servers (no caps, unchanged) and includes a
  discovered server iff its `capabilities` satisfy the filter.
- Self-exclusion + de-dup by `instance_name`.

## Config (feature-gated, on ServerConfig/ServerBuilder)

| Field | Default | Meaning |
|---|---|---|
| multicast_discovery (enable) | false | opt-in even when the feature is compiled in |
| mdns_server_name | application name | DNS-SD instance name advertised |
| advertised capabilities | from ServerCapabilities, else ["NA"]/["LDS"] | TXT `caps` |
