# Phase 0 Research: mDNS multicast discovery (LDS-ME)

Grounded against OPC UA Part 12 (§4.3.4 MulticastSubnet Discovery, §5.1, Annex C record format), Part 4
§5.5.3 (FindServersOnNetwork), Part 2 §8.3 (FindServersOnNetwork DoS threat), RFC 6762/6763, the
`mdns-sd` crate API, and the current code (`info.rs`, `server.rs`, `config/capabilities.rs`, `deny.toml`).

## D1 — Off-by-default `discovery-mdns` feature; `mdns-sd` optional

**Decision**: Add `discovery-mdns = ["dep:mdns-sd"]` (OFF by default) to `async-opcua-server/Cargo.toml`
with `mdns-sd = { version = "0.20", optional = true }`, plus a facade passthrough
`discovery-mdns = ["async-opcua-server/discovery-mdns"]` in `async-opcua/Cargo.toml`. Mirror the existing
`discovery-server-registration = ["async-opcua-client"]` pattern. ALL new code is `#[cfg(feature =
"discovery-mdns")]`. With the feature off, `mdns-sd` is not compiled and `find_servers_on_network` keeps
its exact current behavior.

**Rationale**: the project guarantees a pure-Rust `--no-default-features` build and a clean advisory gate;
`mdns-sd` is pure-Rust (won't break the minimal build) but it is still a new network-facing dep, so it is
opt-in. `--all-features` CI exercises it; the `--no-default-features` CI leg proves its absence.

## D2 — `mdns-sd` API + tokio bridge

**Decision**: One `ServiceDaemon` per server (`ServiceDaemon::new()`). Responder:
`ServiceInfo::new("_opcua-tcp._tcp.local.", instance_name, host_name, ip(s), port, Some(txt_props))` then
`daemon.register(info)`; on shutdown `daemon.unregister(fullname)`. Querier:
`daemon.browse("_opcua-tcp._tcp.local.")` returns a `flume::Receiver<ServiceEvent>`; consume it from a
tokio task via `receiver.recv_async().await`, handling `ServiceEvent::ServiceResolved(info)` (add/refresh
cache) and `ServiceRemoved`/`SearchStopped` (evict). `flume`'s async recv integrates cleanly with tokio
without a dedicated reactor.

**Rationale**: `mdns-sd` does the RFC 6762/6763 wire encode/decode and socket/multicast management (one
crate covers both responder and querier); the runtime-agnostic `flume` channel is the only bridge needed.
`ServiceInfo` exposes `get_properties()` (TXT), `get_addresses()`, `get_port()`, `get_hostname()`,
`get_fullname()` for the mapping.

**Alternatives rejected**: `libmdns` (responder only — would need a separate querier crate); C-binding
`zeroconf`/`astro-dnssd` (breaks the pure-Rust minimal build); hand-rolling RFC 6762 (out of scope, error
-prone on the untrusted-packet boundary).

## D3 — Part-12 DNS-SD record format (codec, deterministic + unit-tested)

**Decision**: Service type `_opcua-tcp._tcp` (DNS-SD domain `_opcua-tcp._tcp.local.`). Instance name = the
configured mDNS server name (Part 12 application/mDNS name). SRV → target host + port. TXT key/values:
- `path=<discovery endpoint path>` (the path component of the DiscoveryUrl, e.g. `/` or `/UADiscovery`).
- `caps=<comma-separated CapabilityIdentifiers>` (Part 12 Annex A.1 — two/short codes: `LDS`, `NA`, `DA`,
  `HD`, `AC`, `HE`, `GDS`, `DI`, `ADI`, `FDI`, `FDT`, `UFX`, `AUTO`, …). Multiple caps joined by `,`.
Provide pure functions `encode_txt(path, caps) -> HashMap<String,String>` and
`decode_record(ServiceInfo) -> Option<DiscoveredServer>` that reconstruct the DiscoveryUrl
(`opc.tcp://<host>:<port><path>`) and the `caps` vec. These are deterministic and fully unit-tested with no
network.

**Rationale**: matches the OPC Foundation reference stacks (UA-.NETStandard / open62541) which implement
Part 12 Annex C identically; per-task the exact §C is re-grounded via the reference MCP. The codec is where
correctness lives, so it is isolated and network-free-testable.

## D4 — Discovery cache + `find_servers_on_network` merge

**Decision**: Add a feature-gated discovery cache to `ServerInfo` (e.g. `#[cfg(feature = "discovery-mdns")]
mdns: Option<Arc<MdnsDiscovery>>` holding `RwLock<HashMap<instance_name, DiscoveredServer>>` with an
`expires_at`). `find_servers_on_network` (info.rs:251): when the cache is present, build the candidate list
from BOTH the registered servers (no caps) AND the cache records (with caps), assign stable record ids by
sorting on server URI across the merged set, apply the `capability_filter` against each candidate's caps
(registered → empty caps → excluded by a non-empty filter, as today; discovered → matched against its
advertised caps), then apply the offset + max-records limit. When the feature is off the function body is
unchanged (the merge is behind `#[cfg]` / `if let Some(cache)`).

**Rationale**: reuses the existing sort/offset/limit logic and the `ServerOnNetwork` shape; the only change
is adding cache candidates + making the capability filter meaningful (FR-003/FR-004). Self-exclusion: drop
the cache entry whose instance name / discovery URL is this server's own advertisement (FR-005); de-dup by
instance name (FR-005).

## D5 — Server lifecycle: spawn responder+querier, unregister on shutdown

**Decision**: The server owns a `CancellationToken` (`server.rs:266`). In the run path, when
`discovery-mdns` is enabled AND multicast discovery is opted-in via config, spawn a background tokio task
that creates the `ServiceDaemon`, registers the responder `ServiceInfo`, starts the browse, and loops on
`recv_async()` updating the cache until the token is cancelled; on cancel it unregisters and drops the
daemon (FR-002). Cache expiry is driven by `ServiceRemoved` events + an `expires_at` TTL check at read
time.

**Rationale**: ties the mDNS lifetime to the server lifetime exactly like the other background tasks;
unregister-on-cancel satisfies the "withdraw on shutdown" requirement.

## D6 — Multicast-unavailable degradation (FR-009)

**Decision**: `ServiceDaemon::new()` / `register` / `browse` returning `Err` (multicast blocked, no
interface, sandbox) MUST be logged at warn and the task MUST exit cleanly WITHOUT propagating — the server
continues to run and `find_servers_on_network` simply has an empty cache. Never `unwrap`/`expect` on daemon
results; never block server startup on mDNS.

**Rationale**: CI/containers/sandboxes routinely block `224.0.0.251:5353`; enabling the feature there must
be a no-op, not a crash (the spec's primary edge case).

## D7 — Untrusted-input hardening (Constitution IV / FR-008)

**Decision**: `mdns-sd` parses the raw multicast wire format (the true untrusted boundary). Our
`decode_record` additionally treats the resolved `ServiceInfo` fields as untrusted: cap the number of caps
parsed from `caps` (e.g. ≤ 64) and each cap's length, cap the `path`/host/instance string lengths, reject a
record with no usable address/port (return `None`, skip — no panic), and never index/`unwrap` on
attacker-influenced data. The cache is bounded (cap total entries, e.g. ≤ 4096) so a flood of fake
announcements can't grow it unboundedly (Part 2 §8.3 DoS).

**Rationale**: FindServersOnNetwork/mDNS is unauthenticated and DoS-exposed by spec; bounding parse + cache
size is the required mitigation.

## D8 — Config surface (opt-in)

**Decision**: Feature-gated config on `ServerConfig`/`ServerBuilder`: an enable flag (default false), an
optional mDNS server name (default = the application name), and the advertised CapabilityIdentifiers
(default from the server's `ServerCapabilities`, `config/capabilities.rs:69`, else `["LDS"]`/`["NA"]`).
Builder method e.g. `multicast_discovery(true)`.

**Rationale**: opt-in even when the feature is compiled in (FR-007); a server compiled with `discovery-mdns`
but not configured does not advertise.

## D9 — Supply chain: deny.toml + CI

**Decision**: Run `cargo deny check advisories bans sources` with the feature enabled (i.e. `--all-features`
resolution). `mdns-sd` itself has no advisory; its transitive deps (`flume`, `socket2`, `if-addrs`) are
checked. Add a justified `[advisories].ignore` entry ONLY if a transitive advisory actually appears,
following the existing deny.toml style (id + reason: scope = optional `discovery-mdns` path only). Confirm
the `.github/workflows/main.yml` `--all-features` test/clippy legs now cover the feature and the
`--no-default-features` leg proves its absence.

**Rationale**: the constitution (§110–112) requires a new network-facing dep to pass the advisory gate with
recorded justification; this makes the supply-chain posture explicit and CI-enforced.
