# Research: RegisterServer / RegisterServer2 (LDS)

## Decision 1 — Registry on ServerInfo (shared Arc)
**Finding**: `ServerInfo` is `Arc<ServerInfo>`, held by the controller as `self.info`, and already has
`registered_server()` (the server's own registration). **Decision**: add a bounded in-memory registry
there — `RwLock<HashMap<UAString /*server_uri*/, RegisteredServer>>` plus a `MAX_REGISTERED_SERVERS`
cap — with methods to apply a RegisterServer call (insert/update if `is_online`, remove otherwise) and to
list registered servers as `ApplicationDescription`s. **Rationale**: it's the shared server state the
controller already uses; no new plumbing. **Alternatives**: a separate discovery service struct (more
wiring for no gain at this scope).

## Decision 2 — RegisterServer / RegisterServer2 semantics (Part 4 §5.4.5/§5.4.6)
**Decision**:
- RegisterServer: `is_online=true` → upsert by `server_uri`; `is_online=false` → remove. Reject an entry
  with a null/empty `server_uri` (the registry key) with the appropriate status; unregistering an unknown
  server is a clean no-op success. Respond `RegisterServerResponse` (Good).
- RegisterServer2: same registry update, plus build `configuration_results` — one `StatusCode` per
  `discovery_configuration` element: `BadNotSupported` for `MdnsDiscoveryConfiguration` (and any other
  config we don't honor), without failing the overall registration. Respond `RegisterServer2Response`.
**Rationale**: matches the spec; the multicast path is explicitly out of scope. **Alternatives**: failing
the whole call on an mdns config (rejected — the server should still register).

## Decision 3 — FindServers integration
**Decision**: in the FindServers handler, after assembling the server's own `desc`, append the registry's
`ApplicationDescription`s, then apply the SAME existing filters (endpoint URL match, `server_uris`,
locale). An empty registry leaves the output byte-identical to today. **Rationale**: registered servers
must be discoverable; filters must stay consistent. **Alternatives**: a separate code path (rejected —
reuse the filter logic).

## Decision 4 — Security: bounded registry + no panic (Constitution IV)
**Decision**: cap the registry at `MAX_REGISTERED_SERVERS` (a sane constant, e.g. a few thousand); when
full, a new distinct registration is rejected with a status (not silently dropped, not grown). All
RegisteredServer field access is fallible/defensive (no unwrap on `server_uri`/`server_names`/
`discovery_urls`); oversized lists are stored as-is but bounded by the per-message decode limits already
enforced upstream. Registration honors the existing channel/security checks. **Rationale**: RegisterServer
is attacker-reachable; an unbounded registry is a memory-exhaustion DoS.

## Decision 5 — FindServersOnNetwork stays unsupported (documented)
**Decision**: leave FindServersOnNetwork returning `BadServiceUnsupported`; document that multicast/mDNS
(LDS-ME) is an infrastructure feature requiring a new dependency and is out of scope. **Rationale**: the
agreed scope; no new dep.

## Decision 6 — Verification anchoring
**Decision**: Claude's integration tests drive the live server through the EXISTING client
`register_server()` / `find_servers()`: register(online)→FindServers includes it (right
ApplicationDescription); register(offline)→gone; update→single entry; RegisterServer2 mdns config→
not-supported result + still registered; bound/no-panic (loop many distinct registrations); empty
registry→FindServers unchanged; FindServersOnNetwork→BadServiceUnsupported. Anchored to Part 4
§5.4.5/§5.4.6, real round-trips.
