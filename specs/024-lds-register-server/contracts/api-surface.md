# API Surface: RegisterServer / RegisterServer2 (LDS)

Server-side behavior change only. No public client change (client already has register_server /
find_servers). No new wire type. Internal registry on ServerInfo.

## Behavioral contract (Part 4 §5.4.5/§5.4.6)
| Call | Before | After |
|------|--------|-------|
| RegisterServer (is_online=true) | `BadServiceUnsupported` | Good; server upserted into registry; appears in FindServers |
| RegisterServer (is_online=false) | `BadServiceUnsupported` | Good; server removed from registry |
| RegisterServer2 (with mdns config) | `BadServiceUnsupported` | Good; server registered; configuration_results = [BadNotSupported] for the mdns element |
| FindServers (empty registry) | server's own desc | unchanged (byte-identical) |
| FindServers (with registrations) | server's own desc | server's own desc + registered online servers (filters still applied) |
| FindServersOnNetwork | `BadServiceUnsupported` | `BadServiceUnsupported` (documented; mDNS out of scope) |

**Invariants**: registry bounded (`MAX_REGISTERED_SERVERS`); no panic on crafted/oversized input;
non-persistent; existing channel/security enforcement unchanged; no new runtime dependency.

## Internal (async-opcua-server, may be pub(crate))
- `ServerInfo`: bounded registry + `apply_register(RegisteredServer)` / `registered_application_descriptions(...)`.
- `session/controller.rs`: RegisterServer/RegisterServer2 handlers updated; FindServers appends registry.
