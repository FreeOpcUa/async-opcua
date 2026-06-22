# Implementation Plan: RegisterServer / RegisterServer2 (LDS registration)

**Branch**: `024-lds-register-server` | **Date**: 2026-06-22 | **Spec**: [spec.md](./spec.md)
**Input**: Feature specification from `/specs/024-lds-register-server/spec.md`

## Summary

Make the async-opcua server act as a Local Discovery Server: implement RegisterServer / RegisterServer2
(currently `BadServiceUnsupported` in `session/controller.rs`) backed by a bounded in-memory registry on
`ServerInfo`, and have the FindServers handler append the registered (online) servers to its response.
FindServersOnNetwork stays `BadServiceUnsupported` (mDNS deferred, no new dep). Client unchanged (it
already has `register_server`/`find_servers`). (US1 RegisterServer+FindServers MVP; US2 RegisterServer2 +
config results; US3 tests/doc + documented mDNS deferral.)

## Technical Context

**Language/Version**: Rust (workspace edition 2021).
**Primary Dependencies**: `async-opcua-server` (`ServerInfo`, `session/controller.rs`, the FindServers
handler), `async-opcua-types` wire types (`RegisterServerRequest/Response`,
`RegisterServer2Request/Response`, `RegisteredServer`, `ApplicationDescription`,
`MdnsDiscoveryConfiguration`, `ServiceFault`). **No new dependency.**
**Storage**: in-memory, non-persistent registry (lost on restart, by design).
**Testing**: integration tests via the existing client `register_server()` / `find_servers()`, run
single-threaded; authored + run by Claude.
**Target Platform**: library; all feature legs.
**Project Type**: library + samples.
**Performance Goals**: registry O(1) insert/remove by server URI; FindServers O(registered).
**Constraints**: additive; no new dep; bounded registry (security); no panic on crafted input; clippy
clean on all-features + json-off legs; existing suites pass.
**Scale/Scope**: a registry component on `ServerInfo` + 2 controller handlers rewritten + FindServers
integration + a RegisteredServer→ApplicationDescription conversion + tests.

### Key facts (verified in code)

- `session/controller.rs` handles `RegisterServer` / `RegisterServer2` / `FindServersOnNetwork` by
  dispatching a service-failure audit event + sending `ServiceFault(BadServiceUnsupported)`. The
  `FindServers` handler builds the server's own `desc`, applies filters (endpoint URL, `server_uris`,
  locale via `info.matches_find_servers_filters`), and sends `FindServersResponse { servers }`.
- `ServerInfo` (`info.rs`) is shared as `Arc<ServerInfo>` (the controller holds `self.info`); it already
  exposes `registered_server() -> RegisteredServer` (the server's OWN registration — reverse direction).
  → Add the registry here with interior mutability (e.g. `RwLock<HashMap<UAString, RegisteredServer>>` +
  a cap constant), plus methods: `register(server)` / `unregister(uri)` (or a single
  `apply_register(RegisteredServer)` keyed on `is_online`), `registered_application_descriptions()`.
- Wire types: `RegisterServerRequest { server: RegisteredServer { server_uri, product_uri, server_names,
  server_type, gateway_server_uri, discovery_urls, semaphore_file_path, is_online } }`;
  `RegisterServer2Request { server, discovery_configuration: Option<Vec<ExtensionObject>> }` →
  `RegisterServer2Response { configuration_results: Option<Vec<StatusCode>>, diagnostic_infos }`.
  `MdnsDiscoveryConfiguration` is the multicast config to mark unsupported.
- RegisteredServer → ApplicationDescription mapping: server_uri→application_uri, localized server_name→
  application_name (pick by locale/first), server_type→application_type, gateway_server_uri,
  discovery_urls→discovery_urls, product_uri.

## Constitution Check

- **I. Correctness Over Completion**: register/unregister/update semantics per Part 4 §5.4.5/§5.4.6;
  FindServers reflects the registry + still honors filters; no faked success. ✅
- **IV. Security Is Paramount**: RegisterServer is remotely reachable → the registry is **bounded** (cap;
  beyond it handled deterministically, no unbounded growth), no panic on crafted/oversized input, and the
  existing channel/security enforcement is not weakened. ✅
- **II/III. Do It Right Once / Discipline**: reuse the existing controller + wire types + FindServers
  filter path; registry on `ServerInfo`; additive; one commit per story. ✅
- **V. Leave It Better**: turns a `BadServiceUnsupported` stub into a working LDS-registration capability,
  dependency-free; documents the mDNS/FindServersOnNetwork boundary. ✅
- **Verification division**: codex writes the handlers + registry + FindServers integration; Claude
  authors/runs all tests via the existing client API, anchored to Part 4 §5.4.5/§5.4.6. ✅

**Gate: PASS** — no violations; no Complexity Tracking entries.

## Project Structure

```
specs/024-lds-register-server/
├── spec.md  plan.md  research.md  data-model.md  quickstart.md
├── contracts/api-surface.md
└── checklists/requirements.md

async-opcua-server/src/info.rs          # (codex) bounded registry on ServerInfo + register/unregister +
                                         #   registered_application_descriptions(); RegisteredServer->
                                         #   ApplicationDescription conversion.
async-opcua-server/src/session/controller.rs  # (codex) RegisterServer/RegisterServer2 → update registry,
                                         #   send RegisterServer(2)Response (Good + config_results);
                                         #   FindServers → append registered servers (filtered).
                                         #   FindServersOnNetwork stays BadServiceUnsupported (documented).
async-opcua/tests/integration/discovery.rs (new)  # Claude: register→FindServers sees it; unregister→gone;
                                         #   update; RegisterServer2 mdns config → not-supported + still
                                         #   registered; bound/no-panic; FindServersOnNetwork unsupported.
```

**Structure decision**: registry lives on `ServerInfo` (already shared into the controller); the two
handlers are rewritten in place; FindServers gains a registry append. No new crate/dep. Client untouched.

## Complexity Tracking

No constitution violations; no entries.
