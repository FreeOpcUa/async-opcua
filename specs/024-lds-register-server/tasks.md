---
description: "Task list for feature 024 — RegisterServer/RegisterServer2 (LDS registration)"
---

# Tasks: RegisterServer / RegisterServer2 (LDS registration)

**Input**: design docs in `/specs/024-lds-register-server/`. Conformance Tier 3 #8 (dependency-free part).

**Verification division**: codex implements the server handlers + bounded registry + FindServers
integration (production code, NO git, NO tests); **Claude authors + runs ALL tests** independently via the
EXISTING client `register_server()`/`find_servers()`, anchored to OPC UA Part 4 §5.4.5/§5.4.6 + real
round-trips (NOT codex loopback). One commit per user story.

**Gate**: `cargo fmt --all --check && cargo clippy --all-targets --all-features --locked -- -D warnings`
+ json-off legs (`clippy -p async-opcua --no-default-features [--features json] -- -D warnings`) +
`cargo test -p async-opcua --test integration_tests discovery -- --test-threads=1`.

**Pinned facts (plan/research):** `session/controller.rs` handles RegisterServer/RegisterServer2/
FindServersOnNetwork by sending `ServiceFault(BadServiceUnsupported)`; the FindServers handler builds the
server's own `desc` + applies filters (endpoint URL / server_uris / locale via
`info.matches_find_servers_filters`) → `FindServersResponse{servers}`. `ServerInfo` is `Arc`, held as
`self.info`, already has `registered_server()` (own). ADD a bounded registry there
(`RwLock<HashMap<UAString, RegisteredServer>>` + `MAX_REGISTERED_SERVERS` cap) + apply/list methods +
RegisteredServer→ApplicationDescription map. Wire types: RegisterServer(2)Request/Response,
RegisteredServer{server_uri,product_uri,server_names,server_type,gateway_server_uri,discovery_urls,
semaphore_file_path,is_online}, RegisterServer2Request.discovery_configuration:Option<Vec<ExtensionObject>>
→ Response.configuration_results. MdnsDiscoveryConfiguration = the multicast config to mark BadNotSupported.
Client already has register_server/find_servers. Additive; no new dep; warning-free all legs; e2e single-threaded.

## Phase 1: Setup
- [X] T001 Confirm: RegisterServer(2)Request/Response + RegisteredServer + MdnsDiscoveryConfiguration
  types; the FindServers handler's `desc`/filter code; where to add the registry on `ServerInfo`; the
  RegisteredServer→ApplicationDescription field mapping. No code change.

## Phase 2: US1 — RegisterServer + FindServers integration (P1) 🎯 MVP
- [X] T002 [US1] codex: add a bounded in-memory registry to `ServerInfo` (`async-opcua-server/src/info.rs`)
  — `RwLock<HashMap<UAString, RegisteredServer>>` + `MAX_REGISTERED_SERVERS` cap; methods to apply a
  RegisterServer call (upsert if `is_online`, remove if not; reject null/empty server_uri; reject when at
  cap), and to list registered servers as `ApplicationDescription`s (with the documented field mapping,
  locale-aware name). No panic on crafted input. (depends T001)
- [X] T003 [US1] codex: rewrite the `RegisterServer` handler in `session/controller.rs` to update the
  registry and send `RegisterServerResponse` (Good / appropriate status) instead of the fault; and extend
  the `FindServers` handler to append the registry's ApplicationDescriptions before applying the existing
  filters. Empty registry → byte-identical to today. (depends T002)
- [X] T004 [P] [US1] Claude: integration tests in `async-opcua/tests/integration/discovery.rs` (register
  `mod discovery;`) via the existing client — register(online)→FindServers includes it with the right
  ApplicationDescription fields; register(offline)→FindServers excludes it; re-register/update→single
  entry; empty-registry FindServers unchanged. Anchored to Part 4 §5.4.5. (depends T003)
- [X] T005 [US1] Gate; **commit US1** (`feat(024 US1): RegisterServer + FindServers integration (LDS registry)`).

## Phase 3: US2 — RegisterServer2 + discovery configuration results (P2)
- [X] T006 [US2] codex: rewrite the `RegisterServer2` handler — update the same registry, build
  `configuration_results` (one StatusCode per `discovery_configuration` element; `BadNotSupported` for
  MdnsDiscoveryConfiguration / any unsupported config) WITHOUT failing the registration, and send
  `RegisterServer2Response`. (depends T003)
- [X] T007 [P] [US2] Claude: tests — RegisterServer2 with an mdns discovery-config element → the per-config
  result is BadNotSupported AND the server is still registered (FindServers includes it); RegisterServer2
  updates the same registry as RegisterServer. (depends T006)
- [X] T008 [US2] Gate; **commit US2** (`feat(024 US2): RegisterServer2 + discovery-configuration results`).

## Phase 4: US3 — bound/no-panic, FindServersOnNetwork deferral, doc (P3)
- [X] T009 [US3] Claude: security/edge tests — registering beyond `MAX_REGISTERED_SERVERS` is bounded (no
  unbounded growth, no panic); crafted/malformed RegisteredServer (null server_uri, empty names, large
  discovery_urls) handled without panic; FindServersOnNetwork still returns BadServiceUnsupported. (depends T003)
- [X] T010 [US3] codex/Claude: a short doc note (where discovery is documented, or a code doc-comment on
  the registry) that the server can act as an LDS for registration and that FindServersOnNetwork
  (multicast/mDNS) is intentionally unsupported (no new dependency). Gate; **commit US3**
  (`docs(024 US3): LDS registration bound/edge tests + mDNS deferral note`).

## Phase 5: Polish
- [X] T011 Update `specs/conformance-gap-backlog.md` Tier 3 #8 → RegisterServer/RegisterServer2 + LDS
  registry done; FindServersOnNetwork/mDNS documented deferral (no new dep).
- [X] T012 Final gate: fmt + clippy --all-targets --all-features + json-off/no-default legs +
  `cargo test -p async-opcua --test integration_tests discovery -- --test-threads=1` + existing-suite spot-check.

---

## Dependencies & Execution
- Setup (T001) → US1 (T002–T005 MVP) → US2 (T006–T008) → US3 (T009–T010) → Polish. codex: T002, T003,
  T006, T010(doc). Claude: all tests (T004, T007, T009) + docs. One commit per story.

## Notes
- Additive: empty registry → FindServers unchanged; client untouched; no new dep.
- Deferred (documented): FindServersOnNetwork / mDNS / LDS-ME multicast; registry persistence; stale-entry
  expiry; being discovered by an external LDS via mDNS.
