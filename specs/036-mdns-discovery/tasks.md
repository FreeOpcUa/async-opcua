# Tasks: mDNS multicast discovery (LDS-ME) for FindServersOnNetwork

**Feature**: `specs/036-mdns-discovery` | **Branch**: `036-mdns-discovery`
**Spec**: [spec.md](spec.md) · **Plan**: [plan.md](plan.md) · **Contract**: [contracts/mdns-discovery.md](contracts/mdns-discovery.md)

Format: `[ID] [P?] [Story?] Description (Spec: Part/§ or FR)`. Tasks are **atomic** (one concern each) and
**cite the OPC UA Part/§ or the FR** they touch so the implementer grounds them via the reference MCP.
ALL new code is `#[cfg(feature = "discovery-mdns")]` (off by default). Engine in `async-opcua-server/`;
Claude authors the `[Claude]` test tasks; the multicast integration tests MUST self-skip when multicast
is unavailable.

---

## Phase 1: Setup

- [X] T001 [P] Confirm baseline green: `cargo build/test -p async-opcua-server` (default), `cargo build -p async-opcua-server --no-default-features`, and `cargo deny check advisories bans sources` all pass at HEAD (Spec: SC-005)
- [X] T002 Inventory the integration points: `find_servers_on_network` (info.rs:251) + `registered_servers` + `ServerInfo` (info.rs:53); the server `CancellationToken` + run path (server.rs:266); `ServerCapabilities` (config/capabilities.rs:69); the optional-feature pattern (`discovery-server-registration = ["async-opcua-client"]`, server Cargo.toml:42 + facade async-opcua/Cargo.toml:58); `deny.toml` advisories style; the generated `MdnsDiscoveryConfiguration`/`ServerOnNetwork` types (Spec: Part 4 §5.5.3; Part 12 §4.3.4)

## Phase 2: Foundational (BLOCKING — feature gate + shared codec)

- [X] T003 Add the off-by-default feature + optional dep: `mdns-sd = { version = "0.20", optional = true }` and `discovery-mdns = ["dep:mdns-sd"]` in `async-opcua-server/Cargo.toml`, a facade passthrough `discovery-mdns = ["async-opcua-server/discovery-mdns"]` in `async-opcua/Cargo.toml`, and a new empty `#[cfg(feature = "discovery-mdns")] mod discovery_mdns;` (e.g. `async-opcua-server/src/discovery/mdns.rs`) registered in the crate (Spec: FR-007; FR-010)
- [X] T004 Implement the Part-12 record codec in `discovery/mdns.rs`: a `DiscoveredServer` struct + `encode_txt(path: &str, caps: &[String]) -> HashMap<String,String>` (`path=`, `caps=` comma-joined) + a PURE `decode_from_parts(host: &str, port: u16, txt: &HashMap<String,String>) -> Option<DiscoveredServer>` (reconstruct `opc.tcp://host:port/path`, split `caps` on `,`, BOUND cap count ≤64 + string lengths, return None on missing host/port — never panic) + a thin `from_service_info(&ServiceInfo)` adapter that extracts host/port/txt and calls the pure fn (Spec: Part 12 §A.1 CapabilityIdentifiers + the mDNS record format — verify the exact § via the reference MCP / OPC Foundation reference stacks UA-.NETStandard/open62541; FR-008)
- [X] T005 [P] [Claude] Unit tests for the codec (no network): `encode_txt` emits the Part-12 `path`/`caps` TXT; `decode_from_parts` round-trips a valid record and reconstructs the discovery URL + caps; malformed/missing host or port → None (no panic); an oversized `caps` (e.g. 10 000 entries) and over-long strings are bounded, not OOM/panic (Spec: FR-008; FR-012; SC-006)

**Checkpoint**: feature compiles on/off; the deterministic record codec exists + is tested. No runtime behavior yet.

---

## Phase 3: User Story 1 — The server advertises itself (P1) 🎯 MVP

**Goal**: with discovery enabled, the server announces `_opcua-tcp._tcp` with its URL + caps.
**Independent test**: an external mDNS browser sees the service with the right address/caps.

- [X] T006 [US1] Add the feature-gated opt-in config (ServerConfig/ServerBuilder): an enable flag (default false), an optional mDNS server name (default = application name), and the advertised CapabilityIdentifiers (default derived from `ServerCapabilities`, else `["NA"]`); e.g. a `multicast_discovery(bool)` builder method (Spec: FR-001; Part 12 §A.1)
- [X] T007 [US1] Implement the responder in `discovery/mdns.rs`: create a `ServiceDaemon`, build `ServiceInfo::new("_opcua-tcp._tcp.local.", mdns_name, host, ips, port, Some(encode_txt(path, caps)))`, and `register` it; expose `unregister`/shutdown (Spec: FR-001; Part 12 mDNS record format — verify § via the OPC Foundation reference stacks)
- [X] T008 [US1] Wire the responder into the server lifecycle (server.rs run path): when `discovery-mdns` is on AND multicast is configured-enabled, spawn a background task holding the `CancellationToken` that registers the responder and unregisters + drops the daemon on cancel; if `ServiceDaemon::new`/`register` returns Err (multicast unavailable) log at warn and exit the task WITHOUT crashing or blocking server startup (Spec: FR-002; FR-009; D5/D6)
- [X] T009 [P] [US1] [Claude] Unit test: given a server config (host/port/path + caps), the advertised `ServiceInfo`'s TXT carries `path=` and `caps=<comma-joined>` exactly per Part 12 (build the ServiceInfo via the responder helper; assert on its properties — no network) (Spec: SC-001; FR-012)
- [X] T010 [P] [US1] [Claude] Integration test (multicast-TOLERANT): start a server with discovery enabled; from a second `mdns-sd` browser on the same host, confirm the `_opcua-tcp._tcp` service resolves with the correct discovery URL + caps within a short timeout; if `ServiceDaemon::new`/browse fails or nothing resolves (multicast blocked), the test SKIPS / soft-passes rather than failing (Spec: SC-001; FR-009)

**Checkpoint**: the server advertises itself; discoverable by any conformant browser; safe where multicast is blocked.

---

## Phase 4: User Story 2 — FindServersOnNetwork discovers via multicast (P2)

**Goal**: FindServersOnNetwork merges discovered servers (with caps) into the pull-based results.
**Independent test**: a querier server returns a responder server with the right URL + caps + filter.

- [X] T011 [US2] Implement the querier + bounded cache in `discovery/mdns.rs`: a `MdnsDiscovery { daemon, own_instance, cache: RwLock<HashMap<String, DiscoveredServer>> }`; a task that `browse`s `_opcua-tcp._tcp.local.` and consumes `ServiceEvent` via `recv_async().await` — `ServiceResolved` → `from_service_info` → insert (skip self by `own_instance`, de-dup by instance), `ServiceRemoved` → evict; bound the cache (≤4096) and set `expires_at` (Spec: FR-003; FR-005; FR-006; FR-008)
- [X] T012 [US2] Hold `#[cfg(feature = "discovery-mdns")] mdns: Option<Arc<MdnsDiscovery>>` on `ServerInfo` (None unless feature on + configured), and start the querier in the SAME lifecycle task as the responder (T008), sharing the daemon (Spec: FR-003)
- [X] T013 [US2] Update `find_servers_on_network` (info.rs:251): when the mdns cache is present, build candidates from registered servers (caps=None) PLUS non-expired cache records (caps=Some), assign `record_id` by sorting the MERGED set on server URI, apply the `capability_filter` against each candidate's caps (registered → excluded by a non-empty filter as today; discovered → included iff caps satisfy the filter), then apply offset + max-records; feature-off / cache-absent path byte-identical to today (Spec: Part 4 §5.5.3; FR-003; FR-004)
- [ ] T014 [US2] In RegisterServer2's `MdnsDiscoveryConfiguration` handling (controller.rs): when `discovery-mdns` is on, stop returning `BadNotSupported` for the mDNS configuration and advertise the registering server's mDNS name/capabilities via the responder (or document precisely why it remains per-spec when the local server is not an LDS); keep it minimal (Spec: Part 4 §5.5.6; FR-004)
- [X] T015 [P] [US2] [Claude] Unit test for the merge (no network): seed the cache directly with discovered records + the registered store; assert `find_servers_on_network` returns discovered servers with caps, a non-empty `capability_filter` includes a matching discovered server and excludes a non-matching one (and still excludes registered servers), self/duplicate are collapsed, an EXPIRED cache record (past its `expires_at`) is NOT returned (FR-006), and offset/limit are honored (Spec: SC-002; SC-003; FR-003; FR-004; FR-005; FR-006)
- [ ] T016 [P] [US2] [Claude] Integration test (multicast-TOLERANT): a responder server + a querier server; `FindServersOnNetwork` on the querier returns the responder with correct URL + caps; SKIPS / soft-passes when multicast is unavailable (Spec: SC-002)

**Checkpoint**: FindServersOnNetwork over multicast works and the capability filter is meaningful.

---

## Phase 5: User Story 3 — Opt-in, isolated, supply-chain-clean (P2)

**Goal**: the feature is off by default, absent from the minimal build, and advisory-clean.

- [X] T017 [US3] Verify the build matrix and add the feature to the relevant CI legs if needed: `--no-default-features` builds with `mdns-sd` ABSENT and `find_servers_on_network` unchanged; `--all-features` builds + tests with the feature active; confirm `.github/workflows/main.yml` `--all-features` legs exercise `discovery-mdns` and the `--no-default-features` leg proves its absence (Spec: FR-007; FR-011; SC-004; SC-005)
- [X] T018 [US3] Run `cargo deny check advisories bans sources` with the feature on (mdns-sd + transitive `flume`/`socket2`/`if-addrs`); it MUST be green — add a justified `[advisories].ignore` entry to `deny.toml` (id + reason scoped to the optional `discovery-mdns` path) ONLY if a transitive advisory actually appears, matching the existing deny.toml style (Spec: FR-010; SC-005)
- [X] T019 [P] [US3] [Claude] Test (default build, feature OFF): assert `find_servers_on_network` returns exactly the pull-based registered set and a non-empty `capability_filter` still matches nothing — proving byte-identical behavior when the feature is disabled (Spec: FR-007; SC-004)

**Checkpoint**: default + minimal builds unaffected; advisory gate green; opt-in proven.

---

## Phase 6: Polish & cross-cutting

- [X] T020 [P] [Claude] DoS/no-panic test (no network): feed `decode_from_parts` + the cache a flood of malformed / oversized / duplicate records (huge `caps`, over-long path/host, thousands of fake instances) and assert no panic, caps bounded, cache size bounded (Spec: FR-008; SC-006; Part 2 §8.3)
- [X] T021 [P] `cargo clippy` under default, `--no-default-features`, AND `--all-features` (the `discovery-mdns` leg); `cargo fmt --all --check` clean (Spec: Constitution V; SC-005)
- [X] T022 [P] Add a "Multicast discovery (LDS-ME)" docs section (`docs/gds.md` or `docs/advanced_server.md`) mirroring quickstart.md — enabling the feature, opt-in config, and the multicast-unavailable degradation (Spec: Part 12; FR-009)
- [X] T023 Update `specs/completeness-backlog.md` (FindServersOnNetwork/LDS-ME multicast DONE via the opt-in `discovery-mdns` feature; mDNS removed from "real constraints") + memory (Spec: project process)

---

## Dependencies & MVP

- **Setup (T001–T002)** → **Foundational (T003–T005: feature gate + codec)** → user stories.
- **US1 (P1, T006–T010)** is the MVP: a server that advertises itself is immediately discoverable by any
  conformant third party. **US2 (P2)** adds this product's own discovery + the FindServersOnNetwork merge
  (depends on the US1 record format + lifecycle task). **US3 (P2)** is the isolation/supply-chain gate
  (largely verification; can run in parallel with US2's tests).
- One PR per user story; Polish (T020–T023) folded into the final PR. Each `[Claude]` test is authored
  independently; the multicast integration tests (T010/T016) MUST self-skip when multicast is unavailable
  so CI/sandboxes stay green.
