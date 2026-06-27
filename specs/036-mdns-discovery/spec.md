# Feature Specification: mDNS multicast discovery (LDS-ME) for FindServersOnNetwork

**Feature Branch**: `036-mdns-discovery`
**Created**: 2026-06-27
**Status**: Draft
**Input**: User description: "Add the OPC UA Part 12 multicast extension (LDS-ME): the server advertises itself on the local network via mDNS/DNS-SD and FindServersOnNetwork discovers other servers the same way. Opt-in, behind a new off-by-default feature; pull-based discovery unchanged."

## User Scenarios & Testing *(mandatory)*

### User Story 1 - The server advertises itself on the local network (Priority: P1)

A server operator wants their OPC UA server to be auto-discoverable by other devices on the same network
segment without anyone configuring its address. When the operator enables multicast discovery, the server
announces itself as an OPC UA service on the local network, including the address clients should connect to
and the server's capabilities. Other OPC UA tools on the segment then see the server appear automatically.

**Why this priority**: Advertising is the foundational half of the multicast extension and is independently
valuable — a single server that announces itself is immediately discoverable by any conformant third-party
client/LDS on the segment, even before this product implements its own discovery side. It is the MVP.

**Independent Test**: Enable multicast discovery on a server; from a separate mDNS/DNS-SD browser on the
same host/segment, confirm the OPC UA service appears with the correct address and capability metadata.

**Acceptance Scenarios**:

1. **Given** a server with multicast discovery enabled, **When** it starts, **Then** it announces an OPC UA
   discovery service on the local network carrying its discovery address (host, port, path) and its declared
   server capabilities.
2. **Given** that running advertised server, **When** it shuts down, **Then** it withdraws its announcement
   so stale entries do not linger.
3. **Given** a server with multicast discovery **disabled** (the default), **When** it starts, **Then** it
   makes no network announcement and behaves exactly as before this feature.

---

### User Story 2 - FindServersOnNetwork discovers servers via multicast (Priority: P2)

A client calls FindServersOnNetwork against this server to learn what OPC UA servers exist on the local
network. The client expects the response to include not only servers that explicitly registered with this
server (the existing behavior) but also servers discovered automatically over the network, filtered by the
requested server capabilities.

**Why this priority**: Discovery is the second half of LDS-ME and depends on the advertising format from US1
being correct. It closes the documented gap where a capability filter matches nothing because advertised
capabilities were never discovered.

**Independent Test**: With two servers on a segment (one advertising via US1), call FindServersOnNetwork on
the other; assert the advertised server appears in the results with the right discovery URL, and that a
capability filter includes/excludes it correctly.

**Acceptance Scenarios**:

1. **Given** another OPC UA server advertising itself on the segment, **When** a client calls
   FindServersOnNetwork, **Then** the response includes that server as a network record with its discovery
   URL and advertised capabilities, merged with the existing registered (pull-based) servers.
2. **Given** a FindServersOnNetwork request with a non-empty server-capability filter, **When** the server
   answers, **Then** only servers whose advertised capabilities satisfy the filter are returned (the filter
   now matches against discovered capabilities instead of matching nothing).
3. **Given** multicast discovery disabled, **When** FindServersOnNetwork is called, **Then** the result is
   exactly the pull-based set as before (no discovered servers, capability filter still matches nothing).

---

### User Story 3 - Opt-in, isolated, and supply-chain-clean (Priority: P2)

A maintainer must be able to build and ship the product without the multicast discovery code or its
third-party dependency unless they explicitly ask for it, and the dependency must satisfy the project's
security policy. The default build, the minimal (dependency-light) build, and the security advisory gate
must all be unaffected by this feature when it is not enabled.

**Why this priority**: The multicast path adds a network-facing third-party dependency and parses untrusted
network packets; the project guarantees a minimal-dependency build and a clean advisory gate. Isolation and
supply-chain hygiene are prerequisites for accepting the feature at all.

**Independent Test**: Build with the feature off (default and minimal builds) and confirm the new dependency
is absent and behavior is unchanged; build with it on and confirm it works; run the dependency advisory gate
and confirm it stays green.

**Acceptance Scenarios**:

1. **Given** the default build and the minimal (dependency-light) build, **When** they are compiled and
   tested, **Then** the multicast discovery dependency is absent and all existing behavior is byte-identical.
2. **Given** the feature explicitly enabled, **When** the project is built and tested, **Then** multicast
   advertising and discovery work.
3. **Given** the dependency advisory/license gate, **When** it runs, **Then** it passes with the new
   dependency recorded and justified.

### Edge Cases

- **Multicast unavailable** (CI, containers, restrictive networks block the multicast group): enabling the
  feature MUST NOT crash the server or block startup; advertising/discovery degrade to a no-op and the
  server otherwise runs normally. Tests that require real multicast MUST tolerate its absence (skip or
  soft-pass) rather than fail.
- **Malformed / hostile announcements from the network**: a discovered record with malformed or oversized
  fields MUST be rejected and skipped, never cause a panic or unbounded allocation.
- **Duplicate / self announcements**: the server must not report itself as a separate discovered server, and
  duplicate announcements for the same server collapse to one record.
- **Stale records**: discovered records expire when their advertised lifetime elapses and the advertiser
  stops; FindServersOnNetwork does not return long-dead servers indefinitely.
- **Capability metadata absent**: a discovered server that advertises no capabilities is still returned when
  the request has no capability filter, and excluded when a non-empty filter is supplied.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: When multicast discovery is enabled, the server MUST advertise itself on the local network as
  an OPC UA discovery service (Part 12 LDS-ME) carrying its discovery endpoint (host, port, path) and its
  configured server capabilities, using the standard OPC UA service type and metadata format (Part 12).
- **FR-002**: The server MUST withdraw its network announcement on shutdown so other parties stop seeing a
  stale entry promptly.
- **FR-003**: When multicast discovery is enabled, FindServersOnNetwork MUST return, in addition to the
  existing registered (pull-based) servers, the servers discovered over the network, each as a network
  record with a usable discovery URL and the discovered server capabilities; the two sources MUST be merged
  without duplicate records for the same server.
- **FR-004**: FindServersOnNetwork MUST apply a non-empty server-capability filter against the discovered
  servers' advertised capabilities (closing the current gap where a capability filter matches nothing), and
  MUST continue to honor the record-id offset and max-records limit.
- **FR-005**: The server MUST NOT report itself as a separate discovered server in FindServersOnNetwork
  results, and MUST collapse duplicate announcements for the same server into a single record.
- **FR-006**: Discovered records MUST expire according to their advertised lifetime so FindServersOnNetwork
  does not return servers that have stopped advertising.
- **FR-007**: All multicast discovery code MUST be behind a new, OFF-BY-DEFAULT build feature; with the
  feature disabled the third-party multicast dependency MUST be absent and all existing behavior
  (pull-based FindServersOnNetwork, RegisterServer/RegisterServer2) MUST be byte-identical to today.
- **FR-008**: Code on the multicast path parses untrusted packets from the network and therefore MUST NOT
  panic, MUST bound all attacker-influenced allocations, and MUST reject malformed records with an error or
  skip rather than undefined/abortive behavior.
- **FR-009**: Enabling multicast discovery in an environment where multicast is unavailable MUST NOT crash or
  block the server; advertising and discovery degrade to a no-op and the rest of the server runs normally.
- **FR-010**: The third-party multicast dependency MUST satisfy the project's dependency policy: it MUST pass
  the security advisory/license gate, and its addition MUST be recorded with justification. It MUST NOT break
  the project's minimal (dependency-light) build.
- **FR-011**: The project MUST build and pass tests both with the feature DISABLED (dependency absent) and
  ENABLED (dependency present), and the advisory gate MUST stay green in both.
- **FR-012**: The deterministic parts of the feature — the announcement metadata format (service record +
  capability/path metadata) and the mapping from a discovered announcement to a network record — MUST be
  covered by tests that do not require real network multicast.

### Key Entities

- **Service announcement**: the server's self-advertisement — its discovery address (host, port, path) and
  capability metadata — published on the local network and withdrawn on shutdown (Part 12 service record +
  TXT metadata).
- **Discovered server record**: a network-discovered OPC UA server expressed as the standard
  FindServersOnNetwork network record (discovery URL, server name, advertised capabilities, record id),
  carrying an advertised lifetime for expiry.
- **Discovery cache**: the set of currently-known discovered records, kept current as announcements arrive
  and expire, consulted by FindServersOnNetwork and merged with the pull-based registered servers.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: With multicast discovery enabled, a server's self-announcement is visible to an independent
  mDNS/DNS-SD browser on the same segment, showing the correct discovery address and capabilities.
- **SC-002**: With two servers on a segment, FindServersOnNetwork on one returns the other (advertised)
  server with a correct discovery URL, merged with any registered servers and de-duplicated.
- **SC-003**: A non-empty capability filter includes a discovered server whose advertised capabilities
  satisfy it and excludes one whose do not (previously such a filter returned nothing).
- **SC-004**: With multicast discovery disabled (default and minimal builds), the multicast dependency is
  absent and FindServersOnNetwork / RegisterServer behavior is identical to the prior release.
- **SC-005**: The project builds and its tests pass with the feature disabled and with it enabled, and the
  dependency advisory gate passes in both configurations.
- **SC-006**: No multicast-path code panics or allocates unboundedly on malformed/hostile announcements
  (verified by tests over malformed record inputs); enabling the feature where multicast is blocked does not
  crash or hang the server.

## Assumptions

- The existing pull-based FindServersOnNetwork and the RegisterServer/RegisterServer2 registry
  (`info.rs` registered-servers store + `find_servers_on_network`) and the generated
  `MdnsDiscoveryConfiguration` / `ServerOnNetwork` types are reused; this feature only ADDS the
  advertise-and-discover path and merges its results in.
- "Users" = server operators enabling discovery + OPC UA clients calling FindServersOnNetwork + maintainers
  who build/ship the product. Outcomes are framed as observable discovery results and build configurations.
- The chosen multicast library is a pure-Rust DNS-SD implementation supporting both advertising and browsing,
  so the project's minimal dependency-light build is preserved when the feature is enabled (and the library
  is absent entirely when it is disabled). The specific crate is an implementation/plan detail.
- Multicast service discovery is inherently local-segment and best-effort; FindServersOnNetwork over
  multicast returns whatever is currently discoverable and is not expected to be globally consistent.
- The standard OPC UA service type and the `path` / `caps` metadata keys follow OPC UA Part 12; per-record
  capability semantics follow Part 12 §A.1 capability identifiers.
- Real-multicast end-to-end behavior is environment-dependent; the binding/format logic is verified by
  network-free unit tests, with multicast end-to-end tests written to tolerate environments that block the
  multicast group.
