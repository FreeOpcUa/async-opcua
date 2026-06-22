# Feature Specification: RegisterServer / RegisterServer2 (LDS registration)

**Feature Branch**: `024-lds-register-server`
**Created**: 2026-06-22
**Status**: Draft
**Input**: Implement RegisterServer / RegisterServer2 on the server so it can act as a Local Discovery
Server (LDS), and have FindServers return the registered servers. Conformance Tier 3 facet #8
(dependency-free part; FindServersOnNetwork / mDNS deferred).

## Context *(mandatory)*

OPC UA defines a discovery model in which a **Local Discovery Server (LDS)** lets other servers
**register** themselves (RegisterServer / RegisterServer2) so that clients calling **FindServers** on the
LDS learn about them. In async-opcua, FindServers and GetEndpoints already work, but RegisterServer /
RegisterServer2 currently return "service unsupported," so the server cannot act as an LDS.

This feature implements RegisterServer / RegisterServer2 with an in-memory registry and surfaces the
registered servers through FindServers. The async-opcua **client already exposes** `register_server()`
and `find_servers()`, so no client change is needed.

The network multicast discovery feature, **FindServersOnNetwork**, stays out of scope: it requires mDNS
(a new runtime dependency and an infrastructure/LDS-ME concern, not a requirement for a server or client
to operate). It remains a documented "service unsupported." This feature adds **no new dependency**.

## User Scenarios & Testing *(mandatory)*

### User Story 1 — A server registers with the LDS and appears in FindServers (Priority: P1) 🎯 MVP

As an operator running async-opcua as a discovery server, I want other servers to register themselves so
that clients calling FindServers discover them.

**Why this priority**: This is the core LDS-registration capability and is independently testable.

**Independent Test**: A client calls RegisterServer with a server description (online); a subsequent
FindServers returns that server. The client then registers it as offline; a subsequent FindServers no
longer returns it.

**Acceptance Scenarios**:

1. **Given** the server, **When** a client calls RegisterServer with `is_online = true`, **Then** the
   server is recorded and a subsequent FindServers includes it, described with the correct fields
   (application URI, name, type, discovery URLs).
2. **Given** a previously-registered server, **When** a client calls RegisterServer with
   `is_online = false`, **Then** it is removed and a subsequent FindServers no longer includes it.
3. **Given** a registered server, **When** the same server registers again with updated details, **Then**
   the registry reflects the update (no duplicate entry).
4. **Given** an empty registry (no registrations), **When** FindServers is called, **Then** the result is
   exactly as before this feature (the server's own description only) — no behavior change.

---

### User Story 2 — RegisterServer2 with discovery configuration (Priority: P2)

As a registering server using the richer registration call, I want RegisterServer2 to accept my
discovery configuration and tell me which parts it supports, while still registering me.

**Why this priority**: Completes the registration surface; depends on US1's registry.

**Independent Test**: A client calls RegisterServer2 with a discovery-configuration list including a
multicast (mDNS) configuration; the response returns a per-configuration result that marks the multicast
configuration as not supported, yet the server is still registered and appears in FindServers.

**Acceptance Scenarios**:

1. **Given** a RegisterServer2 call with a multicast/mDNS discovery configuration, **When** processed,
   **Then** the per-configuration result for that element is "not supported," the overall registration
   still succeeds, and FindServers includes the server.
2. **Given** a RegisterServer2 call, **When** processed, **Then** it updates the same registry as
   RegisterServer (consistent behavior).

---

### User Story 3 — Tests, doc, and documented FindServersOnNetwork deferral (Priority: P3)

As a maintainer, I want the registration path tested and the mDNS deferral documented so the scope is
clear.

**Why this priority**: Verification + documentation; depends on US1/US2.

**Acceptance Scenarios**:

1. **Given** the docs, **When** read, **Then** they explain that the server can act as an LDS for
   registration and that FindServersOnNetwork (multicast/mDNS) is intentionally not supported and why.
2. **Given** a FindServersOnNetwork request, **When** issued, **Then** the documented "service
   unsupported" status is returned (no panic).

---

### Edge Cases

- **Unregister** (`is_online = false`) for a server that was never registered → handled cleanly (no-op
  success), no panic.
- **Re-register / update** an existing server → single entry updated, no duplicates.
- **Registry bound**: a flood of distinct registrations must NOT exhaust memory — the registry is capped;
  registrations beyond the cap are handled deterministically (rejected or bounded) without unbounded
  growth or panic.
- **Malformed RegisteredServer** (missing server URI, empty names, very large discovery-URL lists) →
  handled without panic; the operation status reflects validity.
- **FindServers filters** (endpoint URL, locale, server-URIs) still apply to registered servers, and the
  server's own description is still returned.
- **Restart** → the registry is in-memory and non-persistent (registrations are lost), by design.

## Requirements *(mandatory)*

- **FR-001**: The server MUST implement RegisterServer: with `is_online = true`, record/update the server
  in an in-memory registry keyed by its server URI; with `is_online = false`, remove it. Return success.
- **FR-002**: FindServers MUST include the currently-registered (online) servers, each represented with
  the correct application description (application URI, localized application name, application type,
  gateway server URI, discovery URLs), in addition to the server's own description — while still honoring
  the existing FindServers filters (endpoint URL, locale, server URIs). An empty registry MUST leave
  FindServers behavior unchanged from today.
- **FR-003**: The server MUST implement RegisterServer2: update the same registry as RegisterServer, and
  return a per-configuration result for each supplied discovery configuration — marking the multicast/
  mDNS configuration as "not supported" while still registering the server (the overall call succeeds).
- **FR-004** (Security): The registry MUST be **bounded** (a configurable/sane maximum number of
  registered servers) so a malicious or buggy registrant cannot exhaust memory; registrations beyond the
  bound are handled deterministically with no unbounded growth and no panic. All RegisterServer(2) input
  MUST be processed without panic on malformed/oversized data. Registration MUST honor the existing
  channel/security enforcement (not weaken it).
- **FR-005**: The feature MUST be **additive / non-breaking**: existing FindServers/GetEndpoints behavior
  for deployments without registrations is unchanged; the registry is a new server-side component; no
  client API change (the client already has register_server / find_servers).
- **FR-006**: FindServersOnNetwork remains **not supported** (documented), returning the existing
  "service unsupported" status with no panic. No mDNS / multicast / LDS-ME functionality and **no new
  runtime dependency** are added.
- **FR-007**: The workspace MUST build and lint clean (`clippy --all-targets --all-features` plus the
  no-default-features / json-off legs under `-D warnings`); existing suites pass; integration tests run
  reliably (single-threaded per the known parallel-load flakiness).

### Key Entities *(include if feature involves data)*

- **Registered server**: the registering server's identity + discovery info (server URI, product URI,
  localized names, application type, gateway URI, discovery URLs, online flag), keyed by server URI.
- **Server registry**: a bounded, in-memory, non-persistent collection of registered (online) servers
  maintained by the LDS, surfaced through FindServers.
- **Discovery configuration result**: per-configuration status returned by RegisterServer2 (e.g. "not
  supported" for the multicast/mDNS element).

## Success Criteria *(mandatory)*

- **SC-001**: A client can register a server (online) and then see it returned by FindServers with the
  correct description; registering it offline removes it — verified end-to-end via the existing client.
- **SC-002**: RegisterServer2 registers the server and returns a "not supported" per-configuration result
  for the multicast/mDNS configuration, while still listing the server in FindServers.
- **SC-003**: With no registrations, FindServers/GetEndpoints behave exactly as before; the registry is
  bounded (a flood of registrations does not grow memory without limit) and no RegisterServer(2) input
  causes a panic.
- **SC-004**: FindServersOnNetwork returns the documented "service unsupported" status; no new runtime
  dependency is added.
- **SC-005**: `clippy --all-targets --all-features` + the no-default-features / json-off legs are clean
  under `-D warnings`; existing unit + integration suites pass.

## Assumptions

- **In-memory, non-persistent registry** keyed by server URI; bounded by a sane maximum. Stale-entry
  expiry (semaphore files / health checks) is out of scope.
- **The client already exposes** register_server() and find_servers(); this feature is server-side only.
- **Verification division** (established): the server handlers + registry + FindServers integration may be
  implemented by the code-generation assistant; ALL tests are authored and run independently, anchored to
  OPC UA Part 4 §5.4.5/§5.4.6 semantics and real client↔server round-trips via the existing client API.
- **Out of scope / deferred** (documented): FindServersOnNetwork and all mDNS / multicast / LDS-ME
  discovery (would require a new dependency); registry persistence across restarts; stale-registration
  expiry; being discovered by an external LDS via mDNS announcement.
