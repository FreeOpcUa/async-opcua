# Feature Specification: Client Query Service (QueryFirst / QueryNext)

**Feature Branch**: `023-client-query-service`
**Created**: 2026-06-22
**Status**: Draft
**Input**: Expose the OPC UA Query service on the async-opcua client and verify the full Query path
end-to-end. Conformance Tier 3 facet #7.

## Context *(mandatory)*

OPC UA defines a **Query** service (QueryFirst / QueryNext) that lets a client find nodes across the
address space by type and content filter, returning selected attribute/value data sets with pagination.

In async-opcua the **server side is already implemented**: the in-memory node manager (which backs the
standard/core address space) handles Query via dedicated QueryFirst/QueryNext handlers supporting node-
type descriptions, content filters, graph traversal, data-set selection, and authorization filtering.
The conformance backlog's claim that the core address space "doesn't implement Query" is **stale**.

The real gap is the **client**: the async-opcua client exposes **no** Query API, so applications built on
it cannot issue Query requests, and the server Query handler has **no integration-test coverage**. This
feature adds the client-side Query methods and verifies the end-to-end path (which also becomes the first
real test of the server handler).

## User Scenarios & Testing *(mandatory)*

### User Story 1 — Issue Query from the client (Priority: P1) 🎯 MVP

As a developer using the async-opcua client, I want to issue QueryFirst and QueryNext requests so my
application can find nodes by type and filter and page through the results.

**Why this priority**: Without a client API, Query is unusable from this SDK; it is the core deliverable
and is independently testable.

**Independent Test**: Call the new client QueryFirst method with a node-type description over the core
address space and receive decoded data sets (plus a continuation point where applicable); call QueryNext
with that continuation point and receive the next batch; error/empty cases return the documented status.

**Acceptance Scenarios**:

1. **Given** a connected session, **When** the client issues QueryFirst for a node type with selected
   attributes, **Then** it receives the matching data sets (and a continuation point if the result is
   paged), with the operation status surfaced faithfully.
2. **Given** a QueryFirst result with a continuation point, **When** the client issues QueryNext with it,
   **Then** it receives the next batch of data sets.
3. **Given** a QueryNext continuation point and a "release" request, **When** issued, **Then** the
   continuation point is released and no further data is returned.
4. **Given** a malformed or unsupported Query request, **When** issued, **Then** the client surfaces the
   server's status code (no panic, no hang).

---

### User Story 2 — Verify Query end-to-end against the server (Priority: P2)

As a maintainer, I want the full Query path exercised against the running server through the new client
API, so the (previously untested) server handler is proven and conformance regressions are caught.

**Why this priority**: First real coverage of the server Query handler; depends on US1.

**Independent Test**: An integration run brings up the server and, through the client, runs a type-
filtered QueryFirst over the core address space (asserting expected nodes appear), paginates via
QueryNext, checks an empty/no-match query returns the documented status, asserts a non-default/unknown
view is rejected with the documented status, and confirms authorization is respected (no nodes the
session may not read are returned). Any server-side defect surfaced is fixed minimally.

**Acceptance Scenarios**:

1. **Given** the core address space, **When** a QueryFirst selects nodes of a known object type with one
   or two attributes, **Then** the expected nodes/attributes are returned.
2. **Given** a result larger than the batch limit, **When** paged via QueryNext, **Then** all data sets
   are retrieved across batches without duplication or loss.
3. **Given** an empty/no-match query, **When** issued, **Then** the documented status (or an empty
   result) is returned, not an error or panic.
4. **Given** a non-default / unknown view, **When** queried, **Then** it is rejected with the documented
   status code.
5. **Given** a session with limited read authorization, **When** it queries, **Then** unauthorized nodes
   are not returned.

---

### User Story 3 — Demo/doc + continuation-release (Priority: P3, optional)

As a developer, I want a short example/doc of a Query against the demo server and a verified
continuation-point release path, if they fall out cheaply.

**Why this priority**: Nice-to-have documentation + completeness; depends on US1/US2.

**Acceptance Scenarios**:

1. **Given** the docs/example, **When** followed, **Then** a Query against the demo server returns
   results.
2. **Given** an outstanding continuation point, **When** released via QueryNext, **Then** the server
   frees it and subsequent use of it fails with the documented status.

---

### Edge Cases

- **Empty / no-match** query → documented status (e.g. nothing-to-do) or empty result, never a panic.
- **Non-default / unknown view** → documented rejection status.
- **Paged result** → QueryNext retrieves all data sets without loss/duplication; releasing the
  continuation point stops further data.
- **Malformed / oversized** Query input → bounded by existing server limits; surfaced status, no panic.
- **Authorization** → a session does not receive nodes it is not permitted to read.

## Requirements *(mandatory)*

- **FR-001**: The client MUST expose a QueryFirst operation that takes a view, node-type descriptions, a
  content filter, and the result-size limits, and returns the decoded query data sets, the continuation
  point (if any), and the operation status/diagnostics — built from the session context, mirroring the
  existing client service-method pattern.
- **FR-002**: The client MUST expose a QueryNext operation that takes a continuation point and a
  release flag and returns the next batch of data sets (or releases the continuation point).
- **FR-003**: Both client operations MUST surface the server's StatusCode faithfully (success, empty/
  nothing-to-do, and bad-input/unsupported codes) without panicking or hanging.
- **FR-004**: The feature MUST be verified end-to-end against the running server through the new client
  API: a type-filtered QueryFirst over the core address space returns expected data sets; QueryNext
  paginates a multi-batch result; an empty query returns the documented status; a non-default/unknown
  view is rejected with the documented status; authorization is respected.
- **FR-005**: The feature MUST be **additive / non-breaking**: only new client methods are added;
  existing client methods, the server handler's public behavior, and the wire types are unchanged. A
  genuine server-handler defect surfaced by the new tests MAY be fixed minimally (correctness over
  completion) without redesigning the handler.
- **FR-006**: No new runtime dependency; the workspace MUST build and lint clean (`clippy --all-targets
  --all-features` plus the no-default-features / json-off legs under `-D warnings`); existing suites
  pass; integration tests run reliably (single-threaded per the known parallel-load flakiness).
- **FR-007** (Security): A Query MUST NOT return nodes the session is not authorized to read, and
  malformed/oversized Query input MUST be handled without panic (bounded by existing server limits).

### Key Entities *(include if feature involves data)*

- **QueryFirst request**: view, list of node-type descriptions (type + selected attributes/relative
  paths), content filter, max-data-sets / max-references limits → data sets + continuation point +
  status.
- **QueryNext request**: continuation point + release flag → next data sets (or release).
- **Query data set**: a matched node id + its selected attribute values.

## Success Criteria *(mandatory)*

- **SC-001**: A client application can issue QueryFirst and QueryNext and receive decoded results via the
  new API.
- **SC-002**: A type-filtered QueryFirst over the core address space returns the expected nodes, and a
  multi-batch result is fully retrieved via QueryNext (no loss/duplication) — verified end-to-end.
- **SC-003**: Empty/no-match → documented status; non-default/unknown view → documented status;
  unauthorized nodes are not returned; no operation panics or hangs.
- **SC-004**: `clippy --all-targets --all-features` + the no-default-features / json-off legs are clean
  under `-D warnings`; no new runtime dependency; existing unit + integration suites pass.

## Assumptions

- **Server Query is already implemented** (in-memory/core handlers); this feature adds the client API and
  the first end-to-end tests. The backlog's "CoreNodeManager doesn't implement Query" is stale and will
  be corrected.
- **Verification division** (established): the client Query methods (and any minimal server-handler fix
  surfaced by testing) may be implemented by the code-generation assistant; ALL tests are authored and
  run independently, anchored to OPC UA Part 4 §5.9 Query semantics and real client↔server round-trips
  (not author-loopback).
- **Out of scope / deferred**: redesigning the server Query handler; Query over non-core / non-in-memory
  node managers; cross-node-manager federated query; new query capabilities beyond what the server
  handler already supports.
