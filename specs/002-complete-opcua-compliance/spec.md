# Feature Specification: Complete OPC UA Compliance

**Feature Branch**: `002-complete-opcua-compliance`  
**Created**: 2026-06-06  
**Status**: Draft  
**Input**: User description: "continue to implement OPC-UA as laid out in the document in ./local"

## Clarifications

### Session 2026-06-06
- Q: What is the scope of OPC UA PubSub transport mappings? → A: All four transport mappings (MQTT, AMQP, WebSockets, and UDP multicast) are fully in scope.
- Q: Should the HDA backend be in-memory or database-backed? → A: A concrete SQLite storage backend must be implemented or hardened.
- Q: How should OAuth2 signature keys be verified? → A: Use a locally cached trust store of public keys/certificates (no remote HTTP JWKS fetching at runtime).
- Q: How should discovery certificate renewal be implemented? → A: Implement standard OPC UA GDS push/pull certificate management methods (Part 12).
- Q: Where should temporary file transfers be stored? → A: Store in a configurable directory path with default file size/count limits in server settings.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Complete PubSub Interoperability (Priority: P1)

An enterprise integration engineer needs the product to publish and subscribe to OPC UA PubSub data across every transport mapping called out by the roadmap, so factory-floor, brokered, and cloud consumers can interoperate without custom bridges.

**Why this priority**: PubSub is the largest remaining compliance gap and directly affects unified namespace and high-volume telemetry deployments.

**Independent Test**: Configure brokered and brokerless PubSub exchanges, publish changing equipment values, and verify compliant subscribers receive ordered binary and structured messages over each supported mapping.

**Acceptance Scenarios**:

1. **Given** a configured dataset with multiple measured values, **When** values change, **Then** subscribers receive standards-aligned binary messages over brokerless multicast with sequence information that allows missing packets to be detected.
2. **Given** a brokered PubSub connection, **When** values are published through a supported broker mapping, **Then** subscribers receive structured messages using the expected topic and payload conventions.
3. **Given** broker connectivity is unavailable, **When** telemetry continues changing, **Then** the system retries delivery and bounds local buffering to prevent uncontrolled memory growth.

---

### User Story 2 - Harden Discovery and Certificate Lifecycle (Priority: P1)

A security administrator needs applications to register with enterprise discovery services and rotate certificates without manual downtime, while continuing to operate safely when the discovery service is temporarily unavailable.

**Why this priority**: Certificate lifecycle automation is central to secure enterprise OPC UA deployments.

**Independent Test**: Register an application with a discovery service, trigger certificate renewal, confirm active clients remain connected, then simulate discovery-service outage and verify cached credentials keep the application available.

**Acceptance Scenarios**:

1. **Given** an application is enrolled with a discovery service, **When** a certificate renewal is requested, **Then** the application obtains and applies renewed credentials without interrupting active sessions.
2. **Given** the discovery service is unavailable at startup, **When** valid cached credentials exist, **Then** the application starts with those credentials and records an operator-visible warning.
3. **Given** renewal fails during runtime, **When** the current certificate is still valid, **Then** the application keeps serving clients and retries renewal in the background.

---

### User Story 3 - Enforce Modern Security and Enterprise Identity (Priority: P1)

A security officer needs weak security profiles disabled by default and OAuth2-issued identities validated against trusted identity providers before access is granted to protected address-space resources.

**Why this priority**: Secure-by-default behavior and centralized identity validation are required before the advanced features can be safely used in production.

**Independent Test**: Attempt connections with deprecated security profiles and invalid issued tokens, then verify they are rejected; authenticate with a valid signed issued token and verify role-scoped access decisions.

**Acceptance Scenarios**:

1. **Given** a client offers a deprecated security profile without explicit legacy enablement, **When** it attempts a secure session, **Then** the connection is rejected before application data is exchanged.
2. **Given** an issued identity token has an invalid signature, issuer, audience, expiry, or key identifier, **When** it is used for session activation, **Then** activation is rejected with a standards-appropriate identity status.
3. **Given** an issued identity token is valid, **When** the user reads, writes, acknowledges alarms, or starts programs, **Then** access is granted or denied according to mapped roles and claims.

---

### User Story 4 - Complete Information Model and Companion Spec Coverage (Priority: P2)

An automation engineer needs large standard and vendor companion models to load, validate, and generate usable data types so complex devices can be represented without hand-written model patches.

**Why this priority**: Companion specifications are necessary for practical interoperability with domain-specific industrial equipment.

**Independent Test**: Load representative DI, AutoID, PLCopen, and vendor-style model files, including external type dictionaries and cross-model dependencies, then verify nodes, references, encodings, and generated structures are available.

**Acceptance Scenarios**:

1. **Given** a companion model depends on another model, **When** both are imported, **Then** cross-model references resolve in deterministic dependency order.
2. **Given** a model contains custom structured, optional, union, enum, and array fields, **When** types are generated, **Then** clients can encode, decode, compare, and inspect those values through standard OPC UA data representations.
3. **Given** a malformed or incomplete vendor model is imported, **When** recovery is possible without changing semantics, **Then** the system reports actionable diagnostics and imports valid content.

---

### User Story 5 - Complete Historical Data Access (HDA) and Aggregate Behavior (Priority: P2)

A production analyst needs historical reads, updates, continuation points, and processed aggregates to behave consistently for large datasets and edge-case data quality.

**Why this priority**: Existing historical and aggregate support needs conformance hardening before it can be relied on for audits and reporting.

**Independent Test**: Query large historical ranges, release and expire continuation points, perform authorized and unauthorized updates, and compare aggregates against reference calculations over mixed-quality data.

**Acceptance Scenarios**:

1. **Given** a large historical range exceeds one response, **When** a client pages through results, **Then** every record is returned once in chronological order and continuation resources are released or expired.
2. **Given** a user lacks history modification rights, **When** that user attempts to update or delete historical data, **Then** the operation is denied and no data is changed.
3. **Given** requested aggregate intervals contain bad, uncertain, missing, or boundary-spanning values, **When** processed data is requested, **Then** calculated results and quality indicators follow documented OPC UA aggregate behavior.

---

### User Story 6 - Complete Stateful Server Features (Priority: P2)

An operator needs alarm, event, program, and temporary file workflows to survive realistic session behavior, authorization boundaries, and lifecycle cleanup without leaking state or resources.

**Why this priority**: The first implementation added these feature families; this continuation must harden them against production lifecycle and interoperability cases.

**Independent Test**: Exercise alarms, program control, and temporary file transfers across authorized users, unauthorized users, normal session close, timeout, and abrupt disconnect.

**Acceptance Scenarios**:

1. **Given** a condition changes state, **When** subscribed clients filter for relevant events, **Then** they receive the correct event fields and state transitions in order.
2. **Given** a program is started, suspended, resumed, halted, or reset, **When** invalid transitions are requested, **Then** the system rejects them and preserves the previous valid state.
3. **Given** a temporary file transfer is active, **When** the session closes, times out, or disconnects abruptly, **Then** all transfer nodes and backing files are removed and cannot be reused by other sessions.

---

### Edge Cases

- Discovery service outage during startup, renewal, and active session establishment.
- Broker outage, slow broker acknowledgments, multicast packet loss, packet reordering, and payloads larger than the network path can carry in one datagram.
- Companion models with missing dictionaries, duplicate names, cyclic dependencies, unknown encodings, namespace collisions, or vendor extensions.
- Historical queries with zero-length ranges, reversed ranges, huge ranges, sparse data, duplicate timestamps, and mixed source/server timestamps.
- OAuth2 tokens with expired claims, future claims, unknown key identifiers, wrong audience, wrong issuer, unsupported algorithms, malformed content, or revoked signing keys.
- Session termination while continuation points, alarms, program tasks, or file transfers are active.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: System MUST support all brokered and brokerless PubSub transport mappings identified by the OPC UA PubSub roadmap, including MQTT, AMQP, WebSockets, and UDP multicast.
- **FR-002**: System MUST support standards-aligned binary and structured PubSub message formats for dataset values, metadata, sequence tracking, and subscriber validation.
- **FR-003**: System MUST bound PubSub buffering during broker or network failure and MUST retry delivery without blocking normal client-server sessions.
- **FR-004**: System MUST support enterprise discovery registration, certificate request, renewal via standard GDS push/pull methods (Part 12), trust-list handling, cached credential fallback, and operator-visible renewal status.
- **FR-005**: System MUST reject deprecated security profiles by default unless a deployment explicitly enables legacy interoperability.
- **FR-006**: System MUST prefer active modern security profiles for newly generated secure endpoints and configuration examples.
- **FR-007**: System MUST validate issued identity tokens using a locally cached trust store of signing keys (without remote runtime HTTP requests), issuer rules, audience rules, time claims, and token algorithms before accepting a session.
- **FR-008**: System MUST map validated identity claims to access decisions for reads, writes, alarm actions, program actions, history updates, and temporary file operations.
- **FR-009**: System MUST redact passwords and key material from logs and MUST log issued-token identifiers only as safe hashes or similarly non-secret identifiers.
- **FR-010**: System MUST import and validate companion and vendor information models with external type dictionaries, custom structured types, cross-namespace references, and deterministic dependency ordering.
- **FR-011**: System MUST provide clear diagnostics for model import failures, including the affected model, namespace, type, field, and reference where available.
- **FR-012**: System MUST preserve historical query ordering, half-open range behavior, continuation lifecycle behavior, and authorization checks for read and modification operations, backed by a concrete SQLite storage implementation.
- **FR-013**: System MUST calculate historical aggregates with documented handling for boundary values, missing values, bad values, uncertain values, and interval quality.
- **FR-014**: System MUST enforce valid state transitions for alarms and programs and reject invalid transitions without changing existing state.
- **FR-015**: System MUST clean up session-bound temporary resources, including file-transfer nodes, backing files (stored in a configurable directory with file size/count limits), and continuation state, on normal close, timeout, and abrupt disconnect.
- **FR-016**: System MUST expose enough user-facing diagnostics for operators to understand rejected security profiles, token failures, discovery failures, model import failures, and resource cleanup failures without exposing secrets.

### Key Entities *(include if feature involves data)*

- **PubSub Dataset**: A collection of published values, metadata, writer identity, sequence state, and transport-specific routing information.
- **Discovery Enrollment**: The relationship between an application, its discovery registration, certificate request state, trust-list state, and cached credentials.
- **Issued Identity**: A token-backed user identity with validated issuer, audience, signing key, claims, expiry, and mapped authorization scope.
- **Companion Model**: An imported information model with namespaces, nodes, references, type dictionaries, encodings, and dependency relationships.
- **Historical Result Window**: A bounded response page with ordered values, range metadata, continuation state, and release or expiry behavior.
- **Stateful Session Resource**: A session-scoped resource such as a continuation point, temporary file, active program context, or alarm action context that must be cleaned up deterministically.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Interoperability tests demonstrate successful PubSub exchange over every in-scope transport mapping with at least two independent subscriber configurations per mapping.
- **SC-002**: Deprecated security profiles are rejected by default in 100% of negative security tests, while explicitly enabled legacy deployments remain testable.
- **SC-003**: Valid signed issued tokens are accepted and invalid issued tokens are rejected across at least 95% of the token edge cases listed in this specification.
- **SC-004**: Discovery renewal tests show certificate rotation completes without dropping active sessions in repeated runs.
- **SC-005**: Companion model tests import representative DI, AutoID, PLCopen, and vendor-style models with zero unresolved required references.
- **SC-006**: Historical pagination tests retrieve at least 100,000 records with no duplicates, no missing records, and bounded server memory use.
- **SC-007**: Aggregate conformance tests match reference calculations and quality outcomes for normal, sparse, bad-quality, and boundary-spanning intervals.
- **SC-008**: Session cleanup tests leave zero registered temporary resources after normal close, timeout, and abrupt disconnect scenarios.

## Assumptions

- The previously merged OPC UA standard-support implementation is the baseline; this feature focuses on the remaining compliance and hardening gaps from the local roadmap.
- In-scope PubSub mappings include MQTT, AMQP, WebSockets, and UDP multicast because the existing specification called for all mappings identified by OPC UA PubSub.
- Enterprise identity validation uses locally cached trusted signing material where possible to avoid introducing a remote dependency for every session activation.
- Formal OPC Foundation certification is outside this feature, but the feature should produce evidence suitable for later certification preparation.
- Backward compatibility with legacy industrial equipment is preserved only through explicit opt-in settings.
