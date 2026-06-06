# Feature Specification: Implement OPC-UA Standard Support Plan

**Feature Branch**: `001-implement-opc-ua-spec`  
**Created**: 2026-06-06  
**Status**: Draft  
**Input**: User description: "use the plan in local/ to implement the full OPC-UA spec"

## Clarifications

### Session 2026-06-06
- Q: Which transport protocols are in-scope for the PubSub implementation, and which should be explicitly declared out-of-scope? → A: All transport protocols defined in IEC 62541-14 are in-scope.
- Q: How should the OPC-UA server handle persistent connection failures with the external MQTT broker? → A: Log the error, attempt to reconnect using an exponential backoff policy indefinitely, and cache local telemetry updates up to a configurable memory limit.
- Q: How should the NodeIds of Condition (Alarm) instances and Program instances dynamically added to the Address Space be constructed to guarantee uniqueness? → A: Generate NodeIds in the server's dynamic namespace using String identifiers derived from a combination of the device/source identifier and the Alarm/Program type (e.g., ns=2;s=Alarm_<Device>_<Type>).
- Q: What is the specific data redaction policy for security tracing/logging of unencrypted network payloads? → A: Redact passwords and keys, but log truncated or SHA-256 hashed versions of JWT tokens to facilitate session identity debugging.
- Q: How should the OPC-UA server behave when the Global Discovery Server (GDS) is unreachable during startup or dynamic certificate renewal? → A: During startup, log a warning and run with the last known valid cached certificate; during runtime renewal, retry periodically in the background while keeping the active certificate active until expiration.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Real-Time Alarm & Event Management (Priority: P1)

An industrial control operator needs to be notified immediately when equipment enters an abnormal state (e.g., temperature threshold exceeded). The system must transition the alarm through standard lifecycles (Enabled, Active, Acknowledged, Confirmed) and allow authorized users to acknowledge or confirm the alarm.

**Why this priority**: Immediate visibility into abnormal equipment conditions is safety-critical and core to industrial operations.

**Independent Test**: Can be verified by triggering an out-of-bounds telemetry value, confirming the alarm state machine updates, receiving the event notification on a test client, and successfully issuing an acknowledgment call.

**Acceptance Scenarios**:

1. **Given** a machine is operating normally, **When** temperature exceeds the critical threshold, **Then** an Alarm Condition is created in the Active and Unacknowledged states, and an event notification is dispatched to all subscribed clients.
2. **Given** an active and unacknowledged alarm, **When** an authorized operator sends an acknowledgment request, **Then** the alarm transitions to the Acknowledged state, updating its status variables, and a state-change event is dispatched.

---

### User Story 2 - Historical Telemetry Access & Auditing (Priority: P1)

A production analyst needs to retrieve precise historical data logs over specific time intervals to analyze trend lines or perform security and operational audits. The analyst also needs the ability to correct or update historical data points when sensors malfunction, using standard pagination to retrieve large data sets without impacting server performance.

**Why this priority**: Regulatory reporting, diagnostic auditing, and external data analysis require reliable access to historical records.

**Independent Test**: Can be tested by writing 10,000 data points, executing a history read request with a specific page limit, and verifying that all records are retrieved sequentially using returned continuation points.

**Acceptance Scenarios**:

1. **Given** historical telemetry exists for a sensor, **When** a client queries data over a half-open interval `[start, end)`, **Then** the server returns the chronologically ordered records up to the maximum page size along with a continuation point token.
2. **Given** an active continuation point token, **When** the client sends a subsequent query with the token, **Then** the server resumes retrieval from the exact sequence point.

---

### User Story 3 - Decoupled PubSub Telemetry Publishing (Priority: P1)

An enterprise analytics platform needs to subscribe to real-time industrial telemetry from hundreds of edge devices simultaneously without establishing point-to-point connection-oriented sessions for each device.

**Why this priority**: Scalability in high-volume IoT and Unified Namespace (UNS) architectures requires a decoupled publish-subscribe model.

**Independent Test**: Can be tested by configuring a dataset publisher, mapping changes in the local address space, and verifying that updates are successfully broadcast via broker-based (MQTT) or brokerless (UDP multicast) channels without client sessions.

**Acceptance Scenarios**:

1. **Given** a PubSub connection and a DataSetWriter are configured, **When** values in the server's Address Space change, **Then** structured JSON or binary UADP messages are published to the configured topic or multicast group at the specified intervals.

---

### User Story 4 - Managed Program Execution (Priority: P2)

A manufacturing supervisor needs to coordinate long-running complex operations (e.g., a batch recipe or CNC cycle) represented as state machines on the machine, controlling their state (Start, Suspend, Resume, Halt) and tracking execution asynchronously.

**Why this priority**: Managing complex execution states is required for batch processing and automated production sequencing.

**Independent Test**: Can be verified by invoking standard program methods (Start, Halt) and verifying that the Program transitions through the correct states (Running, Halted) while reporting progress.

**Acceptance Scenarios**:

1. **Given** a program is in the Ready state, **When** a client calls the Start method, **Then** the program transitions to the Running state and initiates its task context.

---

### User Story 5 - On-Demand Mathematical Aggregates (Priority: P2)

An edge dashboard needs to query time-weighted averages, maximums, and standard deviations of data points directly from the server over specified intervals without retrieving raw, high-volume datasets.

**Why this priority**: Offloading analytical calculations to the edge server reduces network utilization and improves dashboard load times.

**Independent Test**: Can be verified by querying a specific mathematical aggregate over a historical dataset and comparing the server's calculated output against a reference calculation.

**Acceptance Scenarios**:

1. **Given** historical raw data points, **When** a client requests a calculated average over 1-hour intervals, **Then** the server returns the calculated average values with appropriate data quality flags for each interval.

---

### User Story 6 - Global Discovery & Certificate Management (Priority: P2)

A security administrator needs edge servers to dynamically register with a Global Discovery Server (GDS) and automatically request and renew certificates to ensure zero-downtime operations and secure identity validation.

**Why this priority**: Automating security credential rotation is essential for maintaining a secure network posture without manual administrator overhead.

**Independent Test**: Can be verified by triggering a certificate renewal event and validating that the server receives and applies the new certificate.

**Acceptance Scenarios**:

1. **Given** a server is registered with a GDS, **When** a certificate renewal request is triggered, **Then** the server secures a new signed certificate and applies it dynamically without interrupting active client connections.

---

### User Story 7 - Custom Companion Specification Integration (Priority: P3)

An automation engineer needs to import industry-standard domain models (e.g. DI, AutoID, PLCopen) directly into the environment to represent specialized hardware devices.

**Why this priority**: Companion specifications allow the framework to support specialized vendor equipment and industry models out-of-the-box.

**Independent Test**: Can be verified by loading a custom companion specification XML NodeSet and checking that corresponding address space nodes are created.

**Acceptance Scenarios**:

1. **Given** a companion NodeSet XML file, **When** imported, **Then** the server instantiates the custom types and structures in its Address Space.

---

### User Story 8 - Secure Firmware Transmission & OAuth2 Identity (Priority: P3)

An operator needs to perform secure firmware updates (FOTA) via temporary file transfers isolated to the user session, and authenticate using modern OAuth2 JSON Web Tokens (JWT) for fine-grained access control.

**Why this priority**: High-security industrial environments require centralized identity management and secure mechanism for device updates.

**Independent Test**: Can be verified by attempting to upload a firmware file using a session-bound temporary file transfer node, and verifying the file is cleaned up after the session ends.

**Acceptance Scenarios**:

1. **Given** an active client session authenticated via OAuth2 JWT, **When** a firmware file transfer is initiated, **Then** a session-bound temporary file node is created to receive the stream, and the file is processed and cleaned up on session termination.

---

### Edge Cases

- **Session Abrupt Disconnect**: What happens when a client starts a pagination query or a temporary file transfer but disconnects abruptly? The server must clean up continuation points and session-bound temporary files to prevent resource exhaustion.
- **Uncertain Data Quality**: How does the system handle mathematical aggregates when some historical data points within the queried interval have bad or uncertain quality status? The server must propagate the quality status to the aggregate outcome according to standard rules.
- **Network Congestion during PubSub**: How does the system handle brokerless UDP multicast when the network is congested and packets are dropped? Payloads exceeding MTU must be managed, and packet sequence numbers must be updated to enable subscribers to identify missing frames.
- **MQTT Broker Connection Loss**: When connection to the broker is lost, the publisher must queue messages locally up to a configured threshold and reconnect using exponential backoff to avoid data loss.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: System MUST support Alarms and Conditions state machine transitions (EnabledState, ActiveState, AckedState, ConfirmedState) in accordance with the standard.
- **FR-002**: System MUST emit Event Notifications when condition states change.
- **FR-003**: System MUST validate client authorization and identity before permitting alarm acknowledgments or confirmations.
- **FR-004**: System MUST support historical data queries over half-open intervals `[start, end)` using pagination (continuation points).
- **FR-005**: System MUST enforce user permission checks (e.g., history update bitflag) before executing historical data modifications.
- **FR-006**: System MUST support PubSub configuration modeling including Connections, Groups, and DataWriters.
- **FR-007**: System MUST support binary datagram (UADP) and JSON message formats for PubSub data distribution.
- **FR-008**: System MUST support all PubSub transport mappings defined in IEC 62541-14 (including broker-based MQTT/AMQP/WebSockets and brokerless UDP multicast).
- **FR-009**: System MUST model Program State Machines and allow client-directed execution control (Start, Suspend, Resume, Halt).
- **FR-010**: System MUST support mathematical aggregate calculations (averages, mins, maxs, std deviations) on historical data.
- **FR-011**: System MUST support automatic application registration and secure certificate management with a Global Discovery Server (GDS).
- **FR-012**: System MUST support parsing and generating structures from custom XML NodeSets and companion specifications.
- **FR-013**: System MUST support disabling deprecated security profiles by default and isolating them as opt-in configurations via a compile-time legacy-crypto feature flag.
- **FR-014**: System MUST support modern token-based OAuth2 identity validation for sessions.
- **FR-015**: System MUST support temporary file transfer sessions isolated to active client connections.
- **FR-016**: System MUST support a default history storage engine option, provided via an optional sub-crate for SQLite history storage (e.g. async-opcua-history-sqlite).
- **FR-017**: System MUST handle MQTT broker connection failures by executing an exponential backoff reconnection policy indefinitely while caching outbound telemetry messages up to a configurable cache limit.
- **FR-018**: Dynamic runtime Alarm and Program NodeIds MUST be created in the dynamic namespace using String identifiers following the pattern `Alarm_<Device>_<Type>` or `Program_<Device>_<Name>` to guarantee predictability and uniqueness.
- **FR-019**: Logging and tracing systems MUST completely redact user passwords and cryptographic keys with a `[REDACTED]` placeholder, while logging SHA-256 hashed versions of OAuth2 JWT tokens to support session identity debugging.
- **FR-020**: When the GDS is unreachable during startup, the server MUST log a warning and proceed using its last cached certificate; on dynamic renewal failure, the server MUST retry periodically in the background and continue running with the active certificate.

### Key Entities *(include if feature involves data)*

- **Condition Object**: Represents an abnormal state in the address space with sub-states (Enabled, Active, Acked, Confirmed).
- **Historical Data Record**: Represents persisted telemetry data values consisting of a timestamp, value, and status quality code.
- **PubSub Configuration**: Defines the publisher/subscriber connection details, message structures, dataset mappings, and transmission schedules.
- **Program Object**: Represents an executable operational sequence with controllable states (Ready, Running, Suspended, Halted).

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: 100% compliance of Alarms and Conditions state transitions with the IEC 62541-9 standard, validated by automated test suites.
- **SC-002**: Clients can successfully fetch 100,000 historical telemetry records using paginated continuation points without request timeouts or server out-of-memory issues.
- **SC-003**: PubSub message dispatch latency (from Address Space change to broker publication) is under 50 milliseconds for up to 1,000 monitored variables.
- **SC-004**: Security audits verify that any active connections negotiating deprecated security profiles are rejected by default.

## Assumptions

- Edge machines running the OPC-UA server have sufficient memory and CPU resources to maintain in-memory state machines for active programs and alarms.
- The GDS is accessible over the network for registration and certificate signing requests.
- The underlying operating system supports standard UDP multicast interfaces for brokerless PubSub distribution.
