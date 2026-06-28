# Feature Specification: Performance Optimizations & Advanced Profiles

**Feature Branch**: `[004-performance-optimizations]`  
**Created**: 2026-06-07  
**Status**: Complete with documented TSN hardware-validation gap
**Input**: User description: "Refactor AddressSpace to use DashMap to remove global RwLock bottleneck, implement zero-copy TCP serialization in async-opcua-core/src/comms, switch history cache to async-aware LRU pruning, implement OPC-UA over TSN (Time-Sensitive Networking), and implement the OPC-UA Safety profile (Part 15)."

## Clarifications

### Session 2026-06-07
- Q: TSN Implementation Strategy → A: User-Space Raw Sockets (AF_XDP) with OS Kernel Driver (tc taprio) fallback.
- Q: Functional Safety Standard Target → A: Target SIL 3 (IEC 61508) requirements.
- Q: AddressSpace Concurrency Semantics → A: Accept weakly consistent iterators to maximize point read/write throughput.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - High-Concurrency Data Access (Priority: P1)

As a system operator, I need the server to handle thousands of concurrent read and write requests to the address space without degraded performance, so that large-scale SCADA systems can poll data efficiently.

**Why this priority**: Core bottleneck removal; enables high-scale deployments.

**Independent Test**: Can be independently load-tested by simulating multiple high-frequency concurrent client connections reading and writing to different nodes simultaneously.

**Acceptance Scenarios**:

1. **Given** a highly populated address space, **When** 10,000 concurrent clients read different nodes, **Then** the response time remains under 50ms and no single lock blocks the entire address space.

---

### User Story 2 - Real-Time Deterministic Communication (Priority: P1)

As a control engineer, I need to send and receive time-critical automation data over the network with guaranteed latency and no jitter, so that physical processes can be controlled precisely.

**Why this priority**: Required for time-sensitive industrial use cases.

**Independent Test**: Tested via specialized network hardware to ensure packet delivery meets strict timing boundaries.

**Acceptance Scenarios**:

1. **Given** a TSN-capable network infrastructure, **When** cyclic data is published, **Then** the transmission meets strict deterministic timing guarantees.

---

### User Story 3 - Functional Safety Communication (Priority: P1)

As a safety engineer, I need to transmit safety-critical signals (like emergency stops) reliably, so that the system complies with functional safety standards and fails safely in case of errors.

**Why this priority**: Crucial for industrial environments where human safety or equipment protection is required.

**Independent Test**: Can be tested by simulating network corruption, delays, and lost packets, verifying that the system enters a safe state.

**Acceptance Scenarios**:

1. **Given** a safety-critical connection, **When** network communication is delayed beyond the configured safety timeout, **Then** the receiver immediately transitions the safety data to a predefined safe state.

---

### User Story 4 - High-Throughput Network Serialization (Priority: P2)

As a system administrator, I need the server to minimize CPU and memory overhead when processing high volumes of network traffic, so that the server can handle more connections on the same hardware.

**Why this priority**: Improves overall efficiency and scalability.

**Independent Test**: Tested by sending large payloads and monitoring memory allocation rates and CPU usage.

**Acceptance Scenarios**:

1. **Given** large arrays of data being requested, **When** the server serializes the response, **Then** no unnecessary memory copying occurs, maintaining low CPU utilization.

---

### User Story 5 - Efficient Historical Data Management (Priority: P3)

As a data analyst, I need historical data queries to return quickly without causing out-of-memory errors on the server, so that I can reliably retrieve past trends.

**Why this priority**: Improves stability of historical queries.

**Independent Test**: Test by requesting massive historical datasets while restricting server memory, ensuring oldest items are pruned gracefully.

**Acceptance Scenarios**:

1. **Given** limited memory for history caching, **When** history queries exceed cache capacity, **Then** the oldest data is pruned asynchronously without blocking ongoing data collection.

### Edge Cases

- What happens when a TSN network loses synchronization?
- How does the system handle concurrent writes to the same exact node in the address space?
- What happens if a safety message payload is corrupted during transmission?
- How does the history cache behave under sustained heavy load that constantly evicts items?

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: System MUST process concurrent address space read and write operations without global locking blocking independent nodes, accepting weakly consistent iterators during bulk traversals to prioritize maximum point read/write throughput.
- **FR-002**: System MUST serialize and deserialize network payloads directly from/to network buffers without intermediate memory copying where possible.
- **FR-003**: System MUST provide an asynchronous memory-bounded cache for historical data that automatically evicts least recently used items.
- **FR-004**: System MUST implement Time-Sensitive Networking (TSN) transmission and reception mechanisms for guaranteed latency, utilizing User-Space Raw Sockets (AF_XDP) for peak reliability with automatic fallback to Kernel-Space Drivers (tc taprio) if unavailable.
- **FR-005**: System MUST implement the OPC-UA Safety profile (Part 15) targeting SIL 3 (IEC 61508) requirements to detect corruption, loss, delay, and reordering of safety data.

### Key Entities

- **Address Space Node**: Individual data points or objects that can be accessed concurrently.
- **Safety Protocol Data Unit (SPDU)**: The data packet carrying safety-critical information and validation signatures.
- **History Cache Entry**: A bounded historical data set for a specific node and time range.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Address space concurrent read/write throughput increases by at least 500% compared to the globally-locked implementation.
- **SC-002**: Memory allocation rate during peak network traffic is reduced by 80% through zero-copy mechanisms.
- **SC-003**: System maintains sub-millisecond jitter for deterministic data transmission over a compliant TSN network.
- **SC-004**: The safety communication layer correctly detects 100% of injected network errors (delays, corruption, loss) and transitions to a safe state within the configured safety timeout.
- **SC-005**: The server memory footprint remains strictly within configured limits during unbounded historical queries under heavy load.

## Assumptions

- The target operating system and network interface hardware fully support TSN capabilities for testing deterministic communication.
- End-users requiring the Safety profile will provide appropriate safety parameters (timeout, safety addresses).
- Zero-copy serialization can be applied to the majority of large payload data types in OPC-UA.
