# Feature Specification: Controlled Hot Path Benchmark Harness

**Feature Branch**: `245-controlled-hot-path-bench`  
**Created**: 2026-06-30  
**Status**: Draft  
**Input**: User description: "We still want a harness we control for async-opcua localhost Read/Write hot-path throughput, using the recent perf run only as comparison data."

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Run A Controlled Local Throughput Sample (Priority: P1)

A maintainer can run a self-contained localhost benchmark that starts an async-opcua server, drives repeated OPC UA Read or Write requests against a deterministic value node, and receives machine-readable throughput and correctness results.

**Why this priority**: This is the minimum controlled measurement needed before choosing the next optimization target.

**Independent Test**: Run one read sample and one write sample locally with short warmup and measurement windows; each run reports non-zero successful operations, zero failed operations, elapsed seconds, and operations per second.

**Acceptance Scenarios**:

1. **Given** no benchmark server is already running, **When** the maintainer runs a read benchmark sample, **Then** the harness starts a localhost server, performs OPC UA Read requests, prints one JSON result, and exits successfully after cleanup.
2. **Given** no benchmark server is already running, **When** the maintainer runs a write benchmark sample, **Then** the harness starts a localhost server, performs OPC UA Write requests, prints one JSON result, and exits successfully after cleanup.
3. **Given** any benchmark operation returns an OPC UA error or transport error, **When** the sample completes, **Then** the JSON result includes the failure count and the command exits unsuccessfully.

---

### User Story 2 - Profile Server And Client Separately (Priority: P2)

A maintainer can run the benchmark server as a standalone process and run the load client separately, so external profilers can attach to the server process without modifying benchmark behavior.

**Why this priority**: The recent perf artifacts were collected against the server process; preserving that workflow is necessary for hotspot analysis.

**Independent Test**: Start the benchmark server on a chosen localhost port, run separate read and write client commands against it, observe JSON samples, then stop the server cleanly.

**Acceptance Scenarios**:

1. **Given** a standalone benchmark server is running, **When** a separate read client targets its endpoint and deterministic node, **Then** the client reports successful Read throughput without starting another server.
2. **Given** a standalone benchmark server is running, **When** a separate write client targets its endpoint and deterministic node, **Then** the client reports successful Write throughput without starting another server.
3. **Given** the chosen port is unavailable, **When** the standalone server mode starts, **Then** startup fails clearly without leaving a background process.

---

### User Story 3 - Preserve Comparable Benchmark Metadata (Priority: P3)

A maintainer can compare results between runs by relying on stable result fields and explicit metadata, without committing bulky profiler output to the repository.

**Why this priority**: The harness should support performance tracking over time while keeping generated artifacts out of source control.

**Independent Test**: Run the harness twice with the same settings and verify that each JSON result includes the operation, endpoint, node, warmup count, measured count, failed count, elapsed seconds, throughput, and first failure status if any.

**Acceptance Scenarios**:

1. **Given** a completed benchmark sample, **When** the output is parsed by automation, **Then** required fields are present with stable names and numeric values where appropriate.
2. **Given** a maintainer wants profiler artifacts, **When** they run an external profiler around server mode, **Then** generated profiler files remain outside the committed harness by default.

### Edge Cases

- Port selection conflicts must fail clearly or use an explicit selected port without silently measuring a different endpoint.
- Client startup must fail clearly if the endpoint cannot be reached within the configured readiness window.
- Benchmark samples must distinguish successful OPC UA service results from failed service results.
- Write samples must use a writable value node and must not mask type mismatch or not-writable status results.
- Cleanup must stop the internally started server after successful and failed one-shot runs.
- Very short warmup or measurement intervals must be rejected if they cannot produce meaningful results.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The system MUST provide a controlled localhost benchmark that can run a complete one-shot Read or Write throughput sample against async-opcua.
- **FR-002**: The benchmark MUST exercise normal OPC UA Attribute Service Set Read and Write behavior rather than a private shortcut path.
- **FR-003**: The benchmark server MUST expose a deterministic writable scalar value node with a stable namespace URI and node identifier for repeatable Read and Write samples.
- **FR-004**: The benchmark MUST support configurable operation type, endpoint, port, warmup duration, measurement duration, and target node.
- **FR-005**: The benchmark MUST print a single machine-readable result per sample containing operation, endpoint, node, warmup successes, warmup failures, measured successes, measured failures, elapsed seconds, operations per second, and first failure status.
- **FR-006**: The benchmark MUST exit unsuccessfully when setup fails, the endpoint is unreachable, the target node is invalid, or any measured operation fails.
- **FR-007**: The benchmark MUST support standalone server mode and standalone client mode so external profilers can target only the server process.
- **FR-008**: The benchmark MUST support a self-contained run mode that starts the server, waits for readiness, runs one sample, and shuts the server down.
- **FR-009**: The benchmark documentation MUST explain how to run read, write, standalone server/client, and profiler-oriented workflows.
- **FR-010**: The repository MUST NOT commit generated profiler data, bulky run artifacts, or machine-local measurement outputs as part of the harness.

### Key Entities

- **Benchmark Sample**: A single measured run for one operation against one endpoint and node, including success/failure counters and throughput.
- **Benchmark Target Node**: The deterministic writable scalar node used by the benchmark server for Read and Write service calls.
- **Benchmark Mode**: The selected execution shape: one-shot run, standalone server, or standalone client.
- **Benchmark Endpoint**: The OPC UA endpoint URL used by client mode and reported in every sample.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: A maintainer can produce a read throughput sample and a write throughput sample on localhost in under 30 seconds using documented commands.
- **SC-002**: Each successful sample reports more than zero measured successful operations and zero measured failed operations.
- **SC-003**: Standalone server/client mode supports external server profiling without changing benchmark source files or committing profiler output.
- **SC-004**: The generated result format is stable enough for automation to parse all required fields from every sample.
- **SC-005**: The harness can be run repeatedly on a clean checkout without requiring files from `../scratch` or any external benchmark repository.

## Assumptions

- The initial controlled harness measures async-opcua client-to-async-opcua server throughput; cross-stack C-client comparisons remain external unless added by a later feature.
- The benchmark target is a local unauthenticated SecurityPolicy None endpoint because the immediate optimization work is focused on server hot-path Read/Write overhead, not security policy throughput.
- The recent perf artifacts in `../scratch/opcua-localhost-bench` are comparison data only and are not committed.
- Performance thresholds are not enforced in CI until the harness has enough historical baseline data to set non-flaky gates.
