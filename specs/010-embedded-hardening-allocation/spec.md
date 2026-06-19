# Feature Specification: Embedded Hardening & Allocation Follow-ups

**Feature Branch**: `010-embedded-hardening-allocation`
**Created**: 2026-06-19
**Status**: Draft
**Input**: Remaining open items from the feature-009 embedded audit (`docs/EMBEDDED_AUDIT_2026-06-18.md` §5/§6) and the 2026-06-19 allocation + unbounded-growth sweep.

## Overview

`async-opcua` is a network-facing OPC UA protocol library that may run for long periods on resource-constrained, embedded-Linux devices (Raspberry Pi class) and on untrusted networks. Feature 009 closed the highest-severity hardening and allocation gaps; this feature closes the **remaining documented gaps**:

1. residual **panic surface** on remote-reachable paths (the audit's top open item),
2. an **unbounded read-buffer** path (the frame decoder does not enforce the negotiated maximum message size),
3. **unbounded server-side growth** in the certificate-management (GDS) registries,
4. **unbounded decode recursion** depth,
5. remaining **per-publish allocation churn** on the event-notification path,
6. remaining **per-request allocation churn** in server request dispatch,
7. **copy-on-decode** for strings/byte-strings/arrays, and
8. missing **embedded deployment guidance** (low-jitter runtime + size-optimized build profile).

The work must not regress correctness or security and must keep the existing wire behavior unchanged for well-behaved peers.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - A hostile or buggy peer cannot crash or exhaust the server (Priority: P1)

An operator runs an `async-opcua` server reachable from an untrusted network. A malicious or malfunctioning peer sends crafted, malformed, oversized, or deeply-nested protocol messages. The server must reject each cleanly (dropping at most that one connection) and keep serving every other client — it must never abort the process or grow memory without bound.

**Why this priority**: Security is paramount on a network-facing library; a single crafted message that aborts the process or exhausts memory is a denial of service for every client. This story is the security baseline and gates release.

**Independent Test**: Feed the server (and the decode/secure-channel paths directly) a corpus of crafted/malformed/oversized/deeply-nested inputs via fuzzing and regression tests; assert no panic/abort, bounded memory, recoverable connection-level errors, and that other clients remain served.

**Acceptance Scenarios**:

1. **Given** a connected peer, **When** it sends a chunk whose declared message size exceeds the negotiated maximum, **Then** the server rejects it with a protocol error and does not buffer toward that declared size.
2. **Given** any decode path reachable from remote input, **When** it receives a malformed or adversarial payload, **Then** it returns a recoverable error and never panics/aborts (verified under a panic-hunting fuzz pass).
3. **Given** a deeply-nested encoded structure, **When** it is decoded, **Then** decoding fails with a clean error at a bounded depth rather than overflowing the stack.
4. **Given** sustained certificate-management traffic from an authorized client, **When** it continues over a long period, **Then** server memory for that subsystem stays bounded (old entries are evicted or aged out).

### User Story 2 - Steady-state operation has minimal, predictable allocation (Priority: P2)

An operator runs a long-lived server on a multi-core, resource-constrained SBC (incl. musl builds) driving large subscriptions and high request rates. Steady-state operation must produce minimal, predictable dynamic-memory churn so that allocation activity does not perturb latency on other cores.

**Why this priority**: Allocation-rate jitter on a multi-core SBC degrades real-time behavior; reducing steady-state churn is the core embedded-suitability goal, but it is not a correctness/security gate.

**Independent Test**: Use the allocation-measurement harness (counting allocator) on the event-heavy publish path and on the request-dispatch path; assert per-tick / per-request steady-state allocation is reduced versus the pre-feature baseline, with identical observable behavior.

**Acceptance Scenarios**:

1. **Given** an event/alarm-heavy subscription publishing on a steady interval, **When** it reaches steady state, **Then** the per-tick allocation for the event-notification path is constant (pooled/reused), not proportional to the event count.
2. **Given** a high rate of small read requests, **When** they are dispatched, **Then** per-request heap allocation is reduced versus the baseline, with unchanged results.
3. **Given** the changes above, **When** the full test and integration suites run, **Then** every notification and response is byte-for-byte unchanged on the wire and all tests pass.

### User Story 3 - Embedded deployments have guidance and lean decoding (Priority: P3)

An integrator targeting an embedded-Linux device wants documented guidance for the lowest-jitter, smallest-footprint configuration, and wants decoding of strings/byte-strings/arrays to avoid unnecessary copies.

**Why this priority**: Additive guidance and a decode optimization that improve footprint/throughput but are not required for correctness or for the security baseline.

**Independent Test**: Verify the documentation describes a recommended single-threaded runtime configuration and a size-optimized build profile; verify the decode path for strings/byte-strings/arrays produces identical values while avoiding the copy (measured by the allocation harness) where the source buffer permits.

**Acceptance Scenarios**:

1. **Given** the project documentation, **When** an integrator reads the embedded/deployment section, **Then** it describes a recommended low-jitter runtime and a size-optimized build profile with the trade-offs stated.
2. **Given** a decoded message containing strings/byte-strings/large arrays, **When** the source buffer allows sharing, **Then** the decoded values are identical to before while avoiding a per-field copy.

### Edge Cases

- Declared message size of zero, exactly the maximum, and one over the maximum.
- Empty notification batches; event-only publishes; mixed data-change + event publishes.
- A pooled buffer reused across publishes must never carry stale items into a later message.
- A republished (retransmitted) notification must remain byte-identical.
- Decode recursion exactly at, and one beyond, the configured depth limit.
- Certificate-management registries at their cap (oldest-eviction vs reject-when-full behavior must be defined).
- Abrupt connection drop (not graceful close) must still release all per-connection/per-session state.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: No remote-supplied input (malformed, adversarial, oversized, or deeply-nested) on any decode, secure-channel, or service path may cause the process to panic or abort; every such input MUST map to a recoverable error. The network-facing crates MUST be guarded against unjustified panicking constructs, with any exception explicitly justified.
- **FR-002**: The frame decoder MUST reject a message whose declared size exceeds the negotiated maximum message size before buffering toward that size, returning a protocol-level error.
- **FR-003**: Structure decoding MUST enforce an explicit, configurable maximum nesting depth and fail cleanly when exceeded, independent of message-size limits.
- **FR-004**: Server-side certificate-management state MUST be bounded (capped and/or aged out); it MUST NOT grow without limit under sustained authorized traffic. The overflow behavior MUST be defined and documented.
- **FR-005**: The steady-state event-notification publishing path MUST reuse its working buffer across publishes rather than allocating per tick proportional to the event count, with no possibility of stale data leaking between messages.
- **FR-006**: Per-request server dispatch MUST minimize per-request heap allocation for the common case (e.g. small single-handler reads), without weakening request isolation or correctness.
- **FR-007**: Decoding of strings, byte-strings, and arrays MUST avoid copying out of the receive buffer where the buffer's ownership permits sharing, producing identical decoded values.
- **FR-008**: Project documentation MUST describe a recommended low-jitter runtime configuration and a size-optimized build profile for embedded-Linux deployments, with trade-offs stated.
- **FR-009**: All changes MUST preserve existing wire behavior for well-behaved peers — encoded responses, notifications, and republished notifications MUST remain byte-for-byte unchanged — and MUST keep the full existing test and integration suites passing.
- **FR-010**: Each measurable allocation-reduction change MUST be accompanied by a before/after measurement using a repeatable allocation-counting harness.

### Key Entities

- **Decoding limits**: the configurable bounds applied while decoding remote input — maximum message size (enforced earlier) and a new maximum nesting depth.
- **Certificate-management registry**: the server-side store of pending/created/rejected/updated certificate-management requests that must be bounded.
- **Notification working buffer**: the reusable per-subscription buffer(s) for building outgoing notification messages (data-change already pooled; event path to be added).
- **Receive buffer ownership**: the shared ownership of decoded bytes that enables copy-free strings/byte-strings/arrays.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: A panic-hunting fuzz pass plus targeted regression tests over crafted/malformed/oversized/deeply-nested inputs produce **zero process aborts**; every input yields a recoverable connection-level error and other clients stay served.
- **SC-002**: Under sustained certificate-management traffic, server memory for that subsystem stays within a fixed bound (no monotonic growth) over a long run.
- **SC-003**: For an event-heavy subscription at steady state, per-publish-tick allocation on the event path is **constant** (independent of event count), measured by the allocation harness.
- **SC-004**: Steady-state per-publish allocation is **measurably reduced** versus the pre-feature baseline, with before/after numbers recorded (guaranteed by the event-notification pooling). The per-request (small read) reduction is **contingent on the measure-first outcome** of the dispatch fast-path (FR-006): if measurement does not justify it, that item is deferred with a recorded rationale (per Assumptions / Constitution I) and SC-004 is satisfied by the per-publish reduction alone.
- **SC-005**: The full existing test suite and the integration suite pass with **zero failures**, and encoded responses/notifications/republished notifications are byte-for-byte unchanged for well-behaved peers.
- **SC-006**: Decoding strings/byte-strings/arrays from a shareable receive buffer performs **fewer allocations** than the baseline while producing identical decoded values.
- **SC-007**: The documentation includes a verifiable embedded-deployment section (recommended runtime + size-optimized build profile).

## Assumptions

- The existing project constitution applies: code correctness over speed of delivery; do it right so we do not redo it; tasks assigned individually, never batched; security paramount on this network-facing library; leave things better than found.
- Implementation follows the established orchestration: production-code changes are dispatched to codex one task at a time; testing/verification/measurement is performed directly; commit cadence is one commit per user story.
- The technical approaches identified in the embedded audit and the 2026-06-19 sweep are the starting point (codec size-guard, GDS cap/TTL, recursion counter in decoding options, extending the existing notification-vector pool to events, inline read fast-path for dispatch, shared-`Bytes` decode), but exact mechanisms are decided in planning.
- `no_std` / bare-metal MCU support is explicitly **out of scope**; the target is embedded **Linux** (incl. musl).
- The architectural items (per-request dispatch allocation; zero-copy decode) are measure-first: they are pursued only where a measured benefit is demonstrated without weakening correctness or isolation, and may be staged or deferred within this feature if measurement does not justify the risk.
- "Bounded" memory and "reduced" allocation are validated by the repeatable allocation-counting harness already established in the publish-path work, extended as needed.
