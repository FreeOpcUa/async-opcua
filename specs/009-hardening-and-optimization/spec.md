# Feature Specification: Codebase Hardening, Cleanup & Optimization

**Feature Branch**: `009-hardening-and-optimization`
**Created**: 2026-06-16
**Status**: Draft
**Input**: User description: "use the five review documents (CODE_REVIEW, SECURITY_AUDIT,
NETWORK_REVIEW, PERFORMANCE_AUDIT, ARCHITECTURE_REVIEW — all dated 2026-06-16, in `docs/`) as
instructions to cleanup, improve, harden and optimize this codebase."

## Overview

This feature is a remediation program: it turns the findings of five review documents into a single
prioritized body of work that makes the async-opcua library production-grade. The reviews are the
source of requirements; each requirement below traces back to one or more finding IDs (e.g. `C1`,
`V3`, `N1`, `P2`, `R1`) so progress is auditable against the originals. The work spans four outcomes —
**harden** (eliminate remote crashes and security weaknesses), **clean up** (remove debris and
unsound patterns, fix process gaps), **improve** (resilience, observability, correctness of defaults),
and **optimize** (restore lost performance on the hot path) — without changing the library's public
purpose. Per the Clarifications below, this targets a **0.19 release in which public-API breaking
changes are permitted** (documented in the changelog), so findings can be fixed properly rather than
worked around.

This work is governed by the project constitution v1.0.0: correctness over completion, do it right
once, **one task at a time (never batched)**, security is paramount, and leave things better than you
found them. Every change SHOULD carry a regression test (failing before, passing after).

## Clarifications

### Session 2026-06-17

- Q: Tolerance for public-API breaking changes in this remediation? → A: **Breaking changes are
  permitted in a 0.19 (0.x minor) version bump.** Inherently-breaking fixes (R2 error-context types,
  P5 `Bytes`-backed `ByteString`, R3 `NodeManager` trait split) may be done properly rather than
  worked around (Constitution II). Consumers are expected to adapt at the 0.19 boundary; breaks are
  documented in the changelog.
- Q: Are the four large structural items (R3 `NodeManager` segregation, R5 WebSocket/`opc.wss`
  connector, P5/P10 `Bytes`/`Arc`-backed types, D1 RSA constant-time backend migration) in scope for
  THIS feature? → A: **Yes — all four are in scope now (not deferred).**
- Q: How strict is the SC-010 interop done-gate? → A: **Hard gate** — the dotnet and open62541 interop
  harnesses must run and pass in CI as a release gate.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - The server survives malicious and malformed input (Priority: P1)

An operator runs an async-opcua **server** exposed to a network where any peer — including
unauthenticated and hostile ones — can connect. A single crafted message, a flood of connections, or a
pipelined burst of requests from one client MUST NOT crash the server or let one client deny service to
everyone else.

**Why this priority**: These are the unauthenticated, trivially-triggerable failures (decoder
stack-overflows, identity-decrypt panics, unbounded queues/sessions/connections). They are the highest
real-world risk and the cheapest to fix; nothing else matters if the server can be crashed by anyone.
Covers findings C1, C2, C3, C4, H2, H3, H4, M1, M5, M11, L3, L8, N6, N10.

**Independent Test**: Feed the server (a) the known stack-overflow decode payloads, (b) malformed
legacy identity tokens, and (c) a single connection pipelining unbounded requests / opening unbounded
sessions / connections from one IP — and confirm the server rejects each with an error and keeps
serving other clients, with no panic or unbounded memory growth.

**Acceptance Scenarios**:

1. **Given** a server with default configuration, **When** an unauthenticated peer sends a deeply
   nested `DiagnosticInfo` / `DataValue↔Variant` / dynamic-struct message of a few hundred KB,
   **Then** the server rejects it with a decoding error and does not abort. (C1)
2. **Given** a server with a configured certificate, **When** a peer sends an `ActivateSession` with a
   non-block-aligned or undersized legacy identity-token ciphertext, **Then** the server returns
   `BadIdentityTokenInvalid`/`BadSecurityChecksFailed` and does not panic. (C2)
3. **Given** a server under default limits, **When** one connection pipelines requests faster than they
   complete, **Then** in-flight requests are bounded (backpressure or `BadTooManyOperations`) and
   memory does not grow without bound. (C3)
4. **Given** a server with `max_sessions = 20`, **When** one unauthenticated client opens sessions
   without activating them, **Then** unactivated sessions are capped per channel and expire quickly,
   so other clients can still create sessions. (C4)
5. **Given** a server, **When** one source IP opens many connections (including HELLO-stalling
   slowloris), **Then** a per-IP cap prevents it from consuming all connection slots. (H3, N10)
6. **Given** a client request with a very large `timeout_hint`, **When** the server applies its
   configured `max_timeout_ms`, **Then** the effective timeout is capped at the configured maximum,
   not raised to the client's value. (H2)
7. **Given** a per-subscription monitored-item limit, **When** concurrent `CreateMonitoredItems`
   arrive, **Then** the limit is enforced atomically and a sensible non-zero default applies. (H4)

---

### User Story 2 - The client survives a malicious or unreliable server (Priority: P1)

A developer embeds the async-opcua **client** in their application and connects to servers that may be
hostile, buggy, or unreachable. Malformed responses MUST NOT crash the client, an unreachable server
MUST NOT hang it, and a vanished peer MUST be detected and recovered from.

**Why this priority**: The client is half the network attack surface; reachable panics and disabled
liveness detection are production-affecting and affect every consumer. Covers findings H7, M8, M9, M10,
M11, L12, N2, N8.

**Independent Test**: Point the client at a mock server that returns empty/short result arrays, streams
unbounded chunks, stalls a channel renewal, and silently drops the TCP connection — and confirm the
client errors gracefully, detects the dead peer, and reconnects rather than panicking or hanging.

**Acceptance Scenarios**:

1. **Given** a connected client, **When** the server returns a `Good` `DeleteSubscriptions` response
   with an empty results array, **Then** the client returns an error instead of panicking. (H7)
2. **Given** a client connecting to a black-holed address, **When** the TCP connect would otherwise
   hang for the OS SYN timeout, **Then** a configurable connect timeout fires and the retry loop
   proceeds. (N2)
3. **Given** a long-lived idle connection whose server has silently died, **When** keep-alives fail,
   **Then** after a small default number of consecutive failures the client disconnects and
   reconnects. (N8)
4. **Given** a server that stalls secure-channel renewal, **When** renewal does not complete, **Then**
   the client tears down and reconnects rather than wedging on a hardcoded timeout. (M10)
5. **Given** a malicious server streaming unbounded chunks for one request, **Then** the client
   enforces a hard chunk ceiling and does not exhaust memory or panic on sequence-number overflow.
   (M11)

---

### User Story 3 - Cryptographic and authentication weaknesses are closed (Priority: P1)

A security-conscious operator deploys the library in a regulated or high-value environment. Secrets
MUST NOT leak, weak/legacy cryptography MUST be opt-in and clearly bounded, identity binding MUST be
correct, and known-vulnerable dependencies MUST be tracked and bounded.

**Why this priority**: Security is the constitution's paramount concern and the library is
network-facing. Covers findings H1, H5, H6, H8, M3, M4, M6, M12, D1, L2, L4, L5, L6, L7, L9, L10, L14.

**Independent Test**: Audit each security-relevant path: confirm no secret appears in logs/`Debug`
output, that a `None`-policy activated session cannot be transferred to another channel, that client
certificates are validated against application URI/hostname, that RSA-decrypt failures are
timing/error-uniform, and that the dependency advisory scan passes (or every exception is recorded).

**Acceptance Scenarios**:

1. **Given** a `SecurityPolicy::None` session that is already activated, **When** an observer presents
   its auth token on a different secure channel, **Then** the server refuses the cross-channel
   transfer. (H1)
2. **Given** a `CreateSession` request, **When** the server validates the client certificate, **Then**
   the certificate's application URI (and hostname where applicable) is checked against the request.
   (H5)
3. **Given** any code path that can log a struct embedding key material, **When** it is formatted for
   logging, **Then** key bytes are redacted and not emitted. (M4, M3)
4. **Given** the legacy RSA identity-decrypt path, **When** decryption fails for any reason, **Then** a
   single uniform error with uniform timing is returned (no padding/validity oracle), and the residual
   `rsa`-crate Marvin risk is documented. (H6, H8, D1)
5. **Given** username authentication, **When** an unknown username is supplied, **Then** verification
   time does not reveal whether the username exists. (M6)
6. **Given** a security-conscious build, **When** the consumer disables default features, **Then**
   legacy/deprecated cryptography can be excluded from compilation across all crates (including the
   client), and weak defaults fail closed. (M12, L2)

---

### User Story 4 - The repository and its supply chain are clean and trustworthy (Priority: P2)

A maintainer or downstream auditor inspects the repository. It MUST contain no developer debris,
secrets, or infrastructure disclosure; dependencies MUST be current and monitored; and the disclosure
process MUST protect reporters.

**Why this priority**: Information disclosure and supply-chain hygiene are real but not
remote-exploitable in the running library; they are prerequisites for trust and for catching future
regressions automatically. Covers findings "Repo hygiene" (12 debris files), D2, D3, D4, D5, SEC-P1,
SEC-P2, SEC-P3, and dependency notes (`serde_yaml`, `thiserror`, `env_logger`).

**Independent Test**: Confirm the twelve debris files are removed and ignored, that a dependency
advisory gate runs in CI and passes (or records justified exceptions), that the MQTT/pub-sub path no
longer pins an end-of-life TLS stack, and that the security disclosure policy offers a private channel.

**Acceptance Scenarios**:

1. **Given** the repository, **When** it is inspected, **Then** the throwaway scripts, saved diffs, and
   the committed password hash are gone and prevented from recurring via ignore rules. (P3, hygiene)
2. **Given** CI, **When** it runs, **Then** a dependency-advisory check executes and fails the build on
   a new unbounded advisory; existing unavoidable advisories (e.g. `rsa`) are explicitly recorded. (P1)
3. **Given** the pub/sub MQTT transport, **When** its dependencies are resolved, **Then** it builds on
   a maintained TLS stack rather than an end-of-life one. (D2)
4. **Given** a security reporter, **When** they consult `SECURITY.md`, **Then** they are directed to a
   private, coordinated-disclosure channel. (P2)

---

### User Story 5 - Latency, throughput and idle cost are production-grade (Priority: P2)

An operator runs the server in a latency-sensitive industrial setting and at scale (many sessions and
subscriptions). The library MUST minimize per-message latency, avoid giving back its allocation-free
gains on secured connections, and not waste CPU when idle.

**Why this priority**: Performance is a stated goal of recent work; these items either restore lost
optimization or remove avoidable overhead, but they are lower urgency than not crashing. Covers
network findings N1, N3, N7 and performance findings PERF-P1–PERF-P10 + PERF-P12, plus R6
(observability). (PERF-P11, the retransmission-queue scan, is consciously deferred — see the deferred
list in `tasks.md`.)

**Independent Test**: With new benchmarks in place, measure encode/decode and secured-chunk round-trip
throughput and per-message latency before and after, and measure idle-server CPU with many idle
subscriptions; confirm latency drops (Nagle disabled), secured-path allocations drop, and idle CPU
drops, with no functional regression.

**Acceptance Scenarios**:

1. **Given** any TCP connection, **When** small request/response messages are exchanged, **Then**
   `TCP_NODELAY` is set so no Nagle/delayed-ACK latency penalty applies. (N1)
2. **Given** a secured (Sign/SignAndEncrypt) connection, **When** chunks are sent and received,
   **Then** the per-chunk padding/signature/decrypt buffers are reused and the HMAC/AES key schedule is
   not recomputed per chunk. (P2, P3)
3. **Given** an inbound chunk already held in a buffer, **When** it is decoded, **Then** it is sliced
   zero-copy rather than re-allocated and copied. (P1)
4. **Given** a server with thousands of idle subscriptions, **When** the publish timer ticks, **Then**
   no per-session priority vector is allocated/sorted for idle sessions and the cache lock is not held
   across the whole tick loop. (P6, P7)
5. **Given** the hot paths, **When** the project is built, **Then** benchmarks exist that measure
   encode/decode and secured round-trip throughput so future regressions are caught. (P12)

---

### User Story 6 - Structural cleanups remove unsound patterns and footguns (Priority: P3)

A contributor maintains and extends the library. Generated code MUST NOT carry unnecessary `unsafe`,
error context MUST survive across API boundaries, and the workspace MUST be coherent.

**Why this priority**: These improve long-term maintainability and remove latent unsoundness, but are
not user-visible failures today. Covers findings L1, R1 (codegen `unsafe`/derive), R2 (error context),
R3 (NodeManager interface), R7a (legacy-crypto packaging — see FR-019), plus M2 (encode/byte_len
mismatch surfacing). (R7b, R7c, and R8 are consciously deferred — see the deferred list in `tasks.md`.)

**Independent Test**: Confirm generated types compile without hand-written `unsafe impl Send/Sync` and
without hand-written binary impls; confirm that an error returned across a public service boundary
still carries its request handle/context; confirm the workspace builds with the rationalized
feature/packaging layout.

**Acceptance Scenarios**:

1. **Given** the code generator, **When** types are regenerated, **Then** they rely on auto-derived
   `Send`/`Sync` and derived binary encode/decode, with no hand-emitted `unsafe impl`. (L1, R1)
2. **Given** a service call that fails, **When** the error reaches the caller, **Then** the request
   handle and underlying context are preserved rather than collapsed to a bare status code. (R2)
3. **Given** an internal `byte_len()`/`encode()` mismatch, **When** a message is serialized, **Then**
   the mismatch surfaces as an error/assertion rather than silent wire corruption. (M2)

---

### Edge Cases

- A crafted message that is simultaneously deeply nested *and* large — recursion limit and size limit
  must both apply and the first breached wins, with a clean error.
- `max_chunk_count == 0` ("unlimited") must still be bounded by a derived physical ceiling on both
  client and server. (N6, M11)
- An operator who *intends* to use legacy crypto must still be able to opt in explicitly, with the weak
  posture clearly logged. (M12)
- Removing debris files must not delete anything still referenced by the build, tests, or CI.
- Performance changes must preserve exact wire-format and spec compliance (no behavioral drift to gain
  speed). This is a hard constraint, not a trade-off.
- A dependency advisory with no available fix (e.g. `rsa` Marvin) must be representable as a recorded,
  justified exception rather than blocking all CI. (D1, P1)

## Requirements *(mandatory)*

### Functional Requirements

**Harden — remote crash & DoS resistance (P1)**

- **FR-001**: The decoder MUST bound recursion depth on every nested decode path (`DiagnosticInfo`, the
  `DataValue↔Variant` cycle, and dynamic-struct decode) so no crafted message can exhaust the stack.
  (C1)
- **FR-002**: The legacy identity-token decrypt path MUST validate input length/alignment before
  slicing and MUST NOT panic on any attacker-supplied ciphertext, returning a defined error instead.
  (C2)
- **FR-003**: The server MUST bound per-connection in-flight requests and apply backpressure (or reject
  with `BadTooManyOperations`) rather than queueing unboundedly. (C3)
- **FR-004**: The server MUST cap unactivated sessions per secure channel and expire them on a short
  deadline, so one client cannot exhaust the global session pool before authenticating. (C4)
- **FR-005**: The server MUST limit connections per source IP and resist HELLO-stalling slowloris.
  (H3, N10)
- **FR-006**: The server MUST treat `max_timeout_ms` as a ceiling on request timeouts, never a floor.
  (H2)
- **FR-007**: The server MUST enforce the per-subscription monitored-item limit atomically and ship a
  non-zero default. (H4)
- **FR-008**: Both client and server MUST enforce a hard chunk-count ceiling even when the configured
  `max_chunk_count` is the "unlimited" sentinel. (N6, M11)
- **FR-009**: Network-reachable arithmetic on the receive/transmit path (padding verification, chunk
  sizing, sequence increment) MUST use checked operations and surface errors rather than panicking or
  wrapping. (M1, L3, M11)

**Harden — client robustness (P1)**

- **FR-010**: The client MUST validate server response array lengths before indexing and MUST NOT panic
  on malformed responses. (H7, L12)
- **FR-011**: The client MUST apply a configurable TCP connect timeout. (N2)
- **FR-012**: The client MUST detect a dead peer via keep-alive and reconnect after a small non-zero
  default number of failures. (N8)
- **FR-013**: The client MUST derive secure-channel renewal timeout from configuration and tear down +
  reconnect the channel on renewal failure. (M10)

**Harden — cryptography & authentication (P1)**

- **FR-014**: The server MUST refuse cross-channel transfer of an already-activated `SecurityPolicy::None`
  session. (H1)
- **FR-015**: The server MUST validate the client certificate's application URI (and hostname where
  applicable) against the session request. (H5)
- **FR-016**: Secret material (session keys, signing keys, IVs, decrypted passwords, RSA private keys)
  MUST NOT appear in logs or `Debug` output and SHOULD be zeroized on drop. (M3, M4)
- **FR-017**: RSA-decrypt failure paths MUST return a single uniform error with uniform timing, and the
  decrypted-nonce comparison MUST be constant-time. (H6, H8)
- **FR-018**: Username authentication MUST take uniform time regardless of whether the username exists.
  (M6)
- **FR-019**: Legacy/deprecated cryptography MUST be excludable at compile time across all crates
  (including the client) via feature flags, MUST default to fail-closed, and weak-posture opt-in MUST
  be logged. (M12, L2)
- **FR-020**: Defense-in-depth crypto checks MUST be added: validate the signature algorithm field
  (L4), write private keys with `0o600` (L5), validate JWT `nbf` (L6), make empty-password accounts
  explicit (L7), fail closed on server-signature generation failure (L9), give issued-token policy IDs
  distinct values (L10), and remove latent crypto panics (L14).

**Clean up — repository & supply chain (P2)**

- **FR-021**: The repository MUST NOT contain developer debris, committed secrets, or infrastructure
  disclosure; such files MUST be removed and prevented from recurring. (P3, hygiene)
- **FR-022**: CI MUST run a dependency-advisory gate that fails on new unbounded advisories, with a
  configuration file recording justified exceptions (e.g. `rsa` Marvin). (P1, D1)
- **FR-023**: The pub/sub MQTT transport MUST build on a maintained TLS stack, or be feature-gated off
  by default. (D2)
- **FR-024**: Unmaintained/outdated dependencies MUST be upgraded or replaced where a maintained
  alternative exists (`time`, `rand`, `serde_yaml`, `thiserror`, `env_logger`). (D3, D4, D5)
- **FR-025**: `SECURITY.md` MUST provide a private, coordinated-disclosure channel. (P2)

**Optimize — performance & observability (P2)**

- **FR-026**: All TCP sockets (accepted and connected) MUST set `TCP_NODELAY`; `SO_KEEPALIVE` SHOULD be
  configurable on long-lived sockets. (N1, N3)
- **FR-027**: The secured send/receive path MUST reuse per-chunk padding/signature/decrypt buffers and
  MUST NOT recompute the HMAC/AES key schedule per chunk. (P2, P3)
- **FR-028**: Inbound chunks MUST be decoded zero-copy from the existing buffer rather than
  re-allocated and copied. (P1)
- **FR-029**: The subscription tick MUST NOT allocate/sort per-session priority data for idle sessions
  and MUST NOT hold the cache lock across the whole tick loop; the notification pool MUST NOT block a
  worker thread at capacity. (P6, P7, P8, M5)
- **FR-030**: The project MUST include benchmarks for encode/decode and secured round-trip throughput
  to guard against regressions. (P12)
- **FR-031**: Optional network/transport observability (connection/byte/secure-channel counters with an
  exporter) SHOULD be available. (R6, network §7)

**Improve — correctness of defaults & resilience (P2)**

- **FR-032**: Subscription publish priority MUST serve higher-priority subscriptions first. (M14)
- **FR-033**: History continuation points MUST honor their configured maximum. (M13)
- **FR-034**: `max_queued_notifications` MUST be a hard bound and queue drops MUST be surfaced so
  clients can handle sequence-number gaps. (M7)
- **FR-035**: The client MUST NOT auto-trust unknown server certificates by default, and discovery
  endpoints SHOULD be pinnable; sample/doc code MUST NOT enable unsafe trust. (M8, M9)

**Clean up — structural soundness (P3)**

- **FR-036**: Generated types MUST rely on auto-derived `Send`/`Sync` and derived binary encode/decode
  rather than hand-emitted `unsafe impl` / hand-written impls. (L1, R1)
- **FR-037**: Errors crossing public service boundaries MUST preserve request-handle and underlying
  context rather than collapsing to a bare status code. (R2)
- **FR-038**: An internal `byte_len()`/`encode()` mismatch MUST surface as an error/assertion, not
  silent wire corruption. (M2)

**Large structural items — in scope per Clarifications (breaking changes permitted at 0.19)**

- **FR-042**: RSA operations MUST be migrated to a constant-time cryptographic backend, eliminating the
  `rsa`-crate Marvin timing exposure at the primitive level (in addition to FR-017's application-level
  uniform error/timing, which remains as defense-in-depth during and after migration). (D1)
- **FR-043**: The `NodeManager` interface MUST be segregated into capability traits so an implementer
  depends only on the operations it actually provides (e.g. attributes, history, methods, views, node
  mutation, monitored items). (R3)
- **FR-044**: The library MUST provide a WebSocket (`opc.wss`) transport connector built on a
  maintained TLS stack, usable from the client (and server where applicable). (R5, N11)
- **FR-045**: Hot-path types MUST be made zero-copy / share-friendly where it removes per-message or
  per-notification deep copies: `Bytes`-backed `ByteString`, and `Arc`-backed `Variant` array payloads
  and retransmission messages. (P5, P10)
- **FR-046**: CI MUST run the dotnet and open62541 interop harnesses as a release gate, and they MUST
  pass. (SC-010, hard interop gate)

**Cross-cutting process constraints (from the constitution)**

- **FR-039**: Each finding MUST be remediated as an individual, independently verifiable task — never
  batched with unrelated changes. (Constitution III)
- **FR-040**: Each behavioral fix SHOULD be accompanied by a regression test that fails before the fix
  and passes after; correctness-critical paths MUST be covered. (Constitution I, II)
- **FR-041**: No change may alter the OPC-UA wire format or reduce spec compliance to gain performance
  or simplicity. (Constitution I)

### Key Entities

- **Finding**: a single reviewed issue with an ID (e.g. `C1`, `V3`, `N1`, `P2`, `R1`), a severity, an
  owning crate/file, and a remediation. The unit of work and of traceability.
- **Severity tier**: Critical / High / Medium / Low (code review) and the audit/network/perf severity
  scales — used to order the work.
- **Affected component**: the crate a finding lives in (`async-opcua-types`, `-core`, `-crypto`,
  `-server`, `-client`, `-pubsub`, `-codegen`) — used to group and parallelize.
- **Configuration default**: a shipped default value (e.g. `max_failed_keep_alive_count`,
  `max_monitored_items_per_sub`, `channel_lifetime`, `trust_server_certs`) whose value is itself a
  finding.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Zero unauthenticated remote crashes. Every Critical/High crash finding (C1, C2, H7, M1)
  has a regression test that reproduces the original crash and now passes without panic. (Target: 100%
  of crash findings covered by a passing reproduction test.)
- **SC-002**: A single client or single source IP cannot deny service to others — verified by a load
  test that pins one client at maximum request/session/connection pressure while a second client
  continues to operate within normal latency. (C3, C4, H3)
- **SC-003**: No secret material appears in any log or debug output across a full
  connect→activate→subscribe→disconnect session capture. (M3, M4, FR-016)
- **SC-004**: The dependency-advisory gate runs in CI and is green, with every unavoidable advisory
  (e.g. `rsa`) listed as an explicit, justified exception. (P1, D1)
- **SC-005**: The repository contains zero debris/secret/infra-disclosure files and ignore rules
  prevent recurrence. (P3)
- **SC-006**: Small-message round-trip latency improves measurably with `TCP_NODELAY` enabled, and
  secured-path per-chunk heap allocations are reduced to a fixed (non-per-chunk) count — both shown by
  the new benchmarks. (N1, P1–P3, P12)
- **SC-007**: Idle-server CPU with a large number of idle subscriptions is measurably reduced versus
  baseline. (P6, P7)
- **SC-008**: The full workspace builds warning-free with default features, with `--all-features`, and
  with default features disabled (legacy crypto excluded) — and the test suite passes in all three.
  (M12, FR-019, Constitution "green before done")
- **SC-009**: Every finding in the five documents is either remediated (with its task and test) or
  recorded as an explicit, justified deferral — none silently dropped. The deferred set (L11, L13, N4,
  N13, cert-expiry hook, PERF-P11) is enumerated with rationale in `tasks.md` ("Consciously deferred
  findings"). (Constitution; FR-039)

> **Finding-ID note**: performance-audit findings are written `PERF-P#` and security-audit posture
> findings `SEC-P#` in `tasks.md` to avoid collision with user-story Priority labels (P1/P2/P3). This
> spec uses the same convention from here on where ambiguity is possible.
- **SC-010**: No change alters the OPC-UA wire format, enforced as a **hard release gate**: the dotnet
  and open62541 interop harnesses run in CI and pass. (FR-041, FR-046)
- **SC-011**: The four large structural items land in this feature: RSA runs on a constant-time backend
  (D1), `NodeManager` is segregated into capability traits (R3), an `opc.wss` WebSocket connector
  exists and connects (R5), and `ByteString`/`Variant` payloads are zero-copy/share-backed (P5/P10) —
  each with passing tests. The 0.19 changelog documents every public-API break introduced. (FR-042–045)

## Assumptions

- The five review documents in `docs/` dated 2026-06-16 (CODE_REVIEW, SECURITY_AUDIT, NETWORK_REVIEW,
  PERFORMANCE_AUDIT, ARCHITECTURE_REVIEW) are the authoritative, accepted requirement source; their
  finding IDs and line references are current as of this spec. (The user listed PERFORMANCE twice and
  omitted ARCHITECTURE by name but referred to "the five documents"; all five are included.)
- Line numbers in findings are advisory and MUST be re-confirmed at implementation time (the perf and
  client-chunk findings explicitly note this).
- The `rsa`-crate Marvin timing attack (D1) has **no upstream fix on the `rsa` crate**; per
  Clarifications, RSA is migrated to a constant-time backend in this feature (FR-042), with
  application-level uniform error/timing (FR-017) retained as defense-in-depth and a recorded advisory
  exception kept for any residual transitive exposure.
- Per Clarifications, the four large structural items (R3 `NodeManager` segregation, R5 WebSocket
  connector, P5/P10 type-system changes, D1 backend migration) are **in scope for this feature**, not
  deferred (FR-042–045, SC-011).
- Backwards compatibility: this feature targets a **0.19 (0.x minor) release in which public-API
  breaking changes are permitted** (per Clarifications). Default-value changes (keep-alive count,
  channel lifetime, monitored-item cap, NODELAY) and inherently-breaking fixes (R2 error types, P5
  `ByteString`, R3 trait split) are both acceptable; every break MUST be documented in the changelog.
- The existing interop test harnesses (dotnet, open62541) are available and are a **hard CI release
  gate** for SC-010 (FR-046); the planning phase must ensure CI provisions the required external
  toolchains.
