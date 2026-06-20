# Feature Specification: Audit Remediation (Security & Long-Uptime Hardening)

**Feature Branch**: `011-audit-remediation`
**Created**: 2026-06-20
**Status**: Draft
**Input**: Remediate the verified findings from the 2026-06-20 multi-tool security & reliability audit (codex gpt-5.5 + Antigravity, cross-checked and code-verified) of the async-opcua workspace. Defensive hardening of our own fork; hold upstream PRs pending private disclosure coordination.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Bounded history reads (Priority: P1)

An operator's client requests a historical-data read over a wide time window (e.g. months) while
asking for only a small number of values per node. Today the SQLite history backend loads the
*entire* matching interval into memory before trimming to the requested count, then caches and
splits the remainder — so a single authenticated request can exhaust RAM and stall the history
worker. The server must read only as much as it needs and stream the rest via a cursor.

**Why this priority**: Highest-severity finding. A single authenticated, spec-legal request causes
memory exhaustion and blocks all history processing — a 24/7 industrial deployment cannot tolerate it.

**Independent Test**: With a large populated history table, issue `read_raw_modified` over a very
wide range with a small `num_values_per_node`; assert resident memory stays proportional to the
returned count (not the range), the worker stays responsive, and `HistoryReadNext` via continuation
returns the remaining values correctly.

**Acceptance Scenarios**:

1. **Given** a history table with millions of rows in range, **When** a client reads that range with `num_values_per_node = 100`, **Then** the backend loads on the order of 100 (not millions) rows and returns a continuation point.
2. **Given** a continuation point from such a read, **When** the client calls `HistoryReadNext`, **Then** the next page is returned in correct chronological order with no duplicated or skipped values.
3. **Given** repeated wide-range reads, **When** they run back-to-back, **Then** server memory returns to baseline between requests.

---

### User Story 2 - Replay-safe session activation (Priority: P1)

Two requests race to activate the same session over secured channels. Today the session nonce is
read under a shared lock, the lock is released while user-identity authentication runs, and the
session is then activated without confirming the nonce is still the one that was validated — so an
already-rotated nonce can be reused, weakening replay/freshness protection on session reactivation.

**Why this priority**: Security correctness in the authentication path. Quiet, hard to detect, and
defeats an intended replay protection. (Flagged for private upstream disclosure to Einar.)

**Independent Test**: Drive two concurrent `ActivateSession` requests bound to the same session/token
such that one rotates the nonce before the other commits; assert the late request is rejected with a
nonce/session error rather than activating against the stale nonce.

**Acceptance Scenarios**:

1. **Given** a session whose nonce has been rotated by a concurrent activation, **When** a second activation that observed the old nonce reaches the commit step, **Then** it is rejected (`BadNonceInvalid`/`BadSessionIdInvalid`) and does not overwrite identity/channel/nonce.
2. **Given** a single, uncontended activation, **When** it proceeds, **Then** it succeeds exactly as before (no behavior change on the common path).

---

### User Story 3 - Bounded decode allocations from untrusted input (Priority: P1)

A hostile or malformed message declares large element/field counts or array dimensions. The decoder
must validate declared sizes against configured limits (and against safe arithmetic) *before*
allocating, on every decode surface — including PubSub, which currently has no overall size/field
ceiling equivalent to the TCP transport's `max_message_size`.

**Why this priority**: Pre-allocation from untrusted counts is a classic amplification/DoS vector;
PubSub is an unauthenticated network surface in broker/multicast deployments.

**Independent Test**: Feed crafted UADP messages with maximal `field_count`/dataset counts and
custom-struct array dimensions chosen to overflow; assert decode is rejected with a bounded error and
no oversized or overflow-wrapped allocation occurs.

**Acceptance Scenarios**:

1. **Given** a UADP payload declaring an excessive field/dataset count, **When** it is decoded, **Then** decoding fails with a limits error before any large allocation.
2. **Given** a custom multidimensional structure whose dimensions multiply past `usize`/`u32`, **When** it is decoded, **Then** an overflow is detected and a decode error is returned (no wrap, no panic).
3. **Given** valid in-limit messages, **When** decoded, **Then** results are byte-identical to current behavior.

---

### User Story 4 - No growth over long uptime (Priority: P2)

Over months of steady churn (subscribe/unsubscribe, abandoned browse/query continuations, program
start/stop), server memory must return to baseline. Today the global `monitored_items` reverse index
orphans data-change entries on delete, browse/query continuation points have no TTL sweep, and a
program `Engine` dropped while suspended leaks its task.

**Why this priority**: Directly governs whether the server runs for months without degradation — the
core deployment requirement — but each leak is slow, so below the immediate-DoS P1 items.

**Independent Test**: Run long churn loops (create/delete subscriptions and monitored items; open
browse continuations and abandon them; start/suspend/drop program engines); assert the relevant
indexes/maps and task count return to baseline rather than growing monotonically.

**Acceptance Scenarios**:

1. **Given** repeated create/delete of data-change monitored items, **When** the cycle repeats N times, **Then** the global `monitored_items` and `subscription_to_session` indexes return to their starting size.
2. **Given** abandoned browse/query continuation points, **When** their TTL elapses, **Then** they are evicted without requiring session close.
3. **Given** a program `Engine` dropped while suspended, **When** it is dropped, **Then** its background task is aborted (no leaked task).

---

### User Story 5 - Config & defense-in-depth hardening (Priority: P3)

Tighten footguns and latent risks, and ship safe defaults/profiles for constrained deployments:
bound the "0 = unlimited" config combinations, bound or remove a latent unbounded-allocation API,
allocate decode buffers only after validating stream length, give `max_notifications_per_publish` a
bounded default, and ship deployment limit profiles.

**Why this priority**: Each is low-severity (misconfiguration-gated, latent/unused, or performance
thrash rather than crash), valuable to close but not urgent.

**Independent Test**: Assert config validation rejects the both-zero limit combination; the latent
read API enforces the message-size limit; oversized declared buffers do not pre-allocate before the
stream is confirmed; and the shipped profiles parse and round-trip.

**Acceptance Scenarios**:

1. **Given** both `max_chunk_count` and `max_message_size` set to 0, **When** the server validates config, **Then** it rejects the combination (or applies a hard ceiling) rather than allowing unbounded chunk buffering.
2. **Given** the latent header read API, **When** it reads a declared message size, **Then** it enforces `max_message_size` like the normal decode path.
3. **Given** the shipped `micro`/`gateway`/`server` limit profiles, **When** loaded, **Then** they parse and a server starts with them.

### Edge Cases

- History read where the requested count exceeds available rows (cursor must terminate cleanly, return no continuation).
- Continuation-point TTL eviction racing with a legitimate `HistoryReadNext`/`BrowseNext` (must fail gracefully with the standard "invalid continuation point" status, not panic).
- Activation re-check must not reject legitimate session *transfer* on secured policies (reconnect), only stale-nonce reuse.
- PubSub limit defaults must not reject conformant real-world dataset messages.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The SQLite history backend MUST bound the number of rows it loads to satisfy a `read_raw_modified` request (SQL-level `LIMIT`), independent of the requested time range.
- **FR-002**: History continuation state MUST be represented as a resumable cursor/position rather than a fully materialized remainder `Vec`, and `HistoryReadNext` MUST return subsequent pages in correct order without duplication or loss.
- **FR-003**: Session activation MUST re-validate, under the same lock that commits the activation, that the session nonce/activation generation it authenticated against is still current; if it changed, activation MUST be rejected with an appropriate status and MUST NOT mutate session identity, channel binding, or nonce.
- **FR-004**: Uncontended session activation MUST remain functionally unchanged (no new failure on the normal path), and legitimate secured-policy session transfer/reconnect MUST still be permitted.
- **FR-005**: PubSub decoding MUST enforce configurable upper bounds (e.g. maximum dataset fields, maximum dataset messages, maximum secured payload size) and MUST reject violations before allocating from the declared counts.
- **FR-006**: Multidimensional array length computation from decoded `ArrayDimensions` MUST use checked arithmetic and MUST reject overflow (and exceed-limit) with a decode error rather than wrapping or panicking.
- **FR-007**: Subscription deletion AND expiry MUST fully remove every associated entry from the global `monitored_items` and `subscription_to_session` indexes for all attributes (not only `EventNotifier`), via a single centralized removal path.
- **FR-008**: Browse and query continuation points MUST be subject to TTL/LRU eviction so abandoned points are reclaimed without requiring session close; a `0` configuration MUST NOT mean "unlimited" for these.
- **FR-009**: The program `Engine` MUST abort/cancel its background task on drop, including when dropped while the program is suspended.
- **FR-010**: Server configuration validation MUST reject (or hard-ceiling) the combination of `max_chunk_count = 0` AND `max_message_size = 0` so chunk accumulation can never be unbounded.
- **FR-011**: The latent `MessageHeader::read_bytes` API MUST enforce `max_message_size` before allocating, or be removed if it has no callers.
- **FR-012**: `ByteString` and UADP decoding MUST avoid eagerly allocating a buffer sized from a declared length before the stream is confirmed to hold that many bytes (allocate-after-validate or read incrementally).
- **FR-013**: `max_notifications_per_publish` MUST ship with a bounded (non-zero) default, and the repository MUST provide `micro`, `gateway`, and `server` deployment limit profiles.
- **FR-014**: All changes MUST preserve wire-format byte-identity on the notification/response/republish paths and MUST NOT alter generated code.

### Key Entities *(include if feature involves data)*

- **History continuation cursor**: a resumable position (keyset/offset + query bounds) replacing the materialized remainder `Vec`; identifies where the next page begins.
- **PubSub decoding limits**: configurable ceilings (max dataset fields, max dataset messages, max secured payload size) applied during UADP decode.
- **Browse/Query continuation point**: per-session token with creation time, subject to TTL/LRU eviction.
- **Monitored-item reverse index entry**: global mapping from node/attribute to monitoring handles, which must be created and destroyed in lockstep with the monitored item.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: A `read_raw_modified` over an arbitrarily wide range with a small per-node cap consumes memory proportional to the returned count, not the range; the history worker stays responsive throughout.
- **SC-002**: A stale-nonce concurrent activation is rejected 100% of the time in a targeted race test, while uncontended activation success is unchanged.
- **SC-003**: Crafted oversized/overflowing decode inputs (PubSub field counts, custom-struct dimensions) are rejected with bounded errors and zero process aborts across the malformed corpus.
- **SC-004**: After a sustained subscribe/unsubscribe + abandoned-continuation + program-churn soak, the relevant indexes/maps/task counts return to baseline (no monotonic growth).
- **SC-005**: Config validation rejects the both-zero unlimited combination; the latent read API enforces the size limit; the three deployment profiles load and start a server.
- **SC-006**: `cargo clippy --all-targets --all-features` is clean, the full unit suite and the 98-test integration suite pass, and `verify-clean-codegen` stays green.

## Assumptions

- This work targets our fork only; upstream PRs are held pending private disclosure coordination (notably the FR-003 activation hardening) with the upstream maintainer.
- "Bounded" defaults for new PubSub/continuation limits will be chosen to accept conformant real-world messages; exact numbers are an implementation/plan detail.
- The u32 ID-wraparound collision concern (session/subscription/monitored-item/connection IDs) is **deferred**: it only manifests after ~4.3 billion creations and is irrelevant to low-churn industrial deployments. It is documented here but out of scope for this feature; revisit only if a high-churn gateway use case emerges.
- `no_std`/microcontroller portability is explicitly out of scope (embedded Linux / Pi Zero is the established floor; the OPC UA server belongs off the control MCU).
- Existing limits, moka-backed history continuation cache, and connection-actor panic isolation are reused as the model for the new bounds/eviction work.
