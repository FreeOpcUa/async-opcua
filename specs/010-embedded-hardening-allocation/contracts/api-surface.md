# Public API Surface (Contracts): Embedded Hardening & Allocation Follow-ups

For a library, the "contracts" are the public API and on-wire behavior. This feature is
**hardening/performance**, so the guiding rule is: **additive and non-breaking where possible, and
byte-identical on the wire for well-behaved peers.** Any breaking change must be called out here.

## Wire contract (all stories)

- **Unchanged.** Encoded responses, notifications, and republished notifications MUST be
  byte-for-byte identical for well-behaved peers (FR-009, SC-005). New rejections (oversized message,
  excessive depth) only affect *malformed/abusive* inputs and surface as standard OPC UA error
  status codes, not new framing.

## `DecodingOptions` (async-opcua-types) — FR-002, FR-003

- **Add** `max_decode_depth: u32` (or similar) with a safe default.
  - Additive; constructed via the existing builder/`Default`. Existing callers keep working (default applied).
  - `MessageHeader::decode` begins honoring `DecodingOptions` (`max_message_size`) — behavior change only for over-limit declared sizes (previously buffered, now rejected).
- **Error**: over-depth and over-size decode return existing error types (`StatusCode::BadDecodingError` / `BadTcpMessageTooLarge` or equivalent) — no new public error variants required.

## Server config (async-opcua-server) — FR-004

- **Add** configurable cap(s) (and optional TTL) for the GDS registries, exposed through the existing server/limits config with safe defaults (additive; default behavior bounded). Document overflow semantics.

## Server runtime/dispatch (async-opcua-server) — FR-006

- **Internal only.** The inline read fast-path is an implementation detail; no public API change. Behavior (results, isolation) unchanged.

## Notification pooling (async-opcua-server) — FR-005

- **Internal only.** Pool is private to the subscription module; no public API change; observable behavior (notification content, ordering, republish) unchanged.

## Decode buffer sharing (async-opcua-types) — FR-007

- Prefer **additive** decode entry points that accept a shared `Bytes` source; keep `SimpleBinaryDecodable`/existing decode signatures working (fallback to copy). If a trait-surface change is unavoidable, document it here as a deliberate, justified change before landing (Principle II) — and prefer staging/deferral over a breaking change that the measured benefit does not justify (Principle I).

## Lints / build (workspace) — FR-001, FR-008

- **Add** `#![deny(...)]` panic-surface lints scoped to the network-facing crates (compile-time contract on contributors, not a runtime API change).
- **Add** a size-optimized release profile + docs (FR-008) — additive profile, no API change.

## Breaking-change ledger

- Intended: **none.** All items are additive (new options/config with defaults) or internal. The only behavior change for *existing* peers is the rejection of over-limit declared message sizes / over-deep structures — which were previously latent DoS vectors, not legitimate traffic. Any deviation discovered during implementation MUST be recorded here.
