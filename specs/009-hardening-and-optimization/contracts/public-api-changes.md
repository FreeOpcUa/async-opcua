# Contract — 0.19 Public-API Breaking-Change Catalog

The release contract for `0.19.0`. Breaking changes are permitted at this boundary (per Clarifications)
and **every break listed here MUST appear in `CHANGELOG.md`** with a migration note (SC-011). Items are
grouped by surface. "Source-breaking" = downstream code may need edits; "behavioral" = same API,
different runtime default/behavior.

## A. Type-shape breaks (source-breaking)

| # | Change | Migration for consumers | FR |
|---|--------|-------------------------|----|
| A1 | `ByteString` becomes `Bytes`-backed; `value` field and `From<Vec<u8>>`/accessor surface change | Use the new accessors (`as_ref`/`into`/`Bytes`); `Vec<u8>` conversions still provided but may move | FR-045 |
| A2 | Large `Variant` array payloads become `Arc`-backed | Pattern matches/constructors on array variants adapt to the shared representation | FR-045 |
| A3 | Select service methods return `opcua_types::Error` instead of bare `StatusCode` | Match on `Error` (which still carries the `StatusCode` plus request handle/context) | FR-037 |

## B. Trait breaks (source-breaking)

| # | Change | Migration | FR |
|---|--------|-----------|----|
| B1 | `NodeManager` split into capability sub-traits + composing supertrait | Implementers implement the relevant sub-traits; default impls cover unsupported ops (see `node-manager-traits.md`) | FR-043 |

## C. Feature-flag breaks (build-config-breaking)

| # | Change | Migration | FR |
|---|--------|-----------|----|
| C1 | `async-opcua-crypto` `default = []` (legacy-crypto no longer default-on at compile time) | Consumers needing legacy policies enable the `legacy-crypto` feature explicitly (umbrella/crate) | FR-019 |
| C2 | `async-opcua-client` gains a `legacy-crypto` feature; depends on crypto with `default-features = false` | Enable `legacy-crypto` on the client if legacy policies are required | FR-019 |

## D. Behavioral / default changes (not source-breaking, but observable)

| # | Change | Effect | FR |
|---|--------|--------|----|
| D1 | `TCP_NODELAY` on by default | lower latency; disable via new config if bandwidth-batching desired | FR-026 |
| D2 | `max_failed_keep_alive_count` default `0 → 3` | dead-peer detection now active by default | FR-012 |
| D3 | `channel_lifetime` default `60s → 600s` | fewer renegotiations | FR-013 |
| D4 | `max_monitored_items_per_sub` default `0 → non-zero` | per-sub item cap now enforced | FR-007 |
| D5 | `max_timeout_ms` now a ceiling | large client `timeout_hint` is capped | FR-006 |
| D6 | New per-connection / per-IP / unactivated-session limits | abusive single peers throttled/rejected | FR-003/004/005 |
| D7 | RSA decrypt runs on `aws-lc-rs` | constant-time; adds a build-time toolchain consideration for some targets | FR-042 |

## E. Additive (non-breaking) surface

- `async-opcua-client` `websocket` feature + `WebSocketConnector` (`opc.wss`). (FR-044)
- New config fields (§ data-model) — all defaulted, so existing configs keep working. (FR-003/004/005/011/026)
- Optional `metrics-exporter` feature. (FR-031)

## Wire-format contract (HARD GATE)

**No item in this catalog changes the OPC-UA binary wire format.** Enforced by the dotnet +
open62541 interop harnesses running as a CI release gate (FR-046, SC-010). Any change that would alter
bytes-on-the-wire is out of scope and must be rejected in review.
