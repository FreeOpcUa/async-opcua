# Phase 1 — Data Model

This feature is a remediation program, not a data-feature, so the "entities" are the configuration
values, feature flags, type changes, and trait decompositions the work introduces or alters — plus the
finding/track tracking model. Each item notes its validation rules and the FR/finding it serves.

## 1. Configuration: changed defaults (a default value is itself a finding)

| Field | Crate | Old | New | Validation | FR / finding |
|-------|-------|-----|-----|-----------|--------------|
| `max_failed_keep_alive_count` | client | `0` (disabled) | `3` | `0` = explicit opt-out only | FR-012 / N8 |
| `channel_lifetime` | client | `60_000 ms` | `600_000 ms` | renewal timeout derived from this | FR-013 / N9 |
| `max_monitored_items_per_sub` | server | `0` (unlimited) | non-zero default | enforced atomically in `create_monitored_items` | FR-007 / H4 |
| `trust_server_certs` (samples/docs) | client | `true` in samples | `false`; `warn!` when enabled | default already `false`; fix sample/doc usage | FR-035 / M9 |
| `tcp_nodelay` (new) | client+server | n/a (Nagle on) | `true` | applied to every socket | FR-026 / N1 |

## 2. Configuration: new fields

| Field | Crate | Type / default | Purpose | FR / finding |
|-------|-------|----------------|---------|--------------|
| `max_inflight_requests_per_connection` | server | `usize`, safe default | bound per-connection in-flight; backpressure trigger | FR-003 / C3 |
| `max_unactivated_sessions_per_channel` | server | `usize`, small default | cap pre-auth sessions | FR-004 / C4 |
| `unactivated_session_timeout` | server | `Duration`, few seconds | expire pre-auth sessions | FR-004 / C4 |
| `max_connections_per_ip` | server | `usize`, default | per-IP connection cap | FR-005 / H3, N10 |
| `accept_rate_limit` (optional) | server | rate, optional | slowloris accept throttle | FR-005 / N10 |
| `connect_timeout` | client | `Duration`, 5–10 s | TCP connect timeout | FR-011 / N2 |
| `tcp_keepalive` | client+server | struct{enabled, idle, interval, count} | `SO_KEEPALIVE` params | FR-026 / N3 |
| `max_chunk_count` ceiling (derived) | core | from `max_message_size / MIN_CHUNK_SIZE` | hard bound when `0` = "unlimited" | FR-008 / N6, M11 |
| socket buffer sizes (optional) | client+server | optional `SO_SNDBUF`/`SO_RCVBUF` | high-BDP tuning | (N4, optional) |

**Invariant**: every new limit MUST have a safe non-zero default and reject obviously-invalid values at
config-validation time (Constitution IV, fail-closed).

## 3. Feature flags (Cargo) — changed/new

| Flag | Crate(s) | Change | FR / finding |
|------|----------|--------|--------------|
| `legacy-crypto` | `-crypto` | `default = []` (was `["legacy-crypto"]`); umbrella opts in | FR-019 / M12 |
| `legacy-crypto` (new) | `-client` | new, forwards to `-crypto/legacy-crypto`; `default-features = false` on crypto dep | FR-019 / M12 |
| `websocket` (new) | `-client` | optional `opc.wss` connector (tokio-tungstenite + rustls 0.23) | FR-044 / R5 |
| `metrics-exporter` (new, optional) | `-server` | optional Prometheus/OTel exporter | FR-031 / R6 |
| MQTT/pubsub TLS | `-pubsub` | `rumqttc` upgraded to rustls 0.23 stack (or MQTT gated off) | FR-023 / D2 |

**Invariant**: all flags remain **additive** (no mutual exclusion); workspace builds with default,
`--all-features`, and default-features-off (SC-008).

## 4. Type changes (breaking — 0.19)

| Type | Change | Impact | FR / finding |
|------|--------|--------|--------------|
| `ByteString` | `value: Option<Vec<u8>>` → `Bytes`-backed | zero-copy decode; accessor/`From` surface changes | FR-045 / P5 |
| `Variant` array payloads | large arrays `Arc`-backed (`Arc<[T]>` or equivalent) | clone = refcount bump | FR-045 / P10 |
| `NotificationMessage` (retransmission) | held as `Arc<…>` shared with response | no per-publish deep clone | FR-045 / P10 |
| Service-boundary error type | return `opcua_types::Error` (not bare `StatusCode`) where context matters | preserves request handle/context | FR-037 / R2 |
| `AesKey` | redacting `Debug` impl; `Zeroizing`/`ZeroizeOnDrop` for secret buffers | no key bytes in logs; zeroized | FR-016 / M3, M4 |

**State note**: no new lifecycle/state machines; existing session/subscription/secure-channel state
machines are unchanged except where a limit gates a transition (e.g. unactivated-session expiry).

## 5. Trait decomposition (breaking — 0.19) — see `contracts/node-manager-traits.md`

`NodeManager` (fat, ~30 methods) → capability sub-traits (`AttributeProvider`, `HistoryProvider`,
`MethodProvider`, `ViewProvider`, `NodeMutator`, `MonitoredItemProvider`) + composing supertrait.
(FR-043 / R3)

New transport seam (additive): `WebSocketConnector` implementing the existing `Connector`/`Transport`
traits over `StreamConnector`. (FR-044 / R5)
New crypto seam (internal): `RsaDecryptor` trait over the three decrypt paddings. (FR-042 / D1)

## 6. Tracking model (process)

| Entity | Attributes | Purpose |
|--------|-----------|---------|
| **Finding** | id (C1/V3/N1/P2/R1…), severity, source-doc, owning crate, FR, status (open/fixed/deferred), regression-test ref | one task each (Constitution III); traceability for SC-009 |
| **Track** | A–H, theme, crates, member findings, sequence position | grouping + sequencing |
| **Breaking change** | item, old→new shape, changelog entry | assembled into the 0.19 changelog (SC-011) |
| **Advisory exception** | crate, RUSTSEC id, rationale, expiry/review | recorded in `deny.toml` (FR-022) |

**SC-009 invariant**: every Finding ends in status `fixed` (with a regression-test ref) or `deferred`
(with a written rationale) — never silently dropped.
