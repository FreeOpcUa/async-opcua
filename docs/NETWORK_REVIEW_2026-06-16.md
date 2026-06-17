# async-opcua — Network Engineering Review & Recommendations

**Date:** 2026-06-16
**Scope:** The library as a network protocol stack — the TCP socket layer, the OPC-UA TCP binary
transport (HELLO/ACK handshake, chunking/framing), TLS secure channel, the timeout/keep-alive
hierarchy, transport options, and network-level flow control / DoS resistance.
**Lens:** This is not cloud infrastructure — there is no VPC/LB/DNS to configure. The
network-engineering surface here is how the library *behaves on the wire and on the socket*: latency,
liveness detection, connection resilience, throughput on real links, and resistance to network-level
abuse. Security-specific items (auth, crypto) live in `SECURITY_AUDIT_2026-06-16.md`; this document
covers them only where the *network behavior* is the issue.

Companion docs: `CODE_REVIEW_2026-06-16.md`, `SECURITY_AUDIT_2026-06-16.md`,
`ARCHITECTURE_REVIEW_2026-06-16.md`.

---

## Executive summary

The wire protocol implementation is solid: HELLO/ACK buffer-size negotiation is correct and
symmetric, the secure channel and chunking are well-structured, **reverse-connect (Reverse Hello) is
supported** (valuable for firewall traversal), and the recent allocation-free streaming chunk encoder
is good for throughput. The gaps are at the **socket-tuning layer** and in a few **default timeout
values**, not in the protocol logic:

1. **No TCP socket tuning at all.** `TcpStream::set_nodelay` is never called, so **Nagle's algorithm
   is left enabled** — a real latency penalty for OPC-UA's small request/response messages. No
   `SO_KEEPALIVE`, no socket send/recv buffer sizing, and **no TCP connect timeout** on the client.
2. **Two default values undermine liveness detection:** the client's `max_failed_keep_alive_count`
   defaults to **0, which disables** keep-alive-driven disconnect entirely, and the channel lifetime
   default (60 s) forces frequent renegotiation while the renewal request timeout is hardcoded to 30 s.
3. **No WebSocket (`opc.wss`) transport** in client/server — only raw `opc.tcp` and reverse-TCP.
   Limits deployment behind 443-only proxies/firewalls.
4. **No network-level rate limiting** (per-IP connection caps, in-flight bounds) — covered as DoS in
   the security audit; restated here as the network control that's missing.

Severity legend: **High** = materially affects latency/liveness/throughput in common deployments;
**Medium** = affects specific topologies (WAN, NAT, restrictive firewalls); **Low** = tuning/polish.

---

## 1. TCP socket layer

The library uses `tokio::net::TcpStream`/`TcpListener` directly and **applies no socket options**.
Confirmed: no `set_nodelay`, no keepalive, no `socket2`/`TcpSocket` usage, no buffer sizing anywhere
in the workspace. Connection establishment: server `TcpListener::bind` + `accept` loop
(`server.rs:140, 635`), client `TcpStream::connect(addr)` (`transport/tcp.rs:96`).

### N1 — Enable `TCP_NODELAY` (disable Nagle) · **High**
OPC-UA is a request/response protocol dominated by small messages (Read, Browse, Publish, keep-alive
Reads). With Nagle's algorithm on (the default) interacting with the peer's delayed-ACK, each
small write can incur up to ~40 ms of artificial latency while the stack waits to coalesce segments.
Industrial OPC-UA deployments are frequently latency-sensitive (control loops, alarms), and virtually
every mature OPC-UA stack sets `TCP_NODELAY`.
- **Server:** set on each accepted socket in the accept loop (`server.rs` ~`:140`).
- **Client:** set on the connected socket in `TcpConnector` (`transport/tcp.rs:96`) and the
  reverse-connect accept path (`tcp.rs:239`).
- **→ Call `stream.set_nodelay(true)` on every `TcpStream` (accepted and connected).** Consider
  exposing it as config (default on) for the rare bandwidth-over-latency case. This is the single
  highest-impact network change and is one line per call site.

### N2 — Add a client TCP connect timeout · **Medium**
`TcpStream::connect(addr).await` (`transport/tcp.rs:96`) has **no timeout**. Connecting to a
black-holed / firewalled host (SYN dropped, no RST) hangs for the OS default SYN timeout — often
60–130 s on Linux — before the session retry logic can even react. This stalls reconnection against
exactly the failure mode (a silently-dropped peer) that resilience logic exists to handle.
- **→ Wrap the connect in `tokio::time::timeout(connect_timeout, TcpStream::connect(addr))`** with a
  configurable default (e.g. 5–10 s), and surface it in `ClientConfig`. The session retry/backoff
  loop will then drive reconnection promptly.

### N3 — Enable TCP keep-alive (`SO_KEEPALIVE`) on long-lived sockets · **Medium**
OPC-UA secure channels and subscriptions are long-lived and often idle (subscriptions only push on
data change). With no TCP keepalive, a peer that vanishes (cable pull, NAT state eviction, firewall
idle timeout) leaves a **half-open** connection that is only detected by application-layer mechanisms
— and on the client that mechanism is *disabled by default* (see N5). TCP keepalive provides a
transport-level liveness backstop and also keeps NAT/firewall flow state alive on idle channels.
- **→ Set `SO_KEEPALIVE` (with sensible idle/interval/probe counts) on accepted and connected
  sockets** via `socket2` (tokio's `TcpStream` exposes `set_nodelay` but keepalive needs `socket2` or
  `TcpSocket`). Make the keepalive parameters configurable.

### N4 — Expose socket send/recv buffer sizing for high-BDP links · **Low–Medium**
The `send_buffer_size`/`recv_buffer_size` throughout the code are **OPC-UA protocol buffers**
(application-level message assembly, negotiated in HELLO/ACK), *not* socket buffers — `SO_SNDBUF`/
`SO_RCVBUF` are never set. On high-bandwidth-delay-product paths (WAN, satellite, cross-region), the
OS default socket buffers can cap throughput well below the link capacity for large history reads or
bulk subscription bursts.
- **→ Optionally expose `SO_SNDBUF`/`SO_RCVBUF` configuration** (default = OS auto-tuning, which is
  usually fine on modern Linux). Lower priority than N1–N3; relevant mainly for WAN/bulk scenarios.

### N5 — (see §3) the client keep-alive default disables liveness detection
Cross-referenced here because it compounds N3: with no TCP keepalive *and* the app keepalive disabled
by default, a half-dead client connection is detected by nothing until a request happens to fail.

---

## 2. OPC-UA TCP protocol layer (framing & negotiation)

Reviewed `async-opcua-core/src/comms/` (`tcp_types.rs`, `tcp_codec.rs`, `message_chunk.rs`,
`buffer.rs`) and both transports' HELLO/ACK handling.

**Done well (preserve):**
- **HELLO/ACK buffer negotiation is correct and symmetric.** Each side takes the min of its own and
  the peer's advertised buffer sizes (`server/transport/tcp.rs:184-185`,
  `client/transport/stream.rs:213, 420-440`), validates against `MIN_CHUNK_SIZE` (8192), and logs
  when clamping. This is exactly per OPC-UA Part 6.
- **`message_size > max_message_size` is rejected on decode** (`message_chunk.rs:172`), bounding
  per-message memory.
- The **allocation-free streaming chunk encoder** (recent work) is a genuine throughput/GC-pressure
  win on the transmit path.

### N6 — `max_chunk_count == 0` means "unlimited" on both peers · **Medium** (network DoS)
The chunk-count guards only fire when `max_chunk_count > 0` (server `transport/tcp.rs:396`, client
`transport/core.rs`), but 0 is the documented "unlimited" sentinel. A malicious or malfunctioning
peer can stream unbounded intermediate chunks for a single message and exhaust memory before the
`max_message_size` check can help (the limit is per-assembled-message, but chunk accumulation happens
first). This is the wire-level form of the DoS findings in the security audit (V3/M11).
- **→ Enforce a hard chunk-count ceiling derived from `max_message_size / MIN_CHUNK_SIZE`** even when
  `max_chunk_count == 0`, so "unlimited" still has a physical bound.

### N7 — Document/validate the chunk-vs-MTU and Nagle interaction · **Low**
`MIN_CHUNK_SIZE` is 8192 and negotiated buffers are larger, so chunks span many TCP segments (normal
and fine). But the streaming encoder writes chunk-by-chunk; **with Nagle on (N1), per-chunk writes
can be coalesced/delayed.** Fixing N1 (NODELAY) resolves the latency side; ensure the encoder uses
vectored/batched writes where possible so a multi-chunk message isn't many tiny `write` syscalls.
- **→ After enabling NODELAY, confirm multi-chunk sends use buffered/vectored writes** (the
  `SendBuffer.read_into_async` path) to avoid syscall amplification.

---

## 3. Timeout & keep-alive hierarchy

Defaults gathered from `async-opcua-client/src/config.rs` and `async-opcua-server/src/config/`:

| Parameter | Side | Default | Assessment |
|-----------|------|---------|------------|
| `hello_timeout` | server | 5 s | Reasonable; partial slowloris guard (but per-conn only — see N9) |
| `channel_lifetime` | client | 60 000 ms (60 s) | **Short** — forces renegotiation ~every 45 s |
| secure-channel renewal request timeout | client | **hardcoded 30 s** | Ignores config; breaks if lifetime < 30 s |
| `session_timeout` | client | 60 000 ms | Reasonable |
| `keep_alive_interval` | client | 10 s | Reasonable |
| `max_failed_keep_alive_count` | client | **0 (disabled)** | **Liveness detection off by default** |
| `request_timeout` / `publish_timeout` | client | 60 s | Reasonable |
| server `max_timeout_ms` (request cap) | server | — | **Inverted** — acts as floor not ceiling (see audit H2) |

### N8 — `max_failed_keep_alive_count` defaults to 0, disabling dead-peer detection · **High**
The client sends a keep-alive `Read` every 10 s, but with `max_failed_keep_alive_count = 0` no number
of consecutive failures ever triggers a disconnect/reconnect (`event_loop.rs:175-176`). Combined with
no TCP keepalive (N3), a client whose server has silently died stays "connected" indefinitely,
surfacing the failure only when an application request eventually times out.
- **→ Default `max_failed_keep_alive_count` to a small non-zero value (e.g. 3)** so three missed
  keep-alives (~30 s) trigger reconnection. Keep 0 as an explicit opt-out, documented.

### N9 — Channel lifetime (60 s) + hardcoded 30 s renewal timeout · **Medium**
A 60 s `channel_lifetime` is short — most stacks use 600 000 ms (10 min) or longer — so the client
renegotiates the security token roughly every 45 s (renewal typically at 75% of lifetime), adding
asymmetric-crypto overhead and chattiness. Worse, the renewal request timeout is **hardcoded to 30 s**
(`transport/channel.rs:189`); if an operator lowers `channel_lifetime` below ~40 s the token can
expire before a stalled renewal times out, and a stalling server can wedge the client into repeated
30 s renewal attempts (the channel isn't torn down on renewal failure).
- **→ Raise the default `channel_lifetime` (e.g. 600 000 ms), derive the renewal request timeout from
  config/lifetime instead of hardcoding 30 s, and tear down + reconnect the channel on renewal
  failure.** (Also security M10.)

### N10 — Server slowloris exposure on the HELLO phase · **Medium** (network DoS)
`hello_timeout = 5 s` bounds how long one connection may stall before HELLO, but there is **no per-IP
connection cap and no accept rate limit** (security H3). An attacker opens many connections, never
sends HELLO, and recycles them every 5 s to keep all `max_connections` (default 100) slots occupied.
- **→ Add a per-source-IP connection cap and an accept rate limit** at the accept loop
  (`server.rs:140`). This is the network-layer control that complements the 5 s hello timeout.

---

## 4. TLS / secure channel (network view)

The secure channel and policy negotiation are reviewed in depth in the security audit; from a network
standpoint:
- **Policy negotiation is correct** — unknown/unsupported/deprecated policies are rejected before any
  crypto, endpoints are matched on exact policy+mode (no downgrade). Good.
- **No `opc.https`/TLS-wrapped transport** — OPC-UA's own message security is used over raw TCP. This
  is spec-normal, but see N11 (no WebSocket-over-TLS option for proxy traversal).
- **`rsa` crate Marvin timing attack (no fix)** is a *network-observable* timing side-channel on RSA
  operations — see security audit D1; the network-relevant mitigation is uniform-timing error
  responses so the oracle isn't amplified by distinguishable/variable-latency replies.
- **Certificate lifecycle:** the cert store supports trust folders and (client) optional auto-trust;
  there is no automated renewal/rotation hook. **→ Consider a certificate-expiry monitoring hook**
  so long-running servers/clients can alert before their application-instance cert expires (industrial
  deployments run for years).

---

## 5. Transports & connectivity

Client transports: `opc.tcp` (`TcpConnector`) and **reverse-connect / Reverse Hello**
(`ReverseTcpConnector`) — the latter is a genuine strength for firewall traversal (server dials out
to client, so no inbound port on the client side). The transport seam (`Connector`/`Transport` +
`StreamConnector` over any `AsyncRead+AsyncWrite`) is cleanly pluggable. WebSocket exists **only** in
`async-opcua-pubsub` (`transport/websocket.rs`, tungstenite), not in the client/server session path.

### N11 — No WebSocket (`opc.wss`) transport for the client/server · **Medium**
Many industrial/enterprise networks only permit outbound 443 and route everything through HTTP(S)
proxies. OPC-UA defines `opc.wss` (binary over WebSocket-over-TLS) precisely for this. The client's
`StreamConnector` abstraction already supports it in principle (a tungstenite stream is
`AsyncRead+AsyncWrite`), but no connector ships.
- **→ Ship an optional `websocket` feature with a `WebSocketConnector`** built on `StreamConnector` +
  `tokio-tungstenite`, on a *maintained* TLS stack (see N12). This unlocks proxy/443-only
  deployments and validates the transport abstraction. (Also architecture R5.)

### N12 — pub/sub MQTT path rides an EOL TLS stack · **Medium**
`async-opcua-pubsub` depends on `rumqttc 0.23`, which pulls **rustls 0.21 / rustls-webpki 0.101** —
both end-of-life with unfixed advisories on those lines (security audit D2). For a network transport
carrying telemetry this is the wrong stack to be pinned to.
- **→ Upgrade `rumqttc` to a release on rustls 0.23 / webpki 0.103+**, or feature-gate the MQTT
  transport so it isn't compiled by default.

### N13 — Discovery / LDS registration robustness · **Low**
The server can register with a Local Discovery Server (feature `discovery-server-registration`,
becoming a client). Verify the registration loop has bounded retry/backoff and doesn't hammer the LDS
on failure (the client reconnection backoff applies if it reuses the session event loop).
- **→ Confirm LDS re-registration uses capped backoff** and surfaces registration failures as
  metrics/logs rather than silent retry.

---

## 6. Network-level flow control & DoS resistance

Restating the network-control gaps (full detail in the security audit), because these are the
network-layer defenses a protocol server is expected to have:

- **No per-IP connection cap / accept rate limit** (N10) — single source can exhaust connection slots.
- **No per-connection in-flight request bound** (`session/controller.rs` unbounded
  `FuturesUnordered`) — a single connection can pipeline requests faster than they drain. This is the
  missing **bulkhead**; the fix is a per-connection concurrency semaphore with **backpressure at the
  transport read** (stop reading once the in-flight limit is hit), which naturally throttles the peer
  via TCP flow control (the receive window closes) rather than buffering unboundedly.
- **Unbounded chunk accumulation** when `max_chunk_count == 0` (N6).
- **Inverted request-timeout cap** (`max_timeout_ms` is a floor; security H2) lets a peer hold slow
  requests open beyond the intended ceiling.
- **→ Treat these as one coordinated "ingress rate control" workstream:** per-IP cap, per-connection
  concurrency + TCP backpressure, hard chunk ceiling, and a correct request-timeout ceiling.

---

## 7. Network observability

Per-server `ServerMetrics` exists (atomics) but exposes **no connection/transport-level network
signals and no exporter** (architecture R6). For operating a network service you want:
- Active TCP connections (gauge), connections accepted/rejected/timed-out (counters).
- Bytes in/out, messages in/out, chunks in/out.
- Secure-channel opens/renews/failures; session counts; subscription publish latency.
- Reconnection events and backoff state (client side).
- **→ Add these counters at the accept/connect/enqueue/renew sites and ship an optional
  Prometheus/OTel exporter.** Without on-wire visibility, diagnosing latency/liveness issues in the
  field requires packet capture.

---

## 8. Prioritized action list

| # | Recommendation | Severity | Effort |
|---|----------------|----------|--------|
| N1 | `set_nodelay(true)` on all sockets (disable Nagle) | High | Trivial |
| N8 | Default `max_failed_keep_alive_count` to non-zero (re-enable liveness) | High | Trivial |
| N2 | Client TCP connect timeout | Medium | Low |
| N3 | `SO_KEEPALIVE` on long-lived sockets | Medium | Low |
| N10 | Per-IP connection cap + accept rate limit (slowloris) | Medium | Medium |
| N6 | Hard chunk-count ceiling even when `max_chunk_count==0` | Medium | Low |
| N9 | Raise channel lifetime; derive renewal timeout; teardown on renewal fail | Medium | Low |
| N11 | Ship a WebSocket (`opc.wss`) connector | Medium | Medium |
| N12 | Move pub/sub MQTT off the EOL rustls 0.21 stack | Medium | Low |
| §6 | Coordinated ingress rate control (in-flight bound + TCP backpressure) | Medium | Medium |
| N7 | Confirm vectored/batched multi-chunk writes | Low | Low |
| N4 | Optional `SO_SNDBUF`/`SO_RCVBUF` sizing for high-BDP links | Low | Low |
| §7 | Network/transport metrics + exporter | Low–Med | Medium |
| N13 | Bounded-backoff LDS re-registration | Low | Low |
| §4 | Certificate-expiry monitoring hook | Low | Low |

**Start with N1 and N8** — both are essentially one-line default changes with outsized impact:
`TCP_NODELAY` removes a latency penalty that affects *every* deployment, and re-enabling keep-alive
failure detection fixes silent half-dead connections that affect *every* idle long-lived client. The
protocol logic is sound; these are the socket-hygiene and default-tuning items that separate a correct
implementation from a production-grade network service.
