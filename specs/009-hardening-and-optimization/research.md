# Phase 0 — Research & Technical Decisions

Resolves every open technical decision needed before design. Each entry uses Decision / Rationale /
Alternatives. The only genuinely uncertain decision (the RSA backend) was investigated against the
actual source; the rest are best-practice choices grounded in the existing codebase.

---

## R0.1 — Constant-time RSA backend (FR-042 / D1) ✅ resolved

**Decision**: Migrate **only the three network-reachable RSA *decrypt* operations** (PKCS#1 v1.5,
OAEP-SHA1, OAEP-SHA256) to **`aws-lc-rs`**, behind a narrow internal `RsaDecryptor` trait in
`async-opcua-crypto`. Keep the RustCrypto `rsa` crate for everything else (signing, verification,
public-key encrypt, key generation, and all `x509-cert` integration). Land an application-level
uniform-timing/uniform-error stopgap (FR-017) **first**, then the backend swap.

**Rationale**:
- The Marvin-vulnerable operation is RSA **decrypt** on the server private key, reachable
  pre-authentication via OpenSecureChannel and identity-token decrypt (`policy/aes.rs:389`,
  `user_identity.rs:248`, `identity/rsa_oaep.rs:35`).
- `aws-lc-rs` is the **only** candidate that provides the exact decrypt primitives needed (PKCS1v15 +
  OAEP-SHA1 + OAEP-SHA256) **and** is constant-time for decrypt (AWS-LC / s2n-bignum lineage,
  explicitly Marvin-hardened). It ships prebuilt bindings for Linux x86_64/aarch64, so CI
  (`ubuntu-latest`) and the .NET interop job are unaffected.
- Keeping `rsa`/`x509-cert` for signing/verify/encrypt/keygen/cert-build avoids ripping out the X509
  stack, which is tightly bound to `rsa`'s `SigningKey`/`RsaPublicKey` types (`x509.rs:517,633`). Only
  the vulnerable path moves; OPC-UA wire format is byte-identical (standardized OAEP/PKCS1v15 ct
  encoding).
- The abstraction is one trait over three functions; **no call sites change** because all decrypts
  already route through `private_decrypt::<T>` where `T` names the padding.

**Alternatives considered**:
- **`ring`** — rejected: exposes RSA signing/verification only, **no private-key decryption**; cannot
  cover the actual vulnerable surface. (Also only present transitively via pubsub, not in the server
  crypto build.)
- **`openssl`** — viable (complete primitives, constant-time), rejected as primary: imposes a system
  libssl / C-toolchain dependency on every downstream consumer of a *published* library — a worse
  portability regression than `aws-lc-rs`'s prebuilt bindings. Kept as the documented fallback if the
  team wants to avoid any C toolchain for niche consumer targets.
- **`rustls` primitives** — N/A: no raw-RSA decrypt API.
- **Stay on `rsa`, app-layer mitigation only** — insufficient alone (the timing signal originates
  below our error handling); used as the phase-1 stopgap, not the fix (Constitution II).

**Migration sketch**: `RsaDecryptor { decrypt_pkcs1v15 / decrypt_oaep_sha1 / decrypt_oaep_sha256 }` in
`aes/rsa_private_key.rs`; replace the body of `private_decrypt` (`:240-273`) to dispatch to it; load
the `aws-lc-rs` key from the same PKCS#8/PKCS#1 DER already parsed (single key source of truth). Add a
cross-backend round-trip test (encrypt via `rsa` public path → decrypt via `aws-lc-rs`, all 3 paddings,
2048/4096-bit) and assert MGF1 hash == OAEP hash. Files changed: `aes/rsa_private_key.rs`, the two
crate `Cargo.toml`s; **no public API change**.

**Risk**: low–moderate; main risk is `aws-lc-rs` build on non-Linux consumer targets (mitigated by
prebuilt bindings; document CMake fallback).

---

## R0.2 — WebSocket (`opc.wss`) transport + EOL TLS stack removal (FR-044 / R5, FR-023 / D2)

**Decision**: Implement a `WebSocketConnector` in `async-opcua-client` behind an optional `websocket`
feature, built on `tokio-tungstenite` over **rustls 0.23** (`tokio-rustls` 0.26), wrapping the existing
`StreamConnector<R,W>` (any `AsyncRead + AsyncWrite`). Separately, upgrade `async-opcua-pubsub`'s
`rumqttc` to a release built on rustls 0.23 / webpki 0.103+, removing the EOL rustls 0.21 / webpki
0.101 stack. Standardize the whole workspace on **one rustls 0.23 line**.

**Rationale**: The client transport seam already accepts any byte stream, so WebSocket is additive (no
breaking change). Aligning the WebSocket TLS stack with the `rumqttc` upgrade means the workspace pulls
a single, maintained rustls major — avoiding two TLS stacks and closing D2. `opc.wss` unlocks
443-only/proxy deployments (N11).

**Alternatives**: `async-tungstenite` (runtime-agnostic) — rejected, the codebase is tokio-committed;
`tokio-tungstenite` is the direct fit. Native-tls — rejected, adds a system TLS dependency.

**Open item for tasks**: confirm the latest `rumqttc` release's rustls major; if no release is on
0.23, evaluate feature-gating the MQTT transport off-by-default (FR-023 allows either).

---

## R0.3 — `Bytes`-backed `ByteString` & `Arc`-backed `Variant` (FR-045 / P5, P10)

**Decision**: Change `ByteString.value` from `Option<Vec<u8>>` to an `Option<bytes::Bytes>`-backed
representation so inbound byte strings decode zero-copy from the chunk buffer; back large `Variant`
array payloads and the subscription retransmission `NotificationMessage` with `Arc` so fan-out is a
refcount bump. This is a **breaking API change** (acceptable at 0.19) — `ByteString` accessors and any
`From<Vec<u8>>`/`AsRef<[u8]>` surface change shape.

**Rationale**: P5/P10 are the deepest steady-state copies (per-decode and per-notification-fanout).
`bytes::Bytes` is already the chunk-buffer type, so `ByteString` sharing the same backing is the
natural zero-copy path. Doing this at 0.19 (breaking allowed) avoids a later second break.

**Alternatives**: keep `Vec<u8>` and only optimize internally — rejected, can't achieve zero-copy
without the type change. A `Cow`-style enum — rejected, more complex than `Bytes` (which already gives
cheap clone + slice). Sequence behind the new benchmarks (FR-030) so the payoff is measured against the
API-churn cost (per the performance audit's guidance).

---

## R0.4 — Socket tuning: NODELAY, keepalive, connect timeout (FR-026 / N1, N3, N2)

**Decision**: Call `TcpStream::set_nodelay(true)` directly on every accepted and connected socket
(server accept loop + client `TcpConnector` + reverse-connect accept). Add `SO_KEEPALIVE` (configurable
idle/interval/probe) via the **`socket2`** crate, applied to the socket before/after connect. Wrap the
client `TcpStream::connect` in `tokio::time::timeout(connect_timeout, …)` with a configurable default
(5–10 s). Surface `tcp_nodelay`, keepalive params, and `connect_timeout` in client/server config
(NODELAY default on; keepalive default on with conservative timings).

**Rationale**: `tokio::TcpStream` exposes `set_nodelay` directly but **not** keepalive, so `socket2`
(or `TcpSocket`) is required for `SO_KEEPALIVE`. These are the highest-ROI network changes (N1, N8 are
the audit's "start here").

**Alternatives**: rely on application keep-alive only — rejected, doesn't fix half-open detection and
the app keep-alive default is itself a finding (N8). `TcpSocket` builder instead of `socket2` —
`socket2` is more flexible for post-connect keepalive on an accepted stream; either is acceptable.

---

## R0.5 — Dependency-advisory gate (FR-022 / P1) + dependency upgrades (FR-024 / D3–D5)

**Decision**: Add a `deny.toml` and a CI job running `cargo deny check advisories bans sources`. Record
explicit, justified exceptions for advisories with no fix (notably **`rsa` RUSTSEC-2023-0071**, which
is mitigated by R0.1 but may linger transitively until the migration fully removes the decrypt use).
Pin/install a `cargo-deny` version that parses CVSS-4.0 advisories (the locally-installed one aborts).
Upgrade `time` ≥ 0.3.47 (D3), `rand` ≥ 0.8.6/0.9.3 (D4), migrate `serde_yaml` → a maintained YAML crate
(`serde_yml` or `serde_norway`) or drop YAML config (D5), and evaluate `thiserror` v2 / `env_logger`
bump.

**Rationale**: Without the gate, D1–D5 shipped silently; the gate must land **early** (CI-first) so all
later work is validated. Exceptions-with-rationale keep the gate green where no upstream fix exists.

**Alternatives**: `cargo audit` — also fine, but `cargo-deny` additionally covers bans/sources/licenses
in one gate and uses the same RustSec DB. `serde_yml` vs `serde_norway` decided at task time by
maintenance status and API compatibility.

---

## R0.6 — Decoder recursion guard (FR-001 / C1)

**Decision**: Add `let _lock = ctx.options().depth_lock()?;` at the top of `DiagnosticInfo::decode`,
`DataValue::decode`, and the dynamic-struct `decode_type_inner` (or depth-lock the `DATA_VALUE` /
`DIAGNOSTIC_INFO` branches in `decode_variant_value`). Extend the fuzz corpus with deeply-nested inputs
and run the fuzzers with a constrained stack so recursion DoS is caught going forward.

**Rationale**: The `DepthGauge` infrastructure already exists and is threaded through `Context`; the
fix is one line per site. The fuzz gap (the existing targets missed these) is closed by the corpus +
constrained-stack run.

**Alternatives**: an explicit recursion counter — rejected, duplicates the existing `DepthGauge`.

---

## R0.7 — Server ingress rate control (FR-003/004/005/006/008 — C3, C4, H2, H3, N6, N10)

**Decision**: Treat the DoS findings as one coordinated "ingress rate control" design: (a) per-connection
in-flight request semaphore with **backpressure at the transport read** (stop reading new messages once
the in-flight limit is hit — TCP's receive window then throttles the peer) rather than an unbounded
`FuturesUnordered`; (b) per-secure-channel cap on **unactivated** sessions + a short unactivated
timeout, counted before authentication; (c) per-source-IP connection cap + accept rate limit at the
accept loop; (d) `max_timeout_ms` applied as `timeout.min(max)` when client > 0 (ceiling, not floor);
(e) a hard chunk-count ceiling derived from `max_message_size / MIN_CHUNK_SIZE` even when
`max_chunk_count == 0`. All new limits are config fields with safe non-zero defaults.

**Rationale**: These findings interlock (an unbounded queue + inverted timeout + no per-IP cap compound
each other), so they share one design even though each is an individual task. Backpressure-via-TCP is
preferred over buffering+reject because it pushes flow control to the kernel.

**Alternatives**: global-only limits — rejected (the existing single global caps are exactly what one
client/IP exhausts). Reject-with-`BadTooManyOperations` instead of backpressure — acceptable fallback
where backpressure isn't structurally possible.

---

## R0.8 — `NodeManager` capability-trait segregation (FR-043 / R3)

**Decision**: Split the ~30-method `NodeManager` into capability sub-traits (e.g. `AttributeProvider`,
`HistoryProvider`, `MethodProvider`, `ViewProvider`, `NodeMutator`, `MonitoredItemProvider`) composed
by a `NodeManager` supertrait. Provide blanket/default impls so existing implementers need minimal
change, but the public trait shape changes (breaking — acceptable at 0.19). Detailed decomposition in
`contracts/node-manager-traits.md`.

**Rationale**: ISP violation flagged in R3; the segregation makes implementers depend only on what they
provide and improves testability. Done at 0.19 with the other breaks.

**Alternatives**: keep the fat trait, document the default-impl pattern as the substitute — rejected
given breaking changes are now permitted and "do it right once" (Constitution II) favors the real fix.

---

## R0.9 — Codegen: drop `unsafe impl Send/Sync`, derive binary impls (FR-036 / L1, R1)

**Decision**: In `async-opcua-codegen`, stop emitting the 305 `unsafe impl Send/Sync` blocks (rely on
auto-derivation) and emit `#[derive(BinaryEncodable, BinaryDecodable)]` instead of hand-written binary
impls (matching how JSON/XML are already derived). Regenerate; the `ci_verify_clean_codegen` workflow
proves the output is reproducible. This removes all `unsafe` from the generated data types and a large
fraction of generated LOC, with no behavioral change.

**Rationale**: The `unsafe impls` are redundant and a latent unsoundness footgun; the hand-written
binary impls duplicate logic the derive macros already provide. Pure cleanup, zero wire change —
validated by codegen-reproducibility + interop.

**Alternatives**: keep but document — rejected; removal is strictly better and low-risk.

---

## Resolved NEEDS CLARIFICATION

- **Performance numeric targets** — intentionally deferred: set after baseline benchmarks (FR-030/P12)
  exist; until then SC-006/SC-007 use "measurable improvement vs. baseline." This is the one
  Technical-Context "NEEDS CLARIFICATION" and it is resolved as a *sequencing* decision (benchmark
  first), not an open question.
- All other Technical-Context fields are known from the existing workspace; no remaining unknowns.
