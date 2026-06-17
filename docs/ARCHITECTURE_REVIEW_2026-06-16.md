# async-opcua — Architecture Review & Recommendations

**Date:** 2026-06-16
**Scope:** Whole-workspace architecture (17 crates). Focus is structure, boundaries, abstractions,
and evolvability — *not* bugs or security (those are in `CODE_REVIEW_2026-06-16.md` and
`SECURITY_AUDIT_2026-06-16.md`).
**Verdict up front:** This is a **mature, well-architected** workspace. The layering is a clean
acyclic DAG, the extension points (node managers, authenticators, type loaders, transports) are
genuinely well-designed around object-safe async traits with dependency inversion, and the
async/state-machine code is idiomatic. The improvement opportunities are concentrated in three
places: the **codegen emission layer**, **error-context loss at API boundaries**, and a few
**packaging/observability** gaps. None are structural rewrites.

---

## 1. System context & layering

async-opcua is a pure-Rust OPC UA protocol stack (client + server + pub/sub) published as an umbrella
crate (`async-opcua`) that re-exports a set of focused sub-crates. The dependency graph is a clean
DAG with no cycles:

```
            macros        xml                      (foundation: proc-macros, XML parsing)
              │            │
              ▼            ▼
            types ◄────────┘                        (encoding traits, ~113k LOC incl. ~88k generated)
           ╱  │  ╲
       crypto  │   nodes ──► xml/macros             (security policies; address-space node model)
          │    │    │
          ▼    ▼    ▼
            core            core-namespace          (secure channel, chunking, comms)
              │              (generated, ~240k LOC)
        ┌─────┴─────┐
        ▼           ▼
     client       server ──(opt: discovery)──► client
                    │  ╲
                    ▼   ╲(dev-only)► history-sqlite
                 pubsub ─► server, core, crypto, types
        (codegen: standalone build-time tool; safety: standalone helpers)
```

Two edges deserve note and are **both fine**:
- `server → client` is **optional**, gated behind `discovery-server-registration` (the server becomes
  a client to register with a Local Discovery Server). Documented rationale; not a cycle.
- `server ↔ history-sqlite` looked circular but `history-sqlite` is only a **dev-dependency** of
  server. No real cycle.

The big crates (`types`, `core-namespace`) are large only because of generated code; splitting them
out is the correct call for compile times and semver isolation.

---

## 2. What's done well (preserve these)

- **Dependency inversion via trait-object injection is exemplary.** The server core depends only on
  `NodeManager`, `AuthManager`, `HistoryStorageBackend` traits — never concretes. Even built-in
  functionality (core namespace, diagnostics) is wired through the *same public seam* a user would
  use (`builder.rs:43-48`), with a `without_node_managers()` escape hatch. This is textbook clean
  architecture.
- **Tiered extensibility.** Server node management offers three levels: implement full `NodeManager`,
  implement the smaller `InMemoryNodeManagerImpl`, or just register read/write/method callbacks
  (`SimpleNodeManager`). Client services likewise offer raw typed `UARequest` builders *and*
  convenience methods on `Session`.
- **The priority-ordered `TypeLoader` registry + `DynEncodable`** (`types/src/type_loader/`,
  `extension_object.rs`) is the architectural crown jewel: generated types, user static types,
  runtime-discovered dynamic types, and a raw fallback coexist and are tried in priority order through
  one uniform encoding model. This is how a protocol library should handle extensible wire types.
- **Sharp transport ↔ business-logic boundary.** On both client and server, "bytes/framing/crypto"
  (transport + secure channel) is cleanly separated from "services/business logic." The server
  boundary at `SessionController::process_request` and the client `Connector`/`Transport` traits are
  real seams, not leaks.
- **Explicit, total state machines** for the client connection lifecycle (`event_loop.rs` —
  `Connected`/`Connecting`/`Disconnected` over `try_unfold`, three layered loops, documented
  cancellation-safety contract, lazy secure-channel renewal with concurrency coalescing).
- **Security-conscious encoding `Context`** carrying `DecodingOptions` + `DepthGauge` (size/recursion
  limits threaded uniformly rather than as global state).
- **Reproducible, CI-verified codegen** (`ci_verify_clean_codegen.yml` re-runs generation + fmt and
  fails on any diff) and consistent `tracing` observability with sensitive-data masking helpers
  (`core/src/logging/mod.rs`).

---

## 3. Recommendations

Prioritized. Severity reflects architectural impact, not urgency.

### R1 — Fix the codegen emission layer (High value, low risk)
The runtime type architecture is excellent; the *generator* that emits it has two issues, both in
`async-opcua-codegen/src/derives.rs`:

- **R1a — Codegen hand-writes binary `encode`/`decode`/`byte_len` impls** field-by-field
  (`struct_impls`), even though `async-opcua-macros` already provides `#[derive(BinaryEncodable,
  BinaryDecodable)]` — which codegen *does* use for JSON/XML. This is a self-inconsistency: two code
  paths implementing identical logic that must stay byte-for-byte aligned, and it bloats the generated
  output by thousands of lines. **→ Emit `#[derive(BinaryEncodable, BinaryDecodable)]` like the other
  formats.**
- **R1b — 305 redundant `unsafe impl Send`/`unsafe impl Sync`** (`send_sync_impls`, 610 unsafe impls).
  Every generated struct is plain owned data and would auto-derive both traits. These add `unsafe`
  surface for zero benefit and *defeat* the compiler's auto-trait safety check: a future field that is
  legitimately `!Send` would be force-marked `Send` and compile anyway. (They were reportedly removed
  once in 2019 and reintroduced.) **→ Delete `send_sync_impls`; rely on auto-derivation.** If a marker
  is ever genuinely needed, use a compile-time `assert_send` const rather than `unsafe impl`.

Landing R1a+R1b removes a large fraction of the 88k generated LOC and eliminates *all* `unsafe` in the
data types, with no behavioral change. This is the single highest-leverage cleanup in the workspace.
(Also flagged from a soundness angle in the code review as L1.)

### R2 — Preserve error context across the `Error → StatusCode` boundary (Medium)
The encoding layer has a rich `opcua_types::Error` (status + `request_id` + `request_handle` +
`Box<dyn Error>` context), and generated decoders diligently attach `with_request_handle(...)`. But
public client/server service APIs frequently collapse to `Result<_, StatusCode>`, and
`From<Error> for StatusCode` **discards** the request id/handle/context (only logs the message).
Debugging context is lost exactly where users consume it.
**→ Return `Error` (not bare `StatusCode`) at public service boundaries where practical; at minimum,
emit structured fields (`request_handle`, `request_id`) in the `From` impl's log.** Secondary:
migrate the hand-rolled server `SessionError` and the near-empty crypto error structs to `thiserror`
for consistency and better diagnostics.

### R3 — Segregate the `NodeManager` interface (Medium)
`NodeManager` (`node_manager/mod.rs:288`) is one ~30-method trait covering read, write, every history
variant, browse, query, call, add/delete nodes/references, and monitored-item lifecycle — an ISP
violation. It's mitigated by default impls returning `BadServiceUnsupported` (so implementers override
only what they need), but it raises the cost of understanding, implementing, and *mocking* the trait.
**→ Split into capability traits (`AttributeProvider`, `HistoryProvider`, `MethodProvider`,
`ViewProvider`, `NodeMutator`, `MonitoredItemProvider`) composed by a supertrait, or — if the
default-impl pattern is the deliberate substitute — document that explicitly.** This is the main
testability friction in the server.

### R4 — Add resource-limit seams on the server request path (Medium — also a security item)
The per-connection in-flight request queue (`controller.rs:87`, a `FuturesUnordered` of spawned tasks)
is unbounded, and there's no per-connection/per-IP concurrency cap. Architecturally this is a missing
**bulkhead**. **→ Introduce a per-connection concurrency semaphore with transport-level backpressure,
and surface the limit as config.** (Detailed as a DoS finding in the security docs; called out here
because the *seam* belongs in the architecture.)

### R5 — Realize the transport abstraction: ship a WebSocket connector (Medium)
The client transport seam (`Connector`/`Transport` + `StreamConnector<R,W>` over any
`AsyncRead+AsyncWrite`) is genuinely pluggable, but only `opc.tcp` ships in the client; WebSocket
exists only in pubsub. The abstraction's main payoff (alternate transports) is therefore latent.
**→ Ship an optional `websocket` feature with a `WebSocketConnector` built on `StreamConnector` +
`tokio-tungstenite`, mirroring `TcpConnector`.** This both serves a commonly requested transport and
validates the abstraction. (Note: bring it in on a maintained rustls 0.23 stack — see the security
audit's EOL-TLS finding D2 about the pubsub `rumqttc`/rustls-0.21 path.)

### R6 — Observability: add an exporter and overload counters (Medium)
Per-server `ServerMetrics` (`server/src/metrics.rs`) is well-isolated (per-`ServerInfo` atomics), but
(a) there's **no exporter** — every consumer hand-rolls Prometheus/OTel, and (b) the key *overload*
signals aren't counted: active session count, TCP connection count, queue-overflow events,
subscription-evaluation latency. **→ Add an optional `metrics`/`prometheus` feature exposing an
exporter trait, and add the missing counters at register/accept/enqueue sites.** Optionally provide a
`tracing-subscriber` helper for samples (the library itself correctly does not init a subscriber).

### R7 — Packaging cleanups (Low–Medium)
- **R7a — Make `legacy-crypto` non-default.** It's compiled in by default in `async-opcua-crypto`
  (`default = ["legacy-crypto"]`); it is runtime-gated off (good defense-in-depth), but consumers
  can't *drop* the deprecated SHA-1/Basic128Rsa15 code without `default-features = false`, and the
  client crate exposes no `legacy-crypto` feature to forward at all. **→ Flip to `default = []`, have
  the umbrella opt in, add a `legacy-crypto` feature to the client crate, and add a CI build without
  it.** (Also security M12.)
- **R7b — Merge the two tiny crates into the server.** `async-opcua-safety` (~314 LOC) and
  `async-opcua-history-sqlite` (~517 LOC, used only by server/tests) don't justify separate crates.
  **→ Fold them into `async-opcua-server` as optional modules/features** (`server/safety`,
  `server/history` with `rusqlite` optional). Keep `pubsub`, `codegen`, `xml`, `nodes`, `macros`,
  `core-namespace` separate — those splits are well-motivated.
- **R7c — Don't force `nodes/xml` unconditionally** from the server; track it with the server `xml`
  feature so JSON-only consumers don't pull XML.

### R8 — Lower-priority structural polish (Low)
- **`ServerInfo` is trending toward a god-object** (`info.rs:46`) — it's a coherent read-mostly
  "server state" bag, but the identity-token decrypt/JWT-validation *behavior* is mislocated on it.
  **→ Move that logic into the `negotiate`/auth modules; keep `ServerInfo` a state container.**
- **Generated code in diffs.** Keeping ~88k LOC of generated output checked in is the right call for a
  published library (consumers build without codegen deps; output is auditable), but **→ mark
  `src/generated/**` as `linguist-generated` in `.gitattributes` and add CODEOWNERS** so PR diffs
  collapse it. The load-bearing `mod opcua { use crate as types; }` indirection (which lets the same
  generated code compile inside the crate *and* in external consumers running their own codegen)
  should get a one-line rationale comment in the header template so it isn't "simplified" away.
- **Document hard tokio coupling.** The public extension traits are runtime-agnostic, but
  runtime/transport/session internals are baked to tokio with no executor seam. For an industrial
  protocol stack this is defensible — **→ just document tokio as a hard requirement** rather than
  attempting abstraction.

---

## 4. Suggested ADRs to capture

A handful of decisions are load-bearing and undocumented; recording them as short ADRs would help
future maintainers:

1. **Checked-in generated code** — why generation is committed rather than run in `build.rs`, and the
   `ci_verify_clean_codegen` contract that keeps it honest.
2. **Node-manager fan-out + `owns_node` namespace partitioning** — the composition model and its
   concurrency implications (the `Arc<RwLock<AddressSpace>>` contention envelope for the in-memory
   backend; guidance to shard via custom node managers for write-heavy workloads).
3. **Umbrella-crate facade + lockstep versioning** — the trade-off (single-dep ergonomics vs. no
   independent sub-crate patch releases); a path to letting the stable `types` crate version
   independently post-1.0.
4. **tokio as a hard dependency** — scope of coupling and what would need an executor seam if runtime
   independence were ever required.

---

## 5. Priority-ordered action list

| # | Recommendation | Severity | Effort |
|---|----------------|----------|--------|
| R1 | Codegen: derive binary impls; delete redundant `unsafe` Send/Sync | High | Low |
| R2 | Preserve error context across `Error → StatusCode` | Medium | Medium |
| R4 | Server request-path bulkhead (concurrency cap + backpressure) | Medium | Medium |
| R3 | Segregate `NodeManager` into capability traits | Medium | Medium–High |
| R6 | Metrics exporter + overload counters | Medium | Medium |
| R5 | Ship a WebSocket connector | Medium | Medium |
| R7 | Packaging: non-default legacy-crypto; merge tiny crates; xml feature | Low–Medium | Low |
| R8 | Polish: relocate ServerInfo auth logic; diff/ADR hygiene; doc tokio | Low | Low |

The architecture is sound; this is a refinement backlog, not a remediation plan. **R1 is the
standout** — high payoff, near-zero behavioral risk, and it removes the workspace's only `unsafe` in
the data types while shrinking the generated surface that dominates the repo.
