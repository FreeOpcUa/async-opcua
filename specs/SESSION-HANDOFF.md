# Session handoff — conformance → interop → footprint → hot-path locks (2026-06-27 → 2026-07-01)

**State:** `master` clean, all CI green, all feature branches pruned. Work is on the fork
`occamsshavingkit/async-opcua` (squash-merged via `gh`); never push upstream FreeOpcUa.

**Driving principle:** async-opcua is a *complete reference implementation* — build the spec
surface; do not defer spec-defined behavior on YAGNI/ponytail grounds (user direction, see memory
`completeness-over-yagni`). Backlog lives in [`specs/completeness-backlog.md`](completeness-backlog.md).

The spec-*completeness* push (RBAC, HistoryUpdate, A&C, aggregates, mDNS — all done, see below) is
essentially finished; this window pivoted to **conformance hardening → interop → deployment
footprint → hot-path performance**, i.e. production-readiness of the surface already built.

## Delivered most recently

### Instance-scoped server state — **COMPLETE** (feature 049, PR pending)
Relocated 3 process-global mutable statics in `async-opcua-server` onto `ServerInfo` so multiple
`Server` instances can run in one process without cross-instance collision (from the 2026-07-01 lock
audit). **Correctness (P1):** FOTA cleanup registry + the localized-text variant side-table — both
NodeId-keyed → genuinely collided across servers. **Hygiene (P2):** the session-id counter + locale map
(no collision, but global coupling). Owner = `ServerInfo` (reached via `RequestContext.info` +
`SessionManager.info`). Public FOTA cleanup + `write_node_value` signatures gained an `&ServerInfo` param
(intentional 0.x breaking change). Deliberately-global statics documented (P3). Requests already run
concurrently (spawned tokio tasks) — this is NOT a concurrency change. Per-instance isolation tests +
await-holding lints clean.

### Node-management validation hardening — **COMPLETE** (feature 048, PR pending)
Closed the reconciled node-management validation cluster on the opt-in writable address space
(`clients_can_modify_address_space`, default OFF): P4-NODEMGMT-01 (targetNodeClass match + hierarchical
HasProperty/HasSubtype rules), P3-03 (abstract type-metadata-only typeDefinition — required a new
`TypeTree::is_abstract`/IsAbstract field threaded through `add_type_node`), P3-06 (HasTypeDefinition
[1..1]), P3-05 (symmetric+InverseName node invariant — already enforced server-side, now a reusable
`ReferenceType` invariant), P3-07 (VariableType subtype DataType/ValueRank refinement). 6 user stories,
TDD red-first, all spec-cited (MCP-verified §s). Standard-nodeset load + full server/nodes/integration
suites green; clippy clean.

### Facade exposure of PubSub + SQLite history — **COMPLETE** (feature 047, PR pending)
Opt-in, default-OFF `pubsub` / `history` umbrella features re-export `async-opcua-pubsub` /
`async-opcua-history-sqlite` as `opcua::pubsub` / `opcua::history`, mirroring client/server. Fixes a
facade-completeness gap (the crates were dev-deps only, unreachable through the facade) surfaced when
verifying the mis-flagged "native" backlog item — `cargo tree -e no-dev` proved they were NOT forced on
users. Footprint invariant preserved (default build pulls zero pubsub/history/sqlite/AMQP/MQTT/WS deps).
Packaging only — no PubSub/history behavior change. Committed per-story (US1 pubsub, US2 history), PR
kept unsquashed to preserve the story commits (new commit convention, 2026-07-01).

## Earlier this window (PRs #233–#244, all merged + CI-green)

### Hot-path lock removal — **COMPLETE** (features 044/045/046, PRs #242–#244)
A rigorously measurement-gated three-step performance effort. See memory `feature-044-046-hot-path-locks`.
- **044 (`240-hot-path-lock-audit`, PR #242)** — audit + lock-*scope* narrowing: moved user callbacks,
  `SyncSampler` work, and subscription fanout OUTSIDE guards; cached the `OPCUA_TRACE_LOCKS` env read;
  restored a CreateSession nonce validation that a narrowing had dropped. Audit doc:
  `docs/HOT_PATH_LOCK_AUDIT_2026-06-30.md`.
- **045 (`045-controlled-hot-path-bench`, PR #243)** — controlled localhost Read/Write benchmark
  harness at `tools/opcua-localhost-bench/` to gate 046.
- **046 (`046-lock-removal-snapshots`, PR #244)** — actual lock *removal* with snapshots:
  - **TypeTreeSnapshot** (`info.rs`): `ServerInfo.type_tree_snapshot: ArcSwap<Option<TypeTreeSnapshot>>`.
    Hot readers (Browse/Query/Read/subscriptions) do a lock-free `load_full()` of an immutable
    `Arc<DefaultTypeTree>` instead of `trace_read_lock!(type_tree)`; writers publish a COMPLETE clone
    atomically; custom getters preserved via `TypeTreeForUser`/`TypeTreeForUserStatic` in
    `node_manager/context.rs`.
  - **Response-size limit** (`core/src/comms/buffer.rs`): deleted the process-wide
    `static Mutex<HashMap<…>>` global; moved to per-`SecureChannel` state. Same `maxResponseMessageSize`
    / `BadResponseTooLarge` behavior.
  - Also: CreateSession split/commit (`session/manager.rs`), subscription route snapshot,
    secure-channel renewal single-flight, sqlite history lock scaling, pubsub config snapshot.
  - Dep added: `arc-swap`. Gates: median throughput drop ≤5% + clippy
    `-W await_holding_lock -W await_holding_refcell_ref`. Higher-risk locks (SecureChannel renewal
    mutex, cert stores, session/notification-ring locks) DELIBERATELY LEFT pending their own
    measurement + conformance proof.

### Minimal deployment footprint — **COMPLETE** (feature 040, PR #238)
Embedded/constrained build path. The perf audit found the generated core namespace is the largest
binary-size bucket, so a **`base-server`** facade path now builds a server WITHOUT it through the
umbrella crate. New minimal sample (umbrella crate, no default features) + CI footprint job that builds
the embedded profile and reports binary size. Tradeoff documented: smaller but not standards-complete
alone; `server` feature still pulls `generated-address-space` by default. See memory
`feature-038-040-conformance-footprint` and `todo-embedded-profiles`.

### Conformance + interop (features 037/038/039, PRs #233/#234/#235/#237)
- **037 (PR #233)** — Part 14 PubSub **subscriber runtime**: `SubscriberRuntime` in
  `async-opcua-pubsub/src/subscriber.rs` receives/decodes/dispatches/applies UADP NetworkMessages
  (`process_datagram`, `DataSetReaderStatus`, field-target application). Prior PubSub was
  publisher/writer + reader *config* only. See memory `feature-037-part14-subscriber`.
- **038 (PR #234)** — StatusCode conformance test matrix + external status-code interop (PR #235).
- **039 (PR #237)** — external interop target checks.
- `da395291b` — "Remediate OPC UA audit findings" (round of audit fixes ahead of the lock work).

## Delivered earlier this window (PRs #196–#217, all merged + CI-green)
- **RBAC / Authorization — COMPLETE** (feature 031, 106/106; PRs →#196). Part 3 §4.8–4.9 / §8.55–8.56
  + Part 18 role model; module `async-opcua-server/src/rbac/`. **Enforcement is OPT-IN** behind
  `enforce_role_based_access` (default off) because the standard core nodeset ships RolePermissions on
  the Server hierarchy that would break default access. See memory `feature-031-rbac-complete`.
- **Historical Access write — COMPLETE** (feature 032, 77/77; PRs #198–#204). Part 11 HistoryUpdate on
  sqlite + new `InMemoryDataHistory` with cross-backend parity. Memory `feature-032-historyupdate-write`.
- **A&C source monitoring — COMPLETE** (feature 033, PRs #206–#209); A&C subsystem now complete.
- **Part 13 aggregates — COMPLETE set** (features 034/035, PRs #210–#215): non-numeric aggregates +
  AnnotationCount; completes the standard aggregate set. Memory `feature-035-annotation-count`.
- **mDNS discovery — COMPLETE** (feature 036, PRs #216/#217): Part 12 LDS-ME multicast
  FindServersOnNetwork behind off-by-default `discovery-mdns`. Memory `feature-036-mdns-discovery`.

## Conventions / gotchas (entry points for continuation)
- **codex sandbox cannot bind sockets** — always run `cargo test -p async-opcua-server` (ALL binaries,
  not just `--lib`; e.g. `event_filter_tests` caught regressions) and the `async-opcua` integration
  suite yourself. codex tasks must cite the OPC UA Part/§ so its reference MCP can look it up.
- **codegen gate:** `verify-clean-codegen` regenerates 3 configs (`code_gen_config.yml`,
  `samples/custom-codegen/`, `async-opcua-fx/`); if you touch `async-opcua-codegen`, regenerate +
  `cargo fmt --all` locally and commit the generated diff.
- **Local clippy** misses the no-default-features leg — run
  `cargo clippy --no-default-features -p async-opcua -p async-opcua-types -p async-opcua-server
  --all-targets` in addition to `--workspace --all-targets --all-features`. For lock work also enable
  `-W clippy::await_holding_lock -W clippy::await_holding_refcell_ref`.
- **RSA Marvin (RUSTSEC-2023-0071):** left as-is — default build uses constant-time aws-lc-rs;
  only the pure-Rust `--no-default-features` path uses the vulnerable decrypt (documented accepted
  trade-off). No action.

## Next
Open backlog in `specs/completeness-backlog.md`, `specs/conformance-gap-backlog.md`, and
`specs/complexity-cuts-backlog.md`. Completeness surface is largely built. Remaining performance
levers: higher-risk lock boundaries are measurement-gated (see 046 — SecureChannel renewal, cert
stores, notification rings still locked pending proof). Pick the next backlog facet or perf slice.
