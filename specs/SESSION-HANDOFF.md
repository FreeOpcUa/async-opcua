# Session handoff — RBAC + HistoryUpdate complete (2026-06-26 → 2026-06-27)

**State:** `master` clean, all CI green, all feature branches pruned. Work is on the fork
`occamsshavingkit/async-opcua` (squash-merged via `gh`); never push upstream FreeOpcUa.

**Driving principle:** async-opcua is a *complete reference implementation* — build the spec
surface; do not defer spec-defined behavior on YAGNI/ponytail grounds (user direction, see memory
`completeness-over-yagni`). Backlog lives in [`specs/completeness-backlog.md`](completeness-backlog.md).

## Delivered most recently (PRs #198–#204, all merged + CI-green)

### Historical Access write — **COMPLETE** (feature `specs/032-historyupdate-write/`, 77/77 tasks)
Full OPC UA Part 11 HistoryUpdate write service (§6.8–6.9 / Part 4 §11.7), built as a speckit feature
(specify→plan→tasks→**analyze looped 3×**→implement; codex one cited task/dispatch, Claude wrote the
independent cross-backend parity tests). The protocol/dispatch/RBAC layer already existed; this filled
in the STORAGE on TWO backends — the sqlite reference backend and a NEW `InMemoryDataHistory`:
- **US1–US3:** UpdateData (Insert/Replace/Update/Remove), DeleteRawModified, DeleteAtTime.
- **US4:** modified-history read (`read_raw_modified(is_read_modified=true)` returns superseded values
  + ModificationInfo; Part 11 §6.5).
- **US5–US6:** annotation write (UpdateStructureData) + event write (UpdateEvent/DeleteEvent by EventId).
- **US7:** e2e server+client wiring; client gained `Session::history_read_modified`.

The `HistoryStorageBackend` trait was extended (default-Unsupported → backwards compat);
`set_history_backend` wires a backend, no backend ⇒ `Bad_HistoryOperationUnsupported`. The analyze
loop + test-first discipline caught **5 real bugs** (the `is_read_modified` selector never threaded to
backends, `modification_infos` hardcoded `None`, `UpdateData(Remove)` not recording a Delete entry,
the original ModificationInfo return-type gap). See memory `feature-032-historyupdate-write`.

## Delivered earlier this session window (PRs #179–#197, all merged + CI-green)

### RBAC / Authorization — **COMPLETE** (feature `specs/031-rbac-authorization/`, 106/106 tasks)
Full OPC UA Part 3 §4.8–4.9 / §8.55–8.56 + Part 18 role model, built as a speckit feature
(specify→plan→tasks→analyze→implement; codex implements one cited task per dispatch, Claude writes
independent tests). Module: `async-opcua-server/src/rbac/`.
- **US1–US7** — node-level `RolePermissions`/`AccessRestrictions` attributes (24/25/26); identity→role
  resolution + `RoleSet` info-model (8 well-known roles); enforcement across Read/Write/Browse/Call/
  History/NodeManagement/event-delivery; per-namespace defaults; runtime `RoleSet`/`RoleType`
  management methods gated to `SecurityAdmin`.
- **US8** — config/builder surface: `ServerBuilder::identity_mapping_rule` / `enforce_role_based_access`
  / `with_secure_role_preset` / `default_role_permissions` / `default_access_restrictions`;
  `ServerUserToken::with_roles`; `rbac/preset.rs` Part 3 §4.9.2 suggested permissions.

**Key decision — enforcement is OPT-IN** behind `enforce_role_based_access` (default off). Off =
permissive exactly as before (attributes readable, never deny → SC-007 holds). On = configured nodes
enforced, unconfigured nodes fail closed. This was forced by **T020**: the codegen node generator
(`async-opcua-codegen/src/nodeset/gen.rs`) now preserves node-level RolePermissions/AccessRestrictions
from the nodeset, and the *standard core nodeset ships restrictions on the Server hierarchy* (Server
node 2253 grants Anonymous only `Browse|Call`). Enforcing those by default broke ~22 integration
tests; opt-in resolved it. Also found+fixed mid-feature: **T019** (reading the RolePermissions
attribute was not gated by `ReadRolePermissions`).

### Other completeness work (pre-RBAC, this session window)
- **Audit hierarchy (Part 4 §A) — COMPLETE:** session/channel/cert/cancel audit events (#182–#186);
  flat `ServerAuditEvent` pattern.
- **PubSub writable config:** connection/group-level (#180) + PublishedDataSet CRUD (#181) Methods.
- **Aggregate subscriptions:** `AggregateFilter` on MonitoredItems (#187/#188), buffer + per-interval
  flush, reuses the Part-13 engine; `ModifyMonitoredItems` restarts the window.

## Conventions / gotchas (entry points for continuation)
- **codex sandbox cannot bind sockets** — always run `cargo test -p async-opcua-server` (ALL binaries,
  not just `--lib`; e.g. `event_filter_tests` caught regressions) and the `async-opcua` integration
  suite yourself. codex tasks must cite the OPC UA Part/§ so its reference MCP can look it up.
- **codegen gate:** `verify-clean-codegen` regenerates 3 configs (`code_gen_config.yml`,
  `samples/custom-codegen/`, `async-opcua-fx/`); if you touch `async-opcua-codegen`, regenerate +
  `cargo fmt --all` locally and commit the generated diff.
- **Local clippy** misses the no-default-features leg — run
  `cargo clippy --no-default-features -p async-opcua -p async-opcua-types -p async-opcua-server
  --all-targets` in addition to `--workspace --all-targets --all-features`.
- **RSA Marvin (RUSTSEC-2023-0071):** left as-is — default build uses constant-time aws-lc-rs;
  only the pure-Rust `--no-default-features` path uses the vulnerable decrypt (documented accepted
  trade-off). No action.

## Next
Open backlog in `specs/completeness-backlog.md`. RBAC, FX, A&C, audit, aggregates, and PubSub
writable-config are all complete. Pick the next major spec area or remaining backlog facets.
