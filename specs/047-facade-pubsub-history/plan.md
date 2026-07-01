# Implementation Plan: Facade Exposure of PubSub and SQLite History

**Branch**: `047-facade-pubsub-history` | **Date**: 2026-07-01 | **Spec**: [spec.md](./spec.md)
**Input**: Feature specification from `/specs/047-facade-pubsub-history/spec.md`

## Summary

Expose `async-opcua-pubsub` and `async-opcua-history-sqlite` through the `async-opcua` umbrella crate as
**optional, default-OFF** dependencies with re-exports, mirroring how `client`/`server`/`nodes`/`xml`
are already exposed. Today these two crates are **dev-dependencies only** of the umbrella crate, so a
consumer cannot reach PubSub or SQLite history through the facade — they must depend on the internal
sub-crates directly. This is pure Cargo packaging + a two-line `lib.rs` re-export: no PubSub, history,
or crypto behavior changes. The footprint guarantee from feature 040 is preserved because both features
stay out of `default`.

## Technical Context

**Language/Version**: Rust 1.75+ workspace
**Primary Dependencies**: Existing workspace crates only — `async-opcua-pubsub` (lib `opcua_pubsub`) and
`async-opcua-history-sqlite` (lib `opcua_history_sqlite`). No new external dependency.
**Storage**: N/A (SQLite backend already lives in the history sub-crate; unchanged)
**Testing**: `cargo test` / `cargo build` across feature combinations; `cargo tree -e no-dev` footprint
assertion; `cargo clippy`; the umbrella crate's existing `tests/integration/{pubsub,fx_spike,hda}.rs`
must stay green.
**Target Platform**: Linux CI and developer environments
**Project Type**: Rust workspace — umbrella/facade crate re-exporting member crates
**Performance Goals**: None (packaging change; zero runtime effect)
**Constraints**: `default` feature set MUST NOT gain `pubsub`/`history`; existing feature combinations
MUST build unchanged; crypto-backend/legacy/ecc feature forwarding must stay consistent with the
current facade; no re-export may leak into a build that didn't opt in.
**Scale/Scope**: One `Cargo.toml` (`async-opcua/Cargo.toml`), one `lib.rs` (2 re-export lines), one
docs touch-up. No sub-crate is modified.

## OPC UA Standard Grounding

Not applicable in the usual sense — this feature touches no wire format, decode path, or cryptographic
operation. The relevant "contract" is Cargo's feature/dependency model and the existing facade
convention, captured in [contracts/facade-contract.md](./contracts/facade-contract.md). The subsystems
being exposed already implement their respective specs (Part 14 PubSub; Part 11 Historical Access
storage) and are unchanged.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

- **I. Correctness Over Completion**: PASS. "Done" requires every previously-supported feature
  combination to build, the footprint invariant to hold under `cargo tree -e no-dev`, and the umbrella
  crate's own PubSub/history integration tests to pass. These are the acceptance gates, not "it
  compiles."
- **II. Do It Right Once**: PASS. The change reuses the exact existing facade mechanism
  (`optional = true` dep + `dep:`/`?`-guarded feature + `#[cfg(feature)] pub use … as …`). No new
  abstraction, no bespoke wiring.
- **III. Individual Task Discipline**: PASS. Work decomposes into independently verifiable tasks: (a)
  PubSub facade dep+feature+re-export, (b) history facade dep+feature+re-export, (c) crypto/legacy
  feature forwarding, (d) self-test wiring, (e) footprint assertion, (f) docs. One at a time.
- **IV. Security Is Paramount**: PASS. No decode/parse/crypto/transport code is added or altered. The
  exposed crates are already in-tree workspace members (no new external advisory surface). Feature
  forwarding preserves fail-closed crypto defaults: the default build keeps the constant-time
  `aws-lc-rs` backend, and enabling a subsystem does not silently downgrade or disable any protection.
  Both features stay opt-in, so no attack surface is added to default builds.
- **V. Leave It Better Than You Found It**: PASS. Corrects a real facade-completeness inconsistency,
  fixes the mis-flagged "native" backlog entry (done), and documents the opt-in path. No debris.

**Result: PASS, no violations.** Complexity Tracking table below is empty by design.

## Project Structure

### Documentation (this feature)

```text
specs/047-facade-pubsub-history/
├── spec.md
├── plan.md              # this file
├── research.md          # Phase 0 — Cargo facade mechanics, forwarding, test-visibility decision
├── data-model.md        # Phase 1 — features/deps/re-exports as config entities
├── quickstart.md        # Phase 1 — consumer usage + maintainer verification commands
├── contracts/
│   └── facade-contract.md   # feature names, re-export paths, forwarding table, footprint invariant
├── checklists/
│   └── requirements.md
└── tasks.md             # Phase 2 (/speckit-tasks) — NOT created here
```

### Source Code (repository root)

```text
async-opcua/
├── Cargo.toml           # move pubsub + history-sqlite from [dev-dependencies] to optional
│                        #   [dependencies]; add `pubsub` + `history` features (NOT in default);
│                        #   forward `legacy-crypto` to async-opcua-pubsub?; enable pubsub+history
│                        #   in the self-referential [dev-dependencies] async-opcua feature list
├── src/
│   └── lib.rs           # + #[cfg(feature = "pubsub")]  pub use opcua_pubsub as pubsub;
│                        # + #[cfg(feature = "history")] pub use opcua_history_sqlite as history;
└── tests/integration/
    ├── pubsub.rs        # unchanged — `use opcua_pubsub::…` stays valid (optional dep enabled in tests)
    ├── fx_spike.rs      # unchanged
    └── hda.rs           # unchanged — `use opcua_history_sqlite::…`
```

Docs: `docs/` setup/footprint guidance (the feature-040 minimal-footprint doc and/or `README`) gains a
note on the two new opt-in features.

**Structure Decision**: All changes live in the umbrella crate `async-opcua`. No member crate is
touched. The re-export names (`opcua::pubsub`, `opcua::history`) follow the established
`pub use opcua_<crate> as <name>` convention already used for `core`, `crypto`, `types`, `client`,
`server`, `nodes`, `xml`, `core_namespace`.

## Phase 0 Research Summary

See [research.md](./research.md). Key decisions:

- **Mechanism**: `optional = true` dependency + a feature that enables it via `dep:`, gated re-export in
  `lib.rs`. Identical to the existing `client`/`server` pattern.
- **Feature forwarding**: only `legacy-crypto` needs an added `async-opcua-pubsub?/legacy-crypto` arm
  (pubsub defines `legacy-crypto`; history-sqlite defines no features). `aws-lc-rs`/`ecc` reach the
  subsystems' transitive `async-opcua-crypto` via Cargo feature unification — the umbrella already
  enables `async-opcua-crypto/aws-lc-rs` directly, so no per-subsystem arm is required (verified in
  research; confirmed by build in implement/verify).
- **Test visibility**: the umbrella's integration tests import the extern crates `opcua_pubsub` /
  `opcua_history_sqlite` directly. Keeping them working means enabling `pubsub`+`history` in the
  self-referential `[dev-dependencies] async-opcua = { features = [...] }` list so the optional deps are
  present for the test build. This keeps the crates on a single dependency surface (no separate
  dev-dep). Fallback if extern names aren't visible to the test target: switch the three test files to
  the `opcua::pubsub` / `opcua::history` re-export paths.
- **Default set untouched**: `default = ["aws-lc-rs"]` — neither new feature is added, preserving the
  feature-040 footprint invariant.

## Phase 1 Design Summary

- [data-model.md](./data-model.md) models the config entities: the two `Facade Feature`s, their
  `Optional Subsystem Dependency`, the `Re-export Namespace`, and the `Feature-Forwarding Set`, plus
  the invariants each must satisfy.
- [contracts/facade-contract.md](./contracts/facade-contract.md) is the authoritative table of feature
  names → enabled dep → re-export path → forwarding arms, and the footprint invariant with its exact
  verification command.
- [quickstart.md](./quickstart.md) gives the consumer snippet (`async-opcua = { features = ["pubsub"] }`
  → `use opcua::pubsub::…`) and the maintainer verification matrix.

**Post-Design Constitution Re-check: PASS.** The design adds no code paths, only Cargo config and two
re-export lines; all five principles remain satisfied with no new justifications.

## Complexity Tracking

| Violation | Why Needed | Simpler Alternative Rejected Because |
|-----------|------------|-------------------------------------|
| None | N/A | N/A |
