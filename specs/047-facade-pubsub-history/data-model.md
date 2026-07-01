# Phase 1 Data Model: Facade Exposure of PubSub and SQLite History

This feature's "data" is Cargo configuration, not runtime state. The entities below are the
configuration objects introduced or modified, with their fields and invariants.

## Entity: Facade Feature

A user-facing feature on the `async-opcua` umbrella crate that toggles a subsystem.

| Instance | Enables dependency | `dep:` target | In `default`? |
|----------|--------------------|---------------|---------------|
| `pubsub` | `async-opcua-pubsub` (optional) | `dep:async-opcua-pubsub` | **No** |
| `history` | `async-opcua-history-sqlite` (optional) | `dep:async-opcua-history-sqlite` | **No** |

**Invariants**:
- Neither is a member of `default` (FR-003).
- Enabling the feature is the *only* way to pull the dependency (FR-004).
- Feature name == re-export module name for discoverability.

## Entity: Optional Subsystem Dependency

A workspace member crate, pulled only when its facade feature is enabled.

| Field | `async-opcua-pubsub` | `async-opcua-history-sqlite` |
|-------|----------------------|------------------------------|
| Manifest section | `[dependencies]` (moved from `[dev-dependencies]`) | `[dependencies]` (moved from `[dev-dependencies]`) |
| `optional` | `true` | `true` |
| lib name (extern crate) | `opcua_pubsub` | `opcua_history_sqlite` |
| own features | `tsn`, `legacy-crypto` | (none) |
| transitively pulls | `async-opcua-server` (+ generated-address-space), `-nodes`, `-crypto`, `-core`, `-types` | `async-opcua-server`, `-core`, `-types` |

**Invariants**:
- Absent from any build that does not enable the corresponding feature (FR-004, SC-003).
- Version pinned to the workspace version (`0.19.0`), matching the other facade deps.

## Entity: Re-export Namespace

The umbrella-crate path exposing the subsystem's public API.

| Feature | `lib.rs` line |
|---------|---------------|
| `pubsub` | `#[cfg(feature = "pubsub")] #[doc(inline)] pub use opcua_pubsub as pubsub;` |
| `history` | `#[cfg(feature = "history")] #[doc(inline)] pub use opcua_history_sqlite as history;` |

**Invariants**:
- Whole-crate re-export (same public API as the sub-crate) — not a curated subset (FR-005).
- Gated by `#[cfg(feature)]` so it never appears in a non-opted-in build (FR-004).
- `#[doc(inline)]` for docs.rs consistency with the other re-exports.

## Entity: Feature-Forwarding Set

Umbrella features that must propagate into the newly-exposed subsystems.

| Umbrella feature | Added forwarding arm | Reason |
|------------------|----------------------|--------|
| `legacy-crypto` | `async-opcua-pubsub?/legacy-crypto` | pubsub defines `legacy-crypto`; keep policy consistent |
| `aws-lc-rs` | *(none — via unification)* | sub-crates have no `aws-lc-rs` feature; shared `async-opcua-crypto` already gets it |
| `ecc` | *(none — via unification)* | sub-crates have no `ecc` feature |
| `history` subsystem | *(none)* | history-sqlite exposes no features |

**Invariants**:
- Forward only features that exist on the target crate (a nonexistent `?/feature` arm is a hard Cargo
  error).
- The default constant-time crypto backend (`aws-lc-rs`) must reach both subsystems in a default build
  (SC-005), satisfied by unification.

## Entity: Self-Test Wiring

The umbrella crate's own test build configuration.

| Field | Value |
|-------|-------|
| Mechanism | `[dev-dependencies] async-opcua = { path = ".", features = [… , "pubsub", "history"] }` |
| Removed | standalone `[dev-dependencies] async-opcua-pubsub` / `async-opcua-history-sqlite` |
| Consumers | `tests/integration/{pubsub,fx_spike}.rs` (`opcua_pubsub`), `tests/integration/hda.rs` (`opcua_history_sqlite`) |

**Invariants**:
- The three integration test files continue to compile and pass (FR-008), preferably unchanged.
- Single dependency surface: the subsystems are reached via the feature, not a parallel dev-dep.

## Footprint Invariant (cross-cutting)

`cargo tree -p async-opcua -e no-dev` for a **default** build MUST contain none of:
`async-opcua-pubsub`, `async-opcua-history-sqlite`, `libsqlite3-sys`/`rusqlite`, `lapin`, `rumqtt*`,
AMQP/MQTT/WebSocket transport crates. (SC-003.)
