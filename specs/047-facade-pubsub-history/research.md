# Phase 0 Research: Facade Exposure of PubSub and SQLite History

## R1 — Exposure mechanism

**Decision**: Move each sub-crate from `[dev-dependencies]` to `[dependencies]` with `optional = true`,
add a same-named feature that enables it, and add a `#[cfg(feature = "…")]` re-export in `lib.rs`.

**Rationale**: This is the exact mechanism the facade already uses for every other member crate. From
`async-opcua/src/lib.rs`:

```rust
#[cfg(feature = "client")]
#[doc(inline)]
pub use opcua_client as client;
#[cfg(any(feature = "server", feature = "base-server"))]
#[doc(inline)]
pub use opcua_server as server;
```

and in `Cargo.toml`, `client = ["async-opcua-client"]`, with `async-opcua-client = { …, optional = true }`.
Mirroring it (Principle II — Do It Right Once) gives consumers a consistent mental model and zero
bespoke wiring.

**Sub-crate lib names** (needed for the `pub use … as …`):
- `async-opcua-pubsub` → `[lib] name = "opcua_pubsub"`
- `async-opcua-history-sqlite` → `[lib] name = "opcua_history_sqlite"`

So: `pub use opcua_pubsub as pubsub;` and `pub use opcua_history_sqlite as history;`.

**Alternatives considered**:
- *Curated re-export* (hand-pick types into `opcua::pubsub`): rejected — FR-005 requires the same public
  API as the sub-crate; a whole-crate re-export is correct and lower-maintenance.
- *Add to `default`*: rejected — violates FR-003 and the feature-040 footprint invariant.

## R2 — Feature forwarding (crypto backend, legacy, ecc)

**Observed sub-crate feature surfaces**:
- `async-opcua-pubsub` `[features]`: `tsn`, `legacy-crypto` (→ core/crypto/server `legacy-crypto`). No
  `aws-lc-rs`, no `ecc`, no `default`.
- `async-opcua-history-sqlite`: **no `[features]` at all.**

Both depend transitively on `async-opcua-crypto` (pubsub with `default-features = false`; history via
`async-opcua-server`).

**Decision**:
- Add `"async-opcua-pubsub?/legacy-crypto"` to the umbrella `legacy-crypto` feature. (`?` = only when the
  optional pubsub dep is enabled — matches the existing `async-opcua-client?/…` style.)
- Do **not** add per-subsystem arms for `aws-lc-rs` or `ecc`: those features don't exist on the
  sub-crates. The crypto backend reaches the subsystems' shared `async-opcua-crypto` via Cargo feature
  unification — the umbrella's `aws-lc-rs` feature already enables `async-opcua-crypto/aws-lc-rs`
  globally, so the single crypto crate instance in the graph is built with the backend regardless of
  which member pulled it.
- No forwarding for `history` (the sub-crate exposes no features).

**Rationale**: Forward only the features that actually exist on the target; rely on unification for the
shared crypto crate exactly as the current build already does for the transitively-pulled server crate.

**Verification obligation** (deferred to implement/verify, not assumed here): build
`--features pubsub,history` (default `aws-lc-rs` on) and confirm the crypto backend is present and the
subsystems compile; build `--no-default-features --features pubsub,history,aws-lc-rs`-style combinations
per the quickstart matrix.

**Edge case (SC-005)**: `async-opcua = { features = ["pubsub"] }` with default features keeps
`aws-lc-rs`, so pubsub gets the constant-time backend via unification. `default-features = false` with
only `pubsub` yields no backend — identical to how `base-server` behaves today (consumer must choose a
backend); consistent facade behavior, not a regression.

## R3 — Keeping the umbrella crate's own tests green

**Finding**: `async-opcua/tests/integration/pubsub.rs` and `fx_spike.rs` do `use opcua_pubsub::…`;
`hda.rs` does `use opcua_history_sqlite::…`. They reference the **extern crate names**, made available
today by the two `[dev-dependencies]`.

**Decision**: Remove the standalone dev-dependencies and instead enable `pubsub` + `history` in the
existing self-referential dev-dependency
`async-opcua = { path = ".", features = ["all", "json", "xml", "legacy-crypto", "wss"] }`
(append `"pubsub", "history"`). When those features are on for the test build, the optional deps are
present and their extern crates (`opcua_pubsub`, `opcua_history_sqlite`) are nameable from the
integration-test target — so the three test files stay unchanged (Principle II/V: least churn, single
dependency surface).

**Rationale**: Avoids carrying the same crate as both a dev-dep and an optional dep (a confusing double
surface). The self-dev-dep feature-enable trick is already how this crate turns on `all`/`json`/`xml`
for its own tests.

**Fallback**: If the extern names turn out not to be visible to the integration-test target under this
arrangement, switch the three files to the re-export paths (`opcua::pubsub::…`, `opcua::history::…`).
This is a mechanical, low-risk edit and is the more "facade-pure" form anyway. The implement phase picks
whichever the compiler accepts; both satisfy FR-008.

## R4 — Footprint invariant

**Decision**: Assert the guarantee with `cargo tree -p async-opcua -e no-dev` and grep for
`pubsub|history|sqlite|lapin|rumqtt|amqp|mqtt|tungstenite` → must be empty for a default build. This is
the same command that disproved the "native" backlog claim, so it doubles as the regression guard for
SC-003.

**Rationale**: `-e no-dev` is the ground truth for what a downstream consumer compiles; it excludes the
dev-dependencies that made the original audit misread the manifest.

## Summary of decisions

| # | Decision |
|---|----------|
| R1 | `optional=true` deps + `pubsub`/`history` features + `#[cfg] pub use opcua_pubsub as pubsub;` / `… as history;` |
| R2 | Forward only `legacy-crypto → async-opcua-pubsub?/legacy-crypto`; crypto backend via unification; history has no features |
| R3 | Enable `pubsub`+`history` in the self dev-dep feature list; keep test files unchanged (fallback: use re-export paths) |
| R4 | `cargo tree -p async-opcua -e no-dev` grep is the footprint regression guard |

No NEEDS CLARIFICATION remain.
