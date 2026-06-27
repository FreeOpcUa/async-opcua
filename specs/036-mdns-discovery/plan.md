# Implementation Plan: mDNS multicast discovery (LDS-ME) for FindServersOnNetwork

**Branch**: `036-mdns-discovery` | **Date**: 2026-06-27 | **Spec**: [spec.md](spec.md)
**Input**: Feature specification from `specs/036-mdns-discovery/spec.md`

## Summary

Add the OPC UA Part 12 multicast extension (LDS-ME): behind a NEW off-by-default `discovery-mdns` cargo
feature, the server advertises itself as an `_opcua-tcp._tcp` DNS-SD service via mDNS (using the pure-Rust
`mdns-sd` crate), and `find_servers_on_network` (`async-opcua-server/src/info.rs:251`) merges
network-discovered servers (with capabilities from the advertised TXT records) into the existing
pull-based registered-server results — closing the `info.rs:255` "capability filter matches nothing"
gap. With the feature off, `mdns-sd` is absent and behavior is byte-identical to today.

## Technical Context

**Language/Version**: Rust (edition 2021), workspace MSRV
**Primary Dependencies**: NEW optional `mdns-sd` v0.20 (pure-Rust DNS-SD responder + querier, runtime-
agnostic, uses a `flume` channel — bridged to tokio via `recv_async`); only pulled under `discovery-mdns`.
No other new deps.
**Storage**: in-memory discovery cache on `ServerInfo` (feature-gated); reuses the existing
`registered_servers` store
**Testing**: `cargo test` — network-free unit tests for the Part-12 record format (TXT `path`/`caps`
encode/decode) + the `ServiceInfo → ServerOnNetwork` mapping + the merge/filter in
`find_servers_on_network`; a multicast-tolerant responder→querier integration test (skips if multicast
is unavailable)
**Target Platform**: Linux/any (library)
**Project Type**: Rust library/server (single workspace)
**Performance Goals**: No effect on the default/pure-Rust build; the mDNS tasks are idle background
listeners gated on the feature + opt-in config
**Constraints**: OFF-by-default; `--no-default-features` (mdns-sd absent) and `--all-features` (present)
both build+test; `cargo deny check advisories` stays green; the mDNS path parses untrusted multicast
data → no panic / bounded allocation / reject-malformed (Constitution IV)
**Scale/Scope**: a new feature-gated `discovery/mdns` module in `async-opcua-server` (responder +
querier + record codec + cache, ~600–800 LOC), the `find_servers_on_network` merge, a config flag, the
`discovery-mdns` feature wiring + facade passthrough, deny.toml verification

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

- **I. Correctness Over Completion (NON-NEGOTIABLE)**: PASS — the DNS-SD record format (`_opcua-tcp._tcp`,
  TXT `path`/`caps`) and FindServersOnNetwork semantics are grounded in OPC UA Part 12 (§4.3.4 /
  Annex C) + Part 4 §5.5.3 and the OPC Foundation reference stacks; the deterministic codec/mapping is
  unit-tested.
- **II. Do It Right Once**: PASS — reuses the existing `registered_servers` registry + `find_servers_on_
  network` + the generated `MdnsDiscoveryConfiguration`/`ServerOnNetwork` types; only ADDS the
  advertise/discover path and merges results. No second discovery registry.
- **III. Individual Task Discipline**: PASS — tasks.md is one atomic task per line, each citing the
  Part/§ or the FR; codex implements one per dispatch.
- **IV. Security Is Paramount**: PASS — this is a NEW network-facing dependency on an unauthenticated,
  attacker-reachable multicast path (Part 2 §8.3 calls out FindServersOnNetwork DoS). Mitigations: (a)
  `mdns-sd` is advisory-clean and the addition is recorded in deny.toml/justification (§110–112); (b) our
  code parses the resolved TXT/SRV fields defensively — bounds the cap count + string lengths, rejects
  malformed records, never unwraps on network data (FR-008); (c) the whole path is opt-in + off by default
  so the default attack surface is unchanged.
- **V. Leave It Better Than You Found It**: PASS — closes a documented gap (`info.rs:255` capability
  filter), and the feature-gating keeps the minimal build and CI legs untouched.

**Result**: No violations. The new network-facing dependency is justified, advisory-checked, opt-in, and
its untrusted-input path is bounded. Proceed.

## Project Structure

### Documentation (this feature)

```text
specs/036-mdns-discovery/
├── plan.md              # This file
├── research.md          # Phase 0 — decisions D1–D9
├── data-model.md        # Phase 1 — service record / discovered record / cache
├── quickstart.md        # Phase 1 — enabling discovery + FindServersOnNetwork
├── contracts/
│   └── mdns-discovery.md # Phase 1 — record format + FindServersOnNetwork merge contract
└── tasks.md             # Phase 2 (/speckit-tasks)
```

### Source Code (repository root)

```text
async-opcua-server/Cargo.toml
  - new optional dep `mdns-sd` + new feature `discovery-mdns = ["dep:mdns-sd"]` (off by default)
async-opcua/Cargo.toml
  - facade passthrough `discovery-mdns = ["async-opcua-server/discovery-mdns"]`
async-opcua-server/src/discovery/mdns.rs            # NEW, #[cfg(feature = "discovery-mdns")]
  - record codec (Part-12 TXT path/caps encode/decode), ServiceInfo↔ServerOnNetwork mapping,
    responder (register/unregister via ServiceDaemon), querier (browse → cache), the cache type
async-opcua-server/src/info.rs
  - ServerInfo gains a feature-gated discovery cache field; find_servers_on_network (L251) merges
    cache records + applies capability_filter against advertised caps (cfg-gated; no-op when off)
async-opcua-server/src/server.rs (run / CancellationToken at L266)
  - feature-gated spawn of the responder+querier background tasks, unregister on cancellation
async-opcua-server/src/config/ (ServerConfig / capabilities.rs)
  - feature-gated opt-in config: enable multicast, mdns server name, advertised capabilities
deny.toml
  - verify `cargo deny check advisories` is green with the feature on; add a justified ignore ONLY if a
    transitive advisory appears
.github/workflows/main.yml
  - (verify) the existing --all-features leg now exercises discovery-mdns; the no-default leg proves absence
```

## Complexity Tracking

The one genuinely new thing is a network-facing optional dependency. It is contained by: (1) total
feature-gating so the default/minimal builds and their CI legs never see it; (2) a thin adapter around
`mdns-sd` (which owns the wire parsing) with our own defensive parsing of the resolved fields; (3) a
deterministic, network-free codec/mapping that carries the testable correctness, leaving only best-effort
multicast e2e to the environment-tolerant integration test. No constitution deviations.
