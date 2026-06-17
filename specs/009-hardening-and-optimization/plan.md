# Implementation Plan: Codebase Hardening, Cleanup & Optimization

**Branch**: `009-hardening-and-optimization` | **Date**: 2026-06-17 | **Spec**: [spec.md](./spec.md)
**Input**: Feature specification from `specs/009-hardening-and-optimization/spec.md`

## Summary

Remediate the findings of the five 2026-06-16 review documents (CODE_REVIEW, SECURITY_AUDIT,
NETWORK_REVIEW, PERFORMANCE_AUDIT, ARCHITECTURE_REVIEW) into a single **0.19.0** release of the
async-opcua workspace. Scope is the full finding set plus the four large structural items confirmed
in scope by the clarification session: RSA constant-time backend migration (D1), `NodeManager`
capability-trait segregation (R3), an `opc.wss` WebSocket connector (R5), and `Bytes`/`Arc`-backed
hot-path types (P5/P10). Public-API breaking changes are permitted at the 0.19 boundary and documented
in the changelog. Wire-format stability is enforced by a **hard CI interop gate** (dotnet +
open62541). Each finding is remediated as an individual, independently verifiable task with a
regression test (Constitution III, I/II).

**Technical approach**: organize the work into eight tracks (below), sequenced security-first. The
only decision requiring research — the constant-time RSA backend — is resolved in `research.md`
(**`aws-lc-rs` for the three decrypt paths behind a narrow trait, `rsa` retained for everything
else**, with application-level uniform timing landing first as a stopgap).

## Technical Context

**Language/Version**: Rust (edition 2021; workspace builds on stable + beta in CI). Target release
**0.19.0** (from 0.18.0). MSRV unchanged unless a dependency upgrade forces a bump (call out if so).
**Primary Dependencies**: tokio (async runtime), `bytes`, `rsa`→**add `aws-lc-rs`** (decrypt only),
`x509-cert`, `aes`/`hmac`/`sha2`/`subtle`, `parking_lot`/`dashmap`/`arc-swap`, `tracing`;
add `socket2` (keepalive), `tokio-tungstenite` on **rustls 0.23** (WebSocket), upgraded `rumqttc`
(off EOL rustls 0.21). Test/bench: `cargo test`, `criterion` (already a workspace dep), `cargo-fuzz`.
**Storage**: N/A (protocol library; optional sqlite history backend unchanged).
**Testing**: `cargo test` (unit + integration), `criterion` benches (existing + new encode/decode &
secured round-trip), `cargo-fuzz` (3 existing targets + recursion-DoS corpus), **interop harnesses**
`dotnet-tests/` and `3rd-party/open62541/` as a hard CI gate, `cargo-deny check advisories`.
**Target Platform**: cross-platform library; CI is Linux (`ubuntu-latest`). `aws-lc-rs` uses prebuilt
bindings on Linux x86_64/aarch64; document the CMake fallback for other consumer targets.
**Project Type**: Rust workspace (~17 crates) — existing layout; no new top-level structure.
**Performance Goals**: NEEDS CLARIFICATION → deferred by design. The performance audit ran no live
profiling; numeric targets are set **after** baseline benchmarks (P12) exist. Until then the goal is
"measurable improvement vs. the new baseline benchmark" (SC-006/SC-007).
**Constraints**: **no OPC-UA wire-format change** (hard interop gate, FR-041/FR-046); secured-path
per-chunk heap allocations reduced to a fixed (non-per-chunk) count; no secret in logs/Debug; builds
warning-free in three feature configs (default / `--all-features` / default-features-off).
**Scale/Scope**: ~50 findings across 7 crates; 6 prioritized user stories; 46 functional requirements.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

Gates derived from constitution v1.0.0:

| Principle | Gate | Status |
|-----------|------|--------|
| I — Correctness over completion | Every behavioral fix carries a regression test (fail-before/pass-after); no item closed with a known defect. Crash findings (C1, C2, H7, M1) get a reproduction test. | **PASS** (enforced per-task; SC-001) |
| II — Do it right once | D1 fixed at the primitive level (backend migration), not only app-layer; no warning-suppression or string-patch shortcuts; root causes fixed. | **PASS** (research.md picks the proper backend) |
| III — Individual task discipline | tasks.md MUST be one task per finding/sub-finding, never batched; each independently verifiable. | **PASS** (binding constraint on /speckit-tasks; FR-039) |
| IV — Security is paramount | Security findings are P1 and sequenced first; no change weakens a security control; fail-closed defaults; advisory gate in CI. | **PASS** (Tracks A–C first; FR-022) |
| V — Leave it better | Debris removed (P3) and no new debris; touched code left healthier. | **PASS** (Track G) |
| Workflow — green before done | Build+test pass in all three feature configs before any item is "done". | **PASS** (SC-008) |
| Workflow — no wire/spec regression | Hard interop gate (dotnet + open62541). | **PASS** (FR-046, SC-010) |

**Result: PASS — no violations.** The feature's breadth is large but that is inherent to a
remediation program; it is managed by per-finding task decomposition (Principle III), not by batching.
No entry in Complexity Tracking is required.

## Work tracks

The 46 FRs are organized into eight tracks. Tracks A–C are P1 (ship first); D–E are P2; F–H are P2/P3
and include the large structural items. Within each track, **one finding = one task** (Principle III).

| Track | Theme | Crates | Key FRs / findings |
|-------|-------|--------|--------------------|
| **A** | Decoder crash-proofing | `-types` | FR-001 (C1 ×3 depth locks), FR-009 (L11), FR-038 (M2) |
| **B** | Server DoS & resource limits | `-server`, `-core` | FR-003 (C3), FR-004 (C4), FR-005 (H3/N10), FR-006 (H2), FR-007 (H4), FR-008 (N6/M11), FR-009 (M1/L3) |
| **C** | Crypto & authN/Z | `-crypto`, `-server` | FR-002 (C2), FR-014 (H1), FR-015 (H5), FR-016 (M3/M4), FR-017 (H6/H8), FR-018 (M6), FR-019 (M12/L2), FR-020 (L4–L10/L14), **FR-042 (D1 backend)** |
| **D** | Client robustness & sockets | `-client`, `-core` | FR-010 (H7/L12), FR-011 (N2), FR-012 (N8), FR-013 (M10), FR-026 (N1/N3), FR-035 (M8/M9) |
| **E** | Performance hot-path | `-core`, `-crypto`, `-server`, `-types` | FR-027 (P2/P3), FR-028 (P1), FR-029 (P6/P7/P8/M5), FR-030 (P12), FR-032 (M14), FR-033 (M13), FR-034 (M7) |
| **F** | Large structural items | `-types`, `-server`, `-client`, `-crypto` | **FR-043 (R3 NodeManager split)**, **FR-044 (R5 WebSocket)**, **FR-045 (P5/P10 Bytes/Arc types)**, FR-037 (R2 error context) |
| **G** | Repo & supply chain | workspace, CI | FR-021 (P3 debris), FR-022 (P1 advisory gate), FR-023 (D2 MQTT TLS), FR-024 (D3/D4/D5 deps), FR-025 (P2 disclosure), FR-046 (interop gate) |
| **H** | Codegen & observability | `-codegen`, `-server`, `-core` | FR-036 (L1/R1 unsafe/derive), FR-031 (R6 metrics) |

**Sequencing rationale**: A and C-crash (FR-002) are the cheapest, highest-impact crash fixes →
first. B closes single-peer DoS. C completes crypto/authN. G's advisory gate + interop gate should
land **early** so every subsequent change is validated against them (CI-first). The large items in F
(esp. FR-042 backend, FR-043 trait split, FR-045 type changes) are the breaking changes — sequence
them after the small fixes so the 0.19 break is a deliberate, batched-at-the-boundary event, with the
changelog assembled as they land. E's benchmarks (FR-030/P12) land **before** the perf optimizations
they measure.

## Project Structure

### Documentation (this feature)

```text
specs/009-hardening-and-optimization/
├── plan.md              # This file
├── research.md          # Phase 0 — RSA backend + transport/dep/socket decisions
├── data-model.md        # Phase 1 — changed/new config, feature flags, capability traits, types
├── quickstart.md        # Phase 1 — build/test/validate (3 configs, benches, interop, cargo-deny)
├── contracts/
│   ├── public-api-changes.md   # 0.19 breaking-change catalog
│   ├── config-and-features.md  # new/changed config fields & feature flags
│   └── node-manager-traits.md  # R3 capability-trait decomposition
├── checklists/requirements.md  # (from /speckit-specify, updated by /speckit-clarify)
└── tasks.md             # /speckit-tasks output — NOT created here
```

### Source Code (repository root — existing workspace, no new top-level structure)

```text
async-opcua-types/      # Track A (decode depth locks, M2), F (FR-045 Bytes ByteString / Arc Variant)
async-opcua-core/       # Track B/D (chunk ceiling, checked arithmetic, sockets), E (zero-copy chunk, byte_len)
async-opcua-crypto/     # Track C (all crypto/authN, FR-042 aws-lc-rs decrypt), E (HMAC/AES schedule cache)
async-opcua-server/     # Track B (limits), C (authN, cert URI), E (tick, pool), F (R3), H (metrics)
async-opcua-client/     # Track D (robustness, sockets, cert trust), F (R5 WebSocket connector)
async-opcua-pubsub/     # Track G (rumqttc/rustls upgrade, D2)
async-opcua-codegen/    # Track H (FR-036 stop emitting unsafe impls / derive binary)
.github/workflows/      # Track G (advisory gate, interop gate) — new/edited CI
deny.toml               # Track G (new — advisory policy + rsa exception)
SECURITY.md             # Track G (private disclosure channel)
fuzz/                   # Track A (recursion-DoS corpus)
*/benches/              # Track E (new encode/decode + secured round-trip benches)
```

**Structure Decision**: This is a remediation feature over an existing 17-crate Cargo workspace.
No new crates are introduced except possibly an optional `websocket` feature/module inside
`async-opcua-client` (FR-044) and an optional metrics-exporter feature (FR-031); both are additive and
feature-gated. All other work edits existing crates in place.

## Complexity Tracking

> No constitution violations — this section is intentionally empty. The feature is large by necessity
> (it remediates ~50 reviewed findings), but breadth is handled by one-task-per-finding decomposition
> (Principle III), not by added architectural complexity. The single new external dependency
> (`aws-lc-rs`) is justified in `research.md` as the only constant-time backend providing the required
> RSA decrypt primitives.

## Phase notes

- **Phase 0 (research.md)**: resolves the RSA backend (done — `aws-lc-rs`), the WebSocket/TLS stack and
  `rumqttc` upgrade, the `ByteString` `Bytes` migration approach and its API impact, socket-tuning
  approach (`socket2` for keepalive; `set_nodelay` direct), the advisory-gate tooling (`cargo-deny` +
  `deny.toml` with a recorded `rsa` exception), and the per-IP-cap / in-flight-backpressure approach.
- **Phase 1 (data-model.md, contracts/, quickstart.md)**: the "entities" are configuration defaults
  (changed values are themselves findings), new config fields/feature flags, the R3 capability-trait
  decomposition, and the 0.19 public-API breaking-change catalog (the release contract). quickstart
  documents how to build/test/bench/interop-validate the three feature configurations.
- **Phase 2 (tasks.md)**: produced by `/speckit-tasks` — one task per finding, grouped by track,
  sequenced A→C→G(gates)→B/D/E→F, each with its regression test.
