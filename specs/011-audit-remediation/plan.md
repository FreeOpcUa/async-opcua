# Implementation Plan: Audit Remediation (Security & Long-Uptime Hardening)

**Branch**: `011-audit-remediation` | **Date**: 2026-06-20 | **Spec**: [spec.md](./spec.md)
**Input**: Feature specification from `/specs/011-audit-remediation/spec.md`

## Summary

Remediate the verified findings from the 2026-06-20 codex+Antigravity audit across five
prioritized, independently-shippable user stories: bound SQLite history reads (P1), make session
activation replay-safe (P1), bound all decode allocations from untrusted input (P1), eliminate
long-uptime growth (P2), and close config/defense-in-depth footguns (P3). The approach reuses
existing infrastructure — `DecodingOptions` limits, the moka-backed history continuation cache, the
connection-actor panic isolation, and the existing decoding framework — rather than inventing new
mechanisms. Every change preserves wire byte-identity and leaves generated code untouched.

## Technical Context

**Language/Version**: Rust (workspace MSRV; edition 2021)
**Primary Dependencies**: `tokio` (async runtime), `bytes`, `rusqlite 0.31` (bundled, history-sqlite),
`moka` (history continuation cache), `serde`/`serde_norway` (config), existing `BinaryDecodable`/
`BinaryEncodable` framework with `Context`/`DecodingOptions`.
**Storage**: SQLite via `async-opcua-history-sqlite` (rusqlite, `spawn_blocking` worker).
**Testing**: `cargo test --workspace` (unit) + `cargo test -p async-opcua --test integration_tests`
(98-test suite) + `cargo +nightly fuzz` decode targets + `cargo clippy --all-targets --all-features
-- -D warnings`.
**Target Platform**: Linux servers and embedded Linux (Pi Zero floor); single- and multi-core.
**Project Type**: Library workspace (server/client/types/core/crypto/pubsub/history-sqlite crates).
**Performance Goals**: No steady-state growth over months of uptime; bounded per-peer/per-request
allocation; wire byte-identity preserved on notification/response/republish paths.
**Constraints**: clippy `--all-targets --all-features` clean; `verify-clean-codegen` green; no
generated-code edits; `no_std`/MCU explicitly out of scope.
**Scale/Scope**: ~8 crates touched; 5 user stories; ~13 functional requirements.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | Assessment |
|-----------|-----------|
| **I. Correctness Over Completion** | ✅ This feature *is* closing known correctness/security gaps; each story ships with a regression test that fails before and passes after (FR acceptance + SC-001..006). |
| **II. Do It Right Once** | ✅ Fixes target root causes (centralized subscription removal, cursor-based history, checked arithmetic) — not symptom suppression. The deferred u32-wraparound item is explicitly recorded (Assumptions), per the "record deliberate shortcuts" rule. |
| **III. Individual Task Discipline** | ✅ Work decomposes one-task-per-line in `/speckit-tasks`; **one task per codex dispatch**; one commit per user story. |
| **IV. Security Is Paramount** | ✅ Directly serves IV: bounds untrusted-input allocations (US3, US5), removes a panic/overflow path (FR-006), hardens auth replay (US2, fail-closed reject), bounds per-peer/long-uptime resource use (US1, US4). No security regression; the activation re-check fails closed. |
| **V. Leave It Better** | ✅ No new debris; removes a latent unbounded API (FR-011) and dead reverse-index entries (FR-007); profiles + bounded defaults improve out-of-box safety. |

**Gate result: PASS.** No violations; Complexity Tracking not required.

Security review note: every story touches a decode/auth/transport path → each PR gets a
security-focused review (Workflow gate). Activation hardening (US2/FR-003) is flagged for private
upstream disclosure before any upstream PR.

## Project Structure

### Documentation (this feature)

```text
specs/011-audit-remediation/
├── plan.md              # This file
├── research.md          # Phase 0 — design decisions per story
├── data-model.md        # Phase 1 — entities (cursor, limits, continuation point, index entry)
├── quickstart.md        # Phase 1 — per-story verification commands
├── contracts/           # Phase 1 — public config/API surface changes
│   └── api-surface.md
├── checklists/
│   └── requirements.md  # spec quality checklist (from /speckit-specify)
└── tasks.md             # Phase 2 — created by /speckit-tasks
```

### Source Code (repository root) — crates touched per story

```text
async-opcua-history-sqlite/src/{backend.rs,query.rs}   # US1: LIMIT + keyset cursor continuation
async-opcua-server/src/
├── session/manager.rs                                 # US2: nonce re-check under commit lock
├── subscriptions/{mod.rs,session_subscriptions.rs}    # US4: centralized monitored_items cleanup
├── session/instance.rs                                # US4: browse/query continuation TTL/LRU
├── programs/engine.rs                                 # US4: Drop → abort task
├── transport/tcp.rs + config/limits.rs                # US5: reject both-zero; bounded defaults
└── config/limits.rs                                   # US5: max_notifications_per_publish default
async-opcua-pubsub/src/{codec/uadp.rs,security/codec.rs}  # US3: dataset field/payload limits
async-opcua-types/src/
├── custom/custom_struct.rs                            # US3: checked_mul on ArrayDimensions
├── byte_string.rs                                     # US5: allocate-after-validate
└── encoding/DecodingOptions                           # US3/US5: limit fields
async-opcua-core/src/comms/tcp_types.rs                # US5: bound or remove read_bytes
samples/ + deploy-profiles.md                          # US5: micro/gateway/server profiles
```

**Structure Decision**: No new crates or modules; changes are surgical edits within the existing
crate boundaries listed above, reusing existing config (`Limits`/`DecodingOptions`), the moka cache
pattern (`history/continuation.rs`), and the decoding framework (`Context`).

## Complexity Tracking

> No constitution violations — section intentionally empty.
