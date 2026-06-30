# Implementation Plan: Audit Findings Remediation

**Branch**: `042-x509-user-token-validation` | **Date**: 2026-06-29 | **Spec**: [spec.md](./spec.md)
**Input**: Feature specification from `/specs/043-fix-audit-findings/spec.md`

## Summary

Close the security, OPC UA conformance, code-review, and negative-path testing findings captured by
the audit remediation spec. The work will be planned as a sequence of atomic, independently
verifiable remediations. Each implementation task must be grounded in an OPC UA MCP reference,
start with a failing negative-path test, change one trust boundary or protocol rule at a time, and
finish with targeted verification before the next task starts.

## Technical Context

**Language/Version**: Rust 1.75+ workspace
**Primary Dependencies**: Existing workspace crates; `async-opcua-core`, `async-opcua-server`,
`async-opcua-crypto`, `async-opcua-pubsub`, `async-opcua-types`, `async-opcua-xml`, and
`async-opcua-history-sqlite`
**Storage**: Existing PKI trust/rejected/issuer/CRL directories, GDS registry/cache state, and
SQLite history backend; no new persistent storage format
**Testing**: `cargo test` with targeted package filters, integration tests, certificate and
session audit-event checks, profile footprint builds, interop harness checks, `cargo fmt --check`,
and `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`
**Target Platform**: Linux CI and local developer environments
**Project Type**: Rust workspace OPC UA client/server/pubsub library implementation
**Performance Goals**: No unbounded attacker-controlled allocation, no decode-path panic, no
new footprint-critical dependency unless explicitly justified, and no intentional algorithmic
slowdown on existing happy paths; throughput benchmarking is outside this audit-remediation
scope unless a task introduces a known hot-path change
**Constraints**: Fail closed for authentication, certificate, crypto, transport, and PubSub
failures; preserve precise public status codes; do not log secrets; preserve application-certificate
contracts unless a spec-backed test proves an intentional change; one task at a time
**Scale/Scope**: Audit-remediation backlog across session activation, user-token protection, X.509
user tokens, certificate validation/auditing, GDS certificate management, binary transport,
PubSub/SKS, XML/history/encoding negative paths, and associated conformance tests

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

- **Correctness Over Completion**: Pass. The plan requires OPC UA MCP references, failing
  negative-path tests, exact status assertions, and side-effect checks before any finding can be
  marked remediated.
- **Do It Right Once**: Pass. The design favors existing validation/authentication/transport
  boundaries and forbids papering over status-code symptoms without testing state preservation.
- **Individual Task Discipline**: Pass. Task generation must produce one self-contained finding or
  one tightly coupled rule per task, with a single targeted verification command for each task.
- **Security Is Paramount**: Pass. The highest-priority work is authentication, certificate trust,
  credential protection, transport verification, and bounded parsing of untrusted input.
- **Leave It Better Than You Found It**: Pass. Every touched path gains a regression test and a
  documented spec reference, without broad refactors or temporary scaffolding.

## Project Structure

### Documentation (this feature)

```text
specs/043-fix-audit-findings/
├── spec.md
├── plan.md
├── research.md
├── data-model.md
├── quickstart.md
├── contracts/
│   └── audit-remediation.md
└── tasks.md              # Phase 2 output from /speckit-tasks, not created by /speckit-plan
```

### Source Code (repository root)

```text
async-opcua-core/src/
├── comms/
├── messages/
└── tests/

async-opcua-crypto/src/
├── cert_chain.rs
├── certificate_store.rs
├── identity/
├── policy/
└── tests/

async-opcua-server/src/
├── authenticator.rs
├── gds/
├── identity_token.rs
├── services/
├── session/
├── transport/
└── rbac/

async-opcua-pubsub/src/
├── codec/
├── security/
└── subscriber.rs

async-opcua-types/src/
├── encoding.rs
├── extension_object.rs
├── diagnostic_info.rs
└── generated/

async-opcua-xml/src/
async-opcua-history-sqlite/src/

async-opcua-server/tests/
async-opcua-pubsub/tests/
async-opcua-core/src/tests/
async-opcua/tests/integration/
```

**Structure Decision**: Keep remediations in the existing module that owns each trust boundary.
Tests should be added at the lowest layer that proves the rule, with integration coverage only when
the externally visible OPC UA contract cannot be proven by a unit or package test alone.

## Complexity Tracking

> **Fill ONLY if Constitution Check has violations that must be justified**

| Violation | Why Needed | Simpler Alternative Rejected Because |
|-----------|------------|-------------------------------------|
| None | N/A | N/A |

## Phase 0 Research Summary

Research is captured in [research.md](./research.md). Key decisions:

- Task order is priority and dependency based: identity/session trust boundaries first,
  certificate/GDS trust material second, protocol negative paths third.
- Each remediation must cite the OPC UA MCP section or conformance rule it implements before code
  changes start; compact task lines may rely on the selected-finding matrix for full finding,
  expected-status, state-assertion, and command traceability.
- Part 4 governs ActivateSession, identity tokens, status-code differentiation, and certificate
  validation/auditing.
- Part 12 governs GDS push/pull certificate-management authorization and encrypted/authenticated
  channel requirements.
- Part 6 governs binary transport chunking, message error handling, sequence verification,
  recursion limits, and XML parsing error exposure.
- Part 14 governs UADP NetworkMessage header/security shapes and SKS key retrieval semantics.

## Phase 1 Design Summary

Design artifacts:

- [data-model.md](./data-model.md) defines audit findings, normative spec rules, negative-path
  tests, remediation tasks, trust boundaries, certificate material, audit events, and protocol
  messages.
- [contracts/audit-remediation.md](./contracts/audit-remediation.md) defines the externally visible
  behavior for ActivateSession, certificate/GDS operations, transport, PubSub/SKS, XML/history, and
  task atomicity.
- [quickstart.md](./quickstart.md) lists targeted verification commands and the full completion
  gate.

## Task Generation Rules For `/speckit-tasks`

- Generate one task per line item; do not batch unrelated findings into a single task.
- Each story task must include the OPC UA part/section used and the module likely to change.
- Before implementation starts, [finding-matrix.md](./finding-matrix.md) must map each task to the
  finding id or spec requirement it closes, expected status, state assertion, and targeted
  verification command.
- Order tasks by dependency:
  1. Session/channel binding and identity state preconditions.
  2. User-token protection and X.509 signature semantics.
  3. Certificate status mapping and certificate audit behavior.
  4. GDS authorization and certificate replacement atomicity.
  5. Binary transport and service-dispatch negative paths.
  6. PubSub UADP and SKS negative paths.
  7. XML, history, and encoding helper failure exposure.
- A task may cover multiple assertions only when they are the same public rule over the same code
  path, such as "Create and Modify monitored item reject the same invalid timestamps value" or
  "one certificate status mapping plus its matching audit event".
- Every task must have a concrete verification command recorded in [finding-matrix.md](./finding-matrix.md)
  or [verification.md](./verification.md) before the task is implemented; final verification tasks
  carry their command inline.

## Post-Design Constitution Check

- **Correctness Over Completion**: Pass. Contracts require exact statuses, preserved side effects,
  and negative-path tests for every accepted remediation.
- **Do It Right Once**: Pass. The data model and contracts require finding-to-rule traceability so
  later implementation cannot close findings with unrelated fixes.
- **Individual Task Discipline**: Pass. The task-generation rules explicitly forbid batching and
  define one verification command per task.
- **Security Is Paramount**: Pass. Security-sensitive changes are sequenced before lower-severity
  protocol robustness work and must fail closed.
- **Leave It Better Than You Found It**: Pass. All planned changes add regression evidence and keep
  touched modules within established repo structure.
