# Spec traceability & test organization

Purpose: map our tests to the OPC UA spec clauses they exercise, record **how each part is grounded**,
and list implemented features that still need tests (happy + error path).

## Grounding policy

Every implemented spec part should be grounded one of two ways:

1. **Interop-grounded** — an *independent* OPC UA stack drives our server and agrees on the behaviour.
   We run three: **node-opcua** (JS), **open62541** (C), **asyncua** (Python), under
   `samples/demo-server/interop/`. When ≥1 independent stack exercises a part, that is the primary
   grounding; our own tests then only need to cover edges/errors the harness can't reach.
2. **Self-grounded** — for parts no harness stack drives (or we are the only implementer), tests are
   authoritative and must be **anchored to a spec clause** and, for crypto/encoding, to an **external
   vector** (RFC / spec sample), authored independently of the production code.

"Self-grounded but the stack *could* drive it" = an **opportunity** to upgrade to interop-grounded.

Legend: ✅ interop-grounded · 🔵 self-grounded (clause-anchored) · 🟡 self, no clause cited · ⬜ implemented, untested

---

## Services (Part 4 §5)

| Service | Spec | Impl | Integration test | Interop (stacks) | Grounding | Notes |
|---|---|---|---|---|---|---|
| GetEndpoints | §5.5.4 | ✅ | core_tests, discovery | node-opcua | ✅ | only node-opcua drives it |
| FindServers | §5.5.2 | ✅ | core_tests, discovery | — | 🔵 | self only |
| FindServersOnNetwork | §5.5.3 | ✅ (pull, no mDNS) | discovery (returns registered) | — | 🔵 | mDNS LDS-ME multicast deferred |
| RegisterServer / 2 | §5.5.5/.6 / Part 12 §7.5 | ✅ | discovery, info.rs unit (C6 race) | — | 🔵 | self only; cited |
| CreateSession | §5.7.2 | ✅ | conformance, core_tests, hardening | all 3 | ✅ | error: hardening/adversarial |
| ActivateSession | §5.7.3 | ✅ | conformance, hardening, tier_a, adversarial | all 3 | ✅ | error: cross-channel, empty pw, X509 tamper |
| CloseSession | §5.7.4 | ✅ | (implicit in withSession) | all 3 | ✅ | |
| Cancel | §5.7.5 | ✅ (no-op) | core_tests (cancel_is_a_clean_noop) | — | 🔵 | cancelCount 0, session survives |
| Read | §5.11.2 | ✅ | read (cited), conformance, many | all 3 | ✅ | |
| Write | §5.11.4 | ✅ | write (cited) | all 3 (+type-mismatch err) | ✅ | |
| Browse | §5.9.2 | ✅ | browse (cited) | all 3 | ✅ | well-cited |
| BrowseNext | §5.9.3 | ✅ | browse | all 3 (bad-CP err) | ✅ | |
| TranslateBrowsePaths | §5.9.4 | ✅ | browse, tier_a (cycle) | all 3 | ✅ | |
| RegisterNodes / Unregister | §5.9.5/.6 | ✅ | browse | — | 🔵 | self only |
| CreateSubscription | §5.14.2 | ✅ | subscriptions (cited) | all 3 (data-change) | ✅ | |
| ModifySubscription | §5.14.3 | ✅ | subscriptions | — | 🔵 | |
| SetPublishingMode | §5.14.4 | ✅ | subscriptions, datachange_overflow | — | 🔵 | |
| Publish / Republish | §5.14.5/.6 | ✅ | subscriptions, datachange_overflow | all 3 (deliver) | ✅ | |
| TransferSubscriptions | §5.14.7 | ✅ | subscriptions (incl old-session notify) | — | 🔵 | |
| DeleteSubscriptions | §5.14.8 | ✅ | subscriptions | — | 🔵 | |
| CreateMonitoredItems | §5.13.2 | ✅ | subscriptions, sampling_transition | all 3 | ✅ | |
| ModifyMonitoredItems | §5.13.3 | ✅ | subscriptions | — | 🔵 | |
| SetMonitoringMode | §5.13.4 | ✅ | sampling_transition (§5.13.1.3) | — | 🔵 | |
| DeleteMonitoredItems | §5.13.6 | ✅ | subscriptions, tier_a | — | 🔵 | |
| SetTriggering | §5.13.5 / §5.13.1.6 | ✅ | triggering (cited) | node-opcua | ✅ | interop: addResults Good |
| Call (Methods) | §5.12.2 | ✅ | methods (cited) | all 3 (arg/type errs) | ✅ | well-grounded |
| AddNodes | §5.8.2 | ✅ (gated) | node_management (cited), tier_a (C7) | — | 🔵 | node-opcua has no client addNodes → self only |
| DeleteNodes | §5.8.4 | ✅ | node_management, tier_a (delete-under-monitor) | — | 🔵 | |
| AddReferences | §5.8.3 | ✅ | node_management | — | 🔵 | |
| DeleteReferences | §5.8.5 | ✅ | node_management | — | 🔵 | |
| HistoryRead | §5.11.3 / Part 11 | ✅ | hda (cited) | node-opcua (rejects non-historizing only) | 🔵 | variants mostly self; interop opportunity |
| HistoryUpdate | §5.11.5 | ✅ | hda, write | — | 🔵 | niche |
| QueryFirst / QueryNext | §5.10 | ✅ | query (cited) | — | 🔵 | asyncua/node-opcua support → interop opportunity |

## Subsystems (other Parts)

| Area | Spec | Impl | Test | Interop | Grounding |
|---|---|---|---|---|---|
| Binary encoding | Part 6 §5.2.2 | ✅ | types/encoding.rs (cited) | all 3 (round-trips) | ✅ |
| JSON encoding | Part 6 §5.4 | ✅ | types/json.rs (cited) | — | 🔵 (ext vectors) |
| XML encoding | Part 6 §5.3 | ✅ | types/xml.rs | — | 🟡 happy-only |
| NumericRange | Part 4 §7.27 | ✅ | types/variant.rs (cited, C5 fix) | — | 🔵 |
| NodeId parsing | Part 6 §5.3.1.x | ✅ | types/node_id.rs | — | 🟡 no clause |
| DateTime | Part 6 §5.2.2.5 | ✅ | types/date_time.rs | — | 🟡 no clause |
| Decoding-depth DoS | Part 6 (limits) | ✅ | types/recursion_dos.rs | — | 🔵 |
| SecureChannel / chunking | Part 6 §6.7, §6.7.2 | ✅ | core/secure_channel.rs, chunk.rs; adversarial (B1-B5) | all 3 (secured sessions) | ✅ |
| Token renewal grace | Part 4 §5.6.2 | ✅ | core/secure_channel.rs (B4) | — | 🔵 |
| Cert-chain validation (CRL + OCSP) | Part 4 §6.1.3 Table 100 | ✅ | crypto/cert_chain.rs (RFC 5280; OCSP good/revoked/forged fixtures) | open62541/node-opcua (trust/untrust) | ✅ |
| ECC ephemeral/secret | Part 6 §6.8.2/3 | ✅ | crypto/ecc_* (RFC 5869/5903) | ecc.rs e2e | ✅ |
| Identity tokens (user/pass, X509, ECC) | Part 4 §7.41/Table 179 | ✅ | crypto/authentication.rs, conformance, tier_a | all 3 (user/pass + fail) | ✅ |
| PubSub UADP + security | Part 14 §7.2.4 | ✅ | pubsub.rs, crypto/pubsub_ctr.rs (RFC 3686) | **— (no independent stack)** | 🔵 |
| Alarms & Conditions | Part 9 | ✅ | alarms.rs (happy + ack/confirm error paths incl. Bad_EventIdUnknown) | — | 🔵 |
| Programs | Part 10 | ✅ | programs.rs (lifecycle + invalid transitions) | — | 🔵 |
| Transport: reverse connect | Part 6 §7.1.3 | ✅ | reverse_connect.rs | — | 🟡 happy-only |
| Transport: WSS | Part 6 §7.x | ✅ | wss.rs | — | 🟡 happy-only |

---

## Gaps & actions (prioritized)

> **Numbering — standardized to Part 4 v1.05.07.** All Part-4 §5 service citations across the codebase
> now use the on-disk 1.05.07 numbering: Discovery §5.5, SecureChannel §5.6, Session §5.7,
> NodeManagement §5.8, View §5.9, Query §5.10, Attribute §5.11 (Read .2 / HistoryRead .3 / Write .4 /
> HistoryUpdate .5), Method §5.12, MonitoredItem §5.13 (model §5.13.1: Monitoring-mode .3, Queue .5,
> Triggering .6), Subscription §5.14. A prior pass converted the older scheme (Attribute §5.10, Method
> §5.11, MonitoredItem §5.12, Subscription §5.13, Discovery §5.4, NodeManagement §5.7) — including a
> stray `HistoryUpdate §5.11.6` (correct is §5.11.5). Bare `§5.6` refs in `nodes/`/`address_space` are
> **Part 3 Variables/ValueRank**, not Part 4, and are left as-is. (The frozen `codex/` candidate
> snapshots keep their original numbers.)

### A. Untested implemented features (write tests)
1. **Cancel** (§5.7.5) — ✅ DONE: `core_tests.rs::cancel_is_a_clean_noop` asserts cancelCount 0 +
   session stays usable (server is a no-op, Part 4 §5.7.5).
2. **Alarms/Conditions error paths** (Part 9) — ✅ DONE: `alarms.rs::alarm_acknowledge_confirm_error_paths`
   covers the Acknowledge/Confirm guards (Confirm-before-Ack → Bad_InvalidState, double-Ack →
   Bad_ConditionBranchAlreadyAcked, double-Confirm → Bad_ConditionBranchAlreadyConfirmed).
   **Part 9 EventId validation — FIXED:** the condition now records the EventId of its current reportable
   state (set at trigger) and Acknowledge/Confirm reject a non-matching EventId with Bad_EventIdUnknown
   before the state guards (Part 9 §5.5.2). Test covers the wrong-EventId case.
3. **Programs error paths** (Part 10) — ✅ DONE: `programs.rs::program_invalid_transitions_return_bad_state`
   covers the state guards (Start/Suspend/Resume/Halt from Halted, Reset/Suspend/Resume from Ready → all
   Bad_StateNotActive).

### B. Annotate foundational tests with their clause (grounding hygiene, no new coverage)
✅ DONE: `read.rs` (§5.11.2), `write.rs` (§5.11.4), `subscriptions.rs` (§5.14 + §5.13) now carry a
module-level service-set citation. Remaining 🟡: `core_tests.rs` is a session/connection grab-bag (no
single clause); `xml.rs`, `reverse_connect.rs`, `wss.rs` are happy-only transport/encoding.

### C. Interop opportunities (upgrade 🔵 self → ✅ interop)
Self-only today; harness stacks that support the service can cross-check them:
- **SetTriggering** — ✅ DONE: the node-opcua harness now links a monitored item via
  `session.setTriggering` and asserts a Good `addResults` (interop-grounded).
- **HistoryRead** (actual reads, not just rejection) — feasible across all three stacks. *Next.*
- **Query** — node-opcua / asyncua client query.
- **Query** — node-opcua / asyncua client query.
- **AddNodes/DeleteNodes** — ❌ NOT feasible via node-opcua: it has the request types but does **not**
  expose `session.addNodes` on the client API. Would also need the interop server's
  `clients_can_modify_address_space` gate (off by default). Stays self-grounded (`node_management.rs`,
  `tier_a`) unless we drive it with the async-opcua client (loses the independent-stack value).
Highest near-term value: SetTriggering.

### D. Known hard gaps (need infrastructure, document only)
- **PubSub end-to-end interop** — no independent PubSub stack wired (would need .NET/open62541 pubsub).
  Stays self-grounded (UADP + AES-CTR are RFC/clause-anchored). 
- **FindServersOnNetwork** — needs mDNS; deferred.
- **OCSP revocation**, **legacy validate_chain=false** — deferred from feature 013.

---

## How to read / maintain this
- New test → add a row (or extend one) with its clause and grounding mark.
- Prefer interop grounding when a harness stack can drive the part; fall back to clause+vector self-tests.
- The multi-AI cross-check backlog (Tier A/B/C) is in `UNIFIED-PROTOCOL.md`; this file is the standing
  spec-coverage view across the whole suite.
