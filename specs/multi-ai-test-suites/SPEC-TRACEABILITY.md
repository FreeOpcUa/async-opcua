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
| GetEndpoints | §5.4.4 | ✅ | core_tests, discovery | node-opcua | ✅ | only node-opcua drives it |
| FindServers | §5.4.2 | ✅ | core_tests, discovery | — | 🔵 | self only |
| FindServersOnNetwork | §5.4.3 | deferred (mDNS) | discovery (rejects) | — | 🔵 | documented gap |
| RegisterServer / 2 | §5.4.5 / Part 12 §7.5 | ✅ | discovery, info.rs unit (C6 race) | — | 🔵 | self only; cited |
| CreateSession | §5.6.2 | ✅ | conformance, core_tests, hardening | all 3 | ✅ | error: hardening/adversarial |
| ActivateSession | §5.6.3 | ✅ | conformance, hardening, tier_a, adversarial | all 3 | ✅ | error: cross-channel, empty pw, X509 tamper |
| CloseSession | §5.6.4 | ✅ | (implicit in withSession) | all 3 | ✅ | |
| Cancel | §5.6.5 | ✅ (no-op) | **none** | — | ⬜ | **gap** — no test of the no-op semantics |
| Read | §10.2 / §5.10.x | ✅ | read, conformance, many | all 3 | ✅ | **read.rs cites no clause** |
| Write | §10.4 | ✅ | write | all 3 (+type-mismatch err) | ✅ | **write.rs cites no clause** |
| Browse | §5.8.2 | ✅ | browse (§5.9 cited) | all 3 | ✅ | well-cited |
| BrowseNext | §5.8.3 | ✅ | browse | all 3 (bad-CP err) | ✅ | |
| TranslateBrowsePaths | §5.8.4 | ✅ | browse, tier_a (cycle) | all 3 | ✅ | |
| RegisterNodes / Unregister | §5.8.5/6 | ✅ | browse | — | 🔵 | self only |
| CreateSubscription | §5.13.2 | ✅ | subscriptions | all 3 (data-change) | ✅ | **subscriptions.rs cites no clause** |
| ModifySubscription | §5.13.3 | ✅ | subscriptions | — | 🟡 | |
| SetPublishingMode | §5.13.4 | ✅ | subscriptions, datachange_overflow | — | 🔵 | |
| Publish / Republish | §5.13.5/6 | ✅ | subscriptions, datachange_overflow | all 3 (deliver) | ✅ | |
| TransferSubscriptions | §5.13.7 | ✅ | subscriptions (incl old-session notify) | — | 🔵 | |
| DeleteSubscriptions | §5.13.8 | ✅ | subscriptions | — | 🟡 | |
| CreateMonitoredItems | §5.12.2 | ✅ | subscriptions, sampling_transition | all 3 | ✅ | |
| ModifyMonitoredItems | §5.12.3 | ✅ | subscriptions | — | 🟡 | |
| SetMonitoringMode | §5.12.4 | ✅ | sampling_transition (§5.12.1.3) | — | 🔵 | |
| DeleteMonitoredItems | §5.12.6 | ✅ | subscriptions, tier_a | — | 🔵 | |
| SetTriggering | §5.12.5 / §5.12.1.6 | ✅ | triggering (cited) | — | 🔵 | **node-opcua supports it → interop opportunity** |
| Call (Methods) | §5.11.2 | ✅ | methods (cited) | all 3 (arg/type errs) | ✅ | well-grounded |
| AddNodes | §5.7.2 | ✅ (gated) | node_management (§5.7), tier_a (C7) | — | 🔵 | **node-opcua/asyncua support it → interop opportunity** |
| DeleteNodes | §5.7.4 | ✅ | node_management, tier_a (delete-under-monitor) | — | 🔵 | |
| AddReferences | §5.7.3 | ✅ | node_management | — | 🔵 | |
| DeleteReferences | §5.7.5 | ✅ | node_management | — | 🔵 | |
| HistoryRead | §10.3 / Part 11 | ✅ | hda (cited) | node-opcua (rejects non-historizing only) | 🔵 | variants mostly self |
| HistoryUpdate | §10.5 | ✅ | hda, write | — | 🔵 | niche |
| QueryFirst / QueryNext | §5.9 | ✅ | query (cited) | — | 🔵 | **asyncua/node-opcua support → interop opportunity** |

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
| Token renewal grace | Part 4 §5.5.2 | ✅ | core/secure_channel.rs (B4) | — | 🔵 |
| Cert-chain validation | Part 4 §6.1.3 Table 100 | ✅ | crypto/cert_chain.rs (RFC 5280) | open62541/node-opcua (trust/untrust) | ✅ |
| ECC ephemeral/secret | Part 6 §6.8.2/3 | ✅ | crypto/ecc_* (RFC 5869/5903) | ecc.rs e2e | ✅ |
| Identity tokens (user/pass, X509, ECC) | Part 4 §7.41/Table 179 | ✅ | crypto/authentication.rs, conformance, tier_a | all 3 (user/pass + fail) | ✅ |
| PubSub UADP + security | Part 14 §7.2.4 | ✅ | pubsub.rs, crypto/pubsub_ctr.rs (RFC 3686) | **— (no independent stack)** | 🔵 |
| Alarms & Conditions | Part 9 | ✅ | alarms.rs | — | 🟡 happy-only, no clause |
| Programs | Part 10 | ✅ | programs.rs | — | 🟡 happy-only, no clause |
| Transport: reverse connect | Part 6 §7.1.3 | ✅ | reverse_connect.rs | — | 🟡 happy-only |
| Transport: WSS | Part 6 §7.x | ✅ | wss.rs | — | 🟡 happy-only |

---

## Gaps & actions (prioritized)

### A. Untested implemented features (write tests)
1. **Cancel** (§5.6.5) — implemented as a spec-conformant no-op, **zero tests**. Add a self-test:
   Cancel of an unknown request handle returns `Good` (cancelCount 0), server survives. *Self.*
2. **Alarms/Conditions error paths** (Part 9) — `alarms.rs` is happy-only and uncited. Add: acknowledge
   an already-confirmed/unknown condition → proper Bad status; anchor each test to a Part 9 clause. *Self.*
3. **Programs error paths** (Part 10) — `programs.rs` happy-only/uncited. Add an invalid state-transition
   (e.g. Resume while Halted) → Bad status; cite Part 10. *Self.*

### B. Annotate foundational tests with their clause (grounding hygiene, no new coverage)
`read.rs`, `write.rs`, `subscriptions.rs`, `core_tests.rs` carry no spec citation. Add a one-line
`// Part 4 §…` header to each so the suite is traceable. Cheap; closes the 🟡 → 🔵 gap for core services.

### C. Interop opportunities (upgrade 🔵 self → ✅ interop)
These are self-only today but the harness stacks support them — cross-checking would harden them:
- **AddNodes/DeleteNodes** — node-opcua + asyncua both implement client-side NodeManagement.
- **SetTriggering** — node-opcua `setTriggering`.
- **Query** — node-opcua / asyncua client query.
- **HistoryRead** (actual reads, not just rejection) — all three can read history.
Each is a handful of `check(...)` lines added to the existing harnesses, gated on the writable/feature
config. Highest value: AddNodes (we found a real audit-class area there) and SetTriggering.

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
