# async-opcua conformance audit — master plan

**Goal:** a structured, spec-anchored audit of `async-opcua` that produces a concrete fix list, then
fixes it. Driven by the observation that non-conformities keep turning up wherever we look closely
(features 011–030). This replaces ad-hoc piece-by-piece discovery with one prioritised board.

**Scope (user decision 2026-06-23):** audit **what we claim** — the two server profiles plus every
service/feature `docs/compatibility.md` + `docs/advanced_compliance.md` advertise as implemented.
Optional facets we don't claim, and the ~130 companion/transport specs (PROFINET, IO-Link, Devices,
UAFX…), are out of scope. If a claim turns out to be a stub or stale doc, that drift is itself a
finding.

**Order (user decision):** behavioral-risk first — **Part 4 (Services) → Part 6 (Mappings/encoding) →
Part 3 (Address Space) → Part 2 (Security) → Part 5 / 8 / 11 / 12 / 14 as claimed.** Front-loads where
a bug means silent data loss or a vulnerability.

**The real arbiter is Part 7 + the CTT.** Part 7 (Profiles) defines which behaviours the claimed
profiles *mandate*; the OPC Foundation CTT is the authoritative behavioural test. This prose audit is
the cheap, deep complement: it finds spec-vs-code divergences the CTT smoke (feature 020) can't, and
feeds them to fix. Where a unit has a CTT facet, note it.

**Spec source:** local PDFs in `~/opcua-specs` (Part 4 = 1.05.07, Part 6 = 1.05.07, Part 3/5/2 =
1.05.06, Part 7 = 1.05.02). Extract the unit's section to a working text file when auditing. The spec
is authoritative: where impl diverges, impl is wrong and is fixed to conform.

---

## What we claim (the audit surface)

**Profiles:** `Server/Behaviour` (base) + `Server/EmbeddedUA`. Plus the analogous client surface.
**Transport:** `opc.tcp://` binary only (XML and https deliberately never).
**Security:** policies None, Basic128Rsa15/Basic256 (legacy, runtime opt-in), Basic256Rsa256,
Aes128-Sha256-RsaOaep, Aes256-Sha256-RsaPss; modes None/Sign/SignAndEncrypt; ECC policies (feature 012).
**Identity tokens:** Anonymous, UserName (plain + encrypted), X509, IssuedToken (OAuth framework).
**Services claimed:** Discovery (GetEndpoints; FindServers; RegisterServer/2 — feature 024),
SecureChannel (Open/Close), Attribute (Read/Write/HistoryRead/HistoryUpdate), Session
(Create/Activate/Close/Cancel), NodeManagement (Add/Delete Nodes+References — feature 022), Query
(QueryFirst/Next — feature 023), View (Browse/BrowseNext/TranslateBrowsePaths/Register/Unregister),
MonitoredItem (Create incl. DataChange+deadband+Event filter / Modify / SetMonitoringMode /
SetTriggering / Delete), Subscription (Create/Modify/Delete/Transfer/Publish/Republish/SetPublishingMode),
Method (Call — feature 021).
**Address space:** CoreNodeManager + generated standard nodeset.
**Advanced (advanced_compliance.md):** PubSub `GetSecurityKeys`, subscription `EventFilter`,
RSA-OAEP encrypted identity secrets, graph Query. **PubSub:** secured UADP NetworkMessage (feature 026).

> ⚠ `docs/compatibility.md` is partly **stale** (still lists RegisterServer/FindServers as
> `BadServiceUnsupported` stubs; feature 024 implemented them). Reconciling doc-vs-impl drift is part of
> each unit's audit, and a refresh of compatibility.md is a deliverable.

---

## Audit-unit backlog (behavioral-risk order)

Each unit = one bounded read-against-spec pass over a claimed area, producing findings into
[FINDINGS.md](./FINDINGS.md). Status: ⬜ not started · ◑ in progress · ✅ audited (findings logged).
"Prior" = features that already covered part of it (don't re-audit settled ground; see each unit /
FINDINGS for the verified-conformant carryover).

### Part 4 — Services (behavioral core)
| Unit | Area (Part 4 §) | Priority | Status | Prior |
|---|---|---|---|---|
| **P4-SUB** | Subscription + MonitoredItem delivery (§5.13/§5.14) — [detail](./unit-P4-SUB.md) | P1 | ◑ | 027/029/030 |
| **P4-ATTR** | Attribute set: Read/Write/HistoryRead/HistoryUpdate (§5.11), IndexRange/NumericRange, DataValue, timestamps, write masks | P1 | ✅ | 017 (NumericRange) |
| **P4-VIEW** | View set: Browse/BrowseNext/TranslateBrowsePaths/Register/Unregister (§5.9), continuation points, ref/nodeclass filtering, BrowseDirection | P1 | ✅ | — |
| **P4-SESS** | SecureChannel (§5.6) + Session (§5.7): Open/Close, Create/Activate/Close/Cancel, nonce, cert binding, token renewal, timeouts | P1 | ✅ | 013/014 |
| **P4-GENERAL** | General service behaviour (§5.1–5.3): request/response headers, diagnostics, OperationLimits, service-result vs operation-level status, per-service security checks | P1 | ⬜ | 011/025 |
| **P4-NODEMGMT** | NodeManagement set (§5.8): Add/Delete Nodes+References, status codes, gating | P2 | ✅ | 022 |
| **P4-METHOD** | Method Call (§5.12): argument validation, status codes, output mapping | P2 | ✅ | 021 |
| **P4-QUERY** | Query set (Annex B): QueryFirst/Next, content filter, continuation points | P2 | ✅ | 023 |
| **P4-DISC** | Discovery set (§5.5): GetEndpoints, FindServers, RegisterServer/2; FindServersOnNetwork (deferred, mDNS) | P2 | ✅ | 024 |

### Part 6 — Mappings (encoding / transport)
| Unit | Area (Part 6 §) | Priority | Status | Prior |
|---|---|---|---|---|
| **P6-BIN** | Binary encoding/decoding (§5.2): all built-ins, NodeId forms, Variant, arrays, ExtensionObject, DataValue; decoder DoS bounds | P1 | ⬜ | 017/018/025 |
| **P6-JSON** | JSON encoding (§5.4): reversible/non-reversible, edges, DateTime precision | P2 | ⬜ | 018/019 |
| **P6-TCP** | opc.tcp secure conversation (§6/§7): Hello/Ack/Error, chunking, message/chunk size limits, sequence headers, abort | P1 | ⬜ | 025 (max_message_size) |

### Part 3 — Address Space Model
| Unit | Area | Priority | Status | Prior |
|---|---|---|---|---|
| **P3-NODES** | Node classes + mandatory attributes per class, references, modelling rules, ValueRank/ArrayDimensions semantics | P2 | ⬜ | — |

### Part 2 — Security Model
| Unit | Area | Priority | Status | Prior |
|---|---|---|---|---|
| **P2-SEC** | Handshake, policy negotiation, cert validation, key derivation/nonce, ECC, user-token encryption, application authentication | P1 | ⬜ | 012/013/014/015/016/025 |

### Parts 5 / 8 / 11 / 12 / 14 — as claimed
| Unit | Area | Priority | Status | Prior |
|---|---|---|---|---|
| **P5-NODESET** | Standard address space (Part 5): mandatory nodes/types, ServerStatus, ServerCapabilities, namespaces | P3 | ⬜ | — |
| **P8-DA** | DataAccess (Part 8): AnalogItem/EURange, deadband types referenced by DataChangeFilter | P3 | ⬜ | — |
| **P11-HIST** | Historical Access (Part 11): HistoryRead/Update detail behind the Attribute service | P3 | ⬜ | — |
| **P12-GDS** | Discovery/GDS (Part 12): RegisterServer registry, GetSecurityKeys/SKS | P3 | ⬜ | 024/026 |
| **P14-PUBSUB** | PubSub (Part 14): secured UADP NetworkMessage, SecurityHeader, anti-replay | P3 | ⬜ | 026 |

---

## Workflow — audit ALL units first, then fix (user decision 2026-06-23)
**Do NOT interleave.** Complete the entire audit (every unit, all findings logged) before any fix
work begins. Rationale: the user wants the full divergence picture before committing to a fix order;
fixes get planned against the complete register, not discovered piecemeal.

**Audit phase (now) — per unit:**
1. **Extract** the unit's normative requirements from the local PDF; list every "shall" / status-code
   table / state rule that applies to the claimed surface.
2. **Map → impl**, recording each divergence as a finding in [FINDINGS.md](./FINDINGS.md) (schema
   below). **Discovery only — change nothing.** Candidate findings from agents are VERIFIED against
   spec+code before logging (audits produce false positives).
3. **Close** the unit: mark ✅, record verified-conformant carryover so it isn't re-audited, note any
   `docs/compatibility.md` drift.

**Fix phase (later, after the audit is complete):** triage the full register by severity; S1/S2 become
speckit features in a deliberate order. Locked protocol: **codex implements one task per dispatch (no
tests, no git); Claude authors all tests anchored to the cited spec text, never to the code.** One
commit per user-story; PR to fork `occamsshavingkit/async-opcua`; wait for full Actions CI.

> Exception already taken: P4-SUB-01 was fixed during setup (one-line guard, closed the Table 79
> audit). No further fixes until the audit phase completes.

## Finding schema (FINDINGS.md rows)
`ID · Part/§/Table · impl location · divergence (spec says X / impl does Y) · severity · fix-size · status`
- **ID:** `<UNIT>-NN`, e.g. `P4-SUB-01`.
- **Severity:** **S1** security or silent data loss · **S2** observable conformance · **S3**
  cosmetic / dead code / doc drift.
- **Fix-size:** S / M / L.
- **Status:** open · fixing(feat#) · fixed(feat#) · deferred(reason) · verified-conformant.

## Status board
- **Done units:** none fully closed yet. P4-SUB partway (027/029/030 merged; **P4-SUB-01 fixed**; 2 gaps open).
- **Carry-over open findings:** P4-SUB-02 (transfer), P4-SUB-03 (event overflow) — see FINDINGS.md.
- **Confirmed findings so far:** P4-SUB-01 (fixed) · P4-ATTR-01 (S2 indexRange decode) · P4-ATTR-05
  (S2 HistoryRead NEITHER) · P4-VIEW-01 (S2 invalid referenceTypeId) · P4-SESS-01 (S2 Cancel
  unimplemented + doc drift) · P4-SESS-02 (S2 nonce max-len) · plus P4-ATTR-02/03/04 deferred S3.
  Several unverified candidates parked in FINDINGS.md.
- **Audited units:** P4-SUB (partial), P4-ATTR ✅, P4-VIEW ✅, P4-SESS ✅, P4-NODEMGMT ✅, P4-METHOD ✅,
  P4-QUERY ✅, P4-DISC ✅. **Part 4 service sets essentially done** except P4-GENERAL (§5.1–5.3).
- **Later findings (P2 batch):** P4-METHOD-01 (S2 Executable not checked), P4-METHOD-02 (S3), P4-QUERY-01
  (S2 typeDef not validated), P4-NODEMGMT-01 (S3 cluster), P4-DISC-01 (S3). ⚠ = agent-cited, re-verify
  at fix time.
- **Multi-AI cross-check done for Part 4:** Antigravity (17) + Codex (11) ran the same audit
  (`FINDINGS-antigravity.md`, `FINDINGS-codex.md`); all 7 inter-model conflicts resolved by
  verification; everything consolidated into FINDINGS.md (~30 findings, source-tagged C/A/X). Pattern
  for remaining units: Claude audit → AG + Codex passes → resolve conflicts → consolidate.
- **Next (no fixes):** P4-GENERAL (§5.1–5.3), then P6-BIN/JSON/TCP, P3-NODES, P2-SEC, P5/P8/P11/P12/P14
  — each via the 3-AI pattern.
