# Certification-Readiness Assessment — async-opcua

**Date:** 2026-06-23
**Scope of this assessment:** the claimed conformance surface — the **Standard UA Server**
(Core + Behaviour) and **Embedded UA Server** profiles, plus everything advertised in
`docs/compatibility.md` and `docs/advanced_compliance.md`. opc.tcp binary transport, RSA +
ECC security policies. PubSub and JSON transport are out of base-profile scope.

> **Bottom line:** the behavioural-conformance core is in good shape. The structured
> multi-AI audit found and **fixed 24 distinct conformance defects** (across 21 register
> rows); the remaining open findings are, with the analysis below, **either not
> base-profile-CTT-blocking, opt-in/off-by-default surface, or separate-profile facets.**
> The one true gate left before *applying* is **an actual UACTT run against a registered
> test lab profile** — a process/logistics step, not a known code defect. See "Real gaps to
> applying" below.

---

## 1. What the audit covered

A structured, spec-anchored audit of Parts 2/3/4/5/6/8 (Part 11/12/14 by reference),
cross-checked through three independent AIs (Claude/Antigravity/Codex), consolidated into
`FINDINGS.md` (67 register rows, source-tagged C/A/X, severity S1–S3, verify ✅/⚠). Every
fix was **red-first tested** (failing test → fix → green), and each shipped through the fork's
full upstream CI (build matrix, 4 clippy legs, codegen, coverage, external-server interop).

## 2. Fixed & merged (24 defects / PRs #61, #64, #63, #66, #67, #68)

**Security (Part 2 / Part 4 §6.1):**
- P2-SEC-01/02 — OpenSecureChannel (Issue **and** Renew) now runs §6.1.3 application-instance
  certificate trust validation (chain/validity/usage/revocation/trust-list) → `BadSecurityChecksFailed`.

**Encoding / transport robustness (Part 6) — DoS & interop:**
- P6-JSON-01 (**S1**) — bounded `Vec<T>` JSON array decode (was unbounded alloc / OOM).
- P6-BIN-01 — Boolean decode treats any non-zero as true (was `== 1`).
- P6-BIN-02 — reserved Variant built-in type IDs 26–31 decode as ByteString (was stream-desync / error).

**Attributes & NumericRange (Part 4 §5.11):**
- P4-ATTR-01 (keystone) — malformed `indexRange` → per-op `Bad_IndexRangeInvalid` (was whole-message
  `BadDecodingError`); one codec fix cleared Read/Write/Query.

**View (Part 4 §5.9):** P4-VIEW-01 (invalid `referenceTypeId` → `Bad_ReferenceTypeIdInvalid`),
P4-VIEW-03 (BrowseNext release returns empty results), P4-VIEW-04 (RegisterNodes echoes all nodes).

**Session/Method/Query/Discovery (Part 4):** P4-SESS-01 (Cancel implemented),
P4-METHOD-01 (Executable attr checked), P4-METHOD-02 (no outputArguments when status Bad),
P4-QUERY-01 (typeDefinition validated), P4-DISC-01 (RegisterServer field validation).

**Subscriptions & MonitoredItems (Part 4 §5.13/§5.14) — the CTT-heavy facet:**
- P4-SUB-01 — Normal4/5 publish-guard fix.
- P4-SUB-02 — TransferSubscriptions issues `Good_SubscriptionTransferred` to the old session.
- P4-SUB-03 — `EventQueueOverflowEventType` placed on event-queue overflow.
- P4-MONITEM-01/02 — Create/Modify reject `TimestampsToReturn::Invalid`.

**Information model (Part 5):** P5-01 (ServerCapabilities.LocaleIdArray), P5-02 (MinSupportedSampleRate as Double).

## 3. Verified NOT bugs (verify-before-fix caught false positives)

P4-VIEW-02 (null targetName already rejected), P4-SESS-02 (spec mandates only the clientNonce
min-length check, already enforced), P6-TCP-01 (both-zero chunk/message-size config is rejected by
server validation, so the effective-limit-of-1 fallback is unreachable).

## 4. Remaining open findings — triaged by base-profile CTT impact

### 4a. NOT base-profile-CTT-blocking — opt-in / off-by-default surface
The NodeManagement (AddNodes/Delete*) service set is gated by `clients_can_modify_address_space`
(**default OFF**); a base server never exposes it to the CTT.
- **P3-01** (ValueRank setter validation), **P3-03** (abstract-type instantiation), **P3-05**
  (symmetric + InverseName), **P3-02/04/06/07** (ArrayDimensions/abstract-ref/HasTypeDefinition/refinement),
  **P4-NODEMGMT-01/02** (AddNodes validation cluster, delete-ref stub).
  → Fix for API-correctness when address-space write is enabled; not gating base certification.

### 4b. NOT opc.tcp-CTT — PubSub-JSON transport (separate profile)
- **P6-JSON-02/03/04/05** (Int64-as-string, NodeId/Variant 1.05 string forms, ExtensionObject UaBody).
  → Only exercised by the JSON/PubSub facets, not the opc.tcp binary CTT this profile certifies against.

### 4c. Best-effort / optional by spec — returning less is conformant
- **P4-GEN-01** (`returnDiagnostics`): Part 4 §5.2.1 — the server returns diagnostics *if available*;
  returning empty is permitted. Not a conformance failure.
- **P4-ATTR-02/03/04** (maxAge, write-locale semantics, range validation) — permitted latitude.

### 4d. Separate facet / non-mandatory
- **P4-ATTR-05** (HistoryRead NEITHER) — Historical Access facet, not base Server.
- **P2-SEC-03** (AuditCertificate* events) — auditing facet (known 013 deferral).
- **P8-01/02, P5-03/04** (DataAccess/info-model niceties) — ⚠ unverified, low risk.

### 4e. Worth doing, plausibly CTT-relevant (recommended next, none known-blocking)
- **P4-GEN-02** (S3) — enforce the client's `MaxResponseMessageSize` (server already bounds by its own
  `max_message_size`; client-hint enforcement is the gap).
- **P4-GEN-03** (S3) — apply requested locales to session-service `LocalizedText`, not just Discovery.
- **P4-MONITEM-03** (S2) — strict-decode of an invalid MonitoringMode (needs codec/codegen work; the
  enum currently defaults unknown→Disabled). Deferred-infra class.
- **⚠ verify-first** rows (P4-SESS-03/04/06/08, P4-DISC-02/03, P6-BIN-03, P6-TCP-02/03/04/05, P2-SEC-04):
  agent-cited, not yet code-verified; re-check before any fix.

## 5. Real gaps to *applying* for certification (process, not code)

1. **Run the UACTT** against the claimed profiles. The harness exists (feature 020:
   `tools/` CTT run guide + CI conformance smoke covering the full policy × mode × token matrix,
   RSA + ECC; demo-server `--ecc`). A clean UACTT pass on a certified test-lab setup is the
   actual evidence required — this audit complements it but does not replace it.
2. **FindServersOnNetwork** is deliberately deferred (needs mDNS = new dependency/infra); the
   `FindServersOnNetwork` facet cannot be claimed until that lands. `FindServers`/`RegisterServer`
   are implemented (feature 024).
3. **Live multi-stack interop** (.NET / open62541) for the PubSub secured-message path remains a gap
   (feature 026) — relevant only if PubSub conformance is claimed.

## 6. Verdict

For the **Standard UA Server (Core + Behaviour)** and **Embedded UA Server** profiles over
opc.tcp with RSA + ECC: **no remaining open finding is a known base-profile-CTT blocker.** The
behavioural core (security handshake/trust, session, subscription/monitored-item lifecycle, view,
method, attribute encoding, transport robustness) is conformant and regression-tested. The
recommended pre-application steps are the **P4-GEN-02/03** polish items and, decisively, an
**actual UACTT run** to convert this code-level confidence into lab evidence.
