# OPC UA conformance gap backlog (scoping pass)

**Scope:** core stack only — Parts 2 (Security), 3 (Address Space), 4 (Services), 6 (Mappings),
8 (DataAccess). The ~130 companion/transport specs (PROFINET, IO-Link, Devices, UAFX, DEXPI, …) are
out of scope; async-opcua deliberately doesn't implement them.

**Method:** read-only cross-reference of `docs/compatibility.md` + `docs/advanced_compliance.md` +
`TODO.md` + the code (no deep PDF reading). Findings calibrated by spot-checking the code.

**The real arbiter:** the OPC Foundation **CTT** (Compliance Test Tool) + the Part 7 profile/facet DB —
not prose. `samples/demo-server` exists for exactly this. Running demo-server against the CTT would
surface *behavioral* gaps (status codes, edge cases) this prose-scan cannot. **Strongly recommended if
CTT is available** — it would re-rank this backlog with hard data.

**Targeted profiles:** `Server/Behaviour` + `EmbeddedUA`. Several "gaps" below are *optional facets*,
not base-profile violations — flagged as such.

---

## Already done (stale-doc correction — do NOT re-investigate)
`advanced_compliance.md` shows the repo is **more complete** than `TODO.md` implies:
- **Modern encrypted identity-token secrets** (RSA-OAEP) on ActivateSession — not just legacy. ✅
- **EventFilter** (SelectClauses + WhereClause content filter) ✅ · **PubSub GetSecurityKeys** ✅
- **Query** service (QueryFirst/QueryNext) implemented ✅ (see Tier 3 for the CoreNodeManager caveat)
- ECC policies (this project), sequence-number legacy/non-legacy, decoder DoS hardening ✅

---

## Tier 1 — Security / PKI conformance (highest value, CONFIRMED real)

| # | Gap | Spec | Confirmed? | Notes |
|---|-----|------|-----------|-------|
| 1 | **Certificate validation is trust-list (leaf-pinning) only** — no CA **chain** walk, no **CRL/OCSP revocation**, no **KeyUsage**/BasicConstraints check (`certificate_store.rs`, `x509.rs`). | Part 2 §6.1.3, Part 4 §6.1.3 | ✅ verified | Leaf-pinning IS a valid, secure model for closed deployments; this is about supporting the **full PKI/CA + revocation** model the spec defines. Cohesive subsystem. **Best first feature.** |
| 2 | **Session-activation hardening TODOs** — endpoint-URL not checked against server-cert hostname (`manager.rs:213`); client-cert / user-token not bound to the secure channel (`manager.rs:593`). | Part 4 §5.6, §6.1.3 | ✅ TODOs in code | Real, security-relevant (confused-deputy / token reuse). Small, targeted. |
| 3 | **ECC-encrypted identity-token secrets** — secret encryption supports RSA only; no ECC path now that ECC policies exist. | Part 4 §7.41.2.3 | ✅ | Natural follow-on to the ECC work; medium. |

## Tier 2 — Encoding / Part 6 edge conformance (medium; binary-vector testable)

| # | Gap | Spec | Notes |
|---|-----|------|-------|
| 4 | **NumericRange**: multiple disjoint ranges (`[0:2,5:7]`) rejected with `BadIndexRangeNoData`; multi-dimensional `set_range_of` incomplete (`variant/mod.rs:~1485,1539`). | Part 6 §6.9 | Confirmed partial. Clean, self-contained. |
| 5 | **JSON encoding edges**: XmlElement-in-Variant untested (`todo!()` in test); DataValue picoseconds not round-tripped; **XML-ExtensionObject inside JSON silently drops to null** when `xml` feature off (should error). | Part 6 §5.4 | JSON is opt-in / less used than binary → lower impact, but the silent-drop should at least error. |

## Tier 3 — Optional facets (only if you target them; NOT base/embedded violations)

| # | Gap | Facet | Notes |
|---|-----|-------|-------|
| 6 | Writable address space / **Node Management** (AddNodes/Write/Delete) — CoreNodeManager is read-only by design; defaults return `BadServiceUnsupported`. | NodeManagement | Architectural opt-in per node manager. |
| 7 | **Query over CoreNodeManager** — service works, but CoreNodeManager doesn't implement `QueryProvider`, and non-default `view` is rejected (`BadViewIdUnknown`). | Query | Service framework is there; the standard address space just isn't queryable. |
| 8 | **Discovery LDS** stubs — FindServersOnNetwork / RegisterServer / RegisterServer2 → `BadServiceUnsupported`. | LDS registration | Not required by base/embedded; needed for LDS integration. |
| 9 | **Method Call** on core address-space methods; **Audit events** (Part 4 §5.6) partial (non-mandatory). | Methods / Auditing | Low priority. |

---

## Recommendation
- **First speckit feature: Tier 1 #1 — Certificate-validation conformance** (CA chain + CRL revocation +
  KeyUsage). Highest security × conformance value, cohesive (`certificate_store.rs` / `x509.rs`), and
  testable with crafted cert chains/CRLs. Pairs naturally with #2 (session-activation hardening).
- **If you want a small warm-up:** Tier 2 #4 (NumericRange) — tiny, clean, vector-testable.
- **Before/instead of more prose-mining:** get demo-server in front of the **CTT**; it will produce a
  harder, behavior-driven defect list than this scan.

Each item → one speckit feature, ECC-style: extract the normative SHALL/MUST → check impl → fix →
independent tests anchored to spec text / official vectors / crafted PKI fixtures.
