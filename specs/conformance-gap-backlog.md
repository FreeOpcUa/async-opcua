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

**CTT harness shipped (feature 020):** a Linux/CI **conformance smoke**
(`async-opcua/tests/integration/conformance.rs`) now drives our server with our client across the full
(security policy × mode × identity-token) matrix — RSA + ECC — on every change (a regression proxy, not
an independent authority). The demo-server gained a separate **ECC profile** (`sample.server.ecc.conf` +
`--ecc` EC-cert provisioning; the RSA profile already covers None + the full RSA matrix with all token
types). For the authoritative pass on Windows, see **`docs/ctt-conformance.md`** (run guide,
cross-trust, `run-conformance.sh`, and an expected-results/known-gaps table mapping the Tier 3 facets
below that fail by design).

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

## Tier 1 — Security / PKI conformance

| # | Gap | Spec | Confirmed? | Notes |
|---|-----|------|-----------|-------|
| 1 | ✅ **DONE (feature 013 + later OCSP work)** — certificate validation builds/verifies CA chains, enforces usage and security-policy checks, validates CRLs, and validates supplied/stapled OCSP responses. | Part 2 §6.1.3, Part 4 §6.1.3 | ✅ verified | Remaining scope is operational/live OCSP fetching or responder infrastructure, not the core validation engine. |
| 2 | ✅ **DONE (feature 014)** — ActivateSession binds the client certificate to the secure channel and endpoint-host behavior is locked by regression tests. | Part 4 §5.6, §6.1.3 | ✅ verified | Deferred only: stricter same-channel re-activation policy and any client-side ergonomics. |
| 3 | ✅ **DONE (feature 016)** — ECC `EccEncryptedSecret` identity-token secrets are supported for username/issued-token paths. | Part 4 §7.40.2.5 / Part 6 §6.8.3 | ✅ verified | Remaining optional variants: RSA-DH / authenticated-encryption forms if a target profile requires them. |

## Tier 2 — Encoding / Part 6 edge conformance (medium; binary-vector testable)

| # | Gap | Spec | Notes |
|---|-----|------|-------|
| 4 | ✅ **DONE (feature 017, PR #46)** — **NumericRange** multi-dimensional read (`range_of`) + write (`set_range_of`) per **Part 4 §7.27** (the backlog's "Part 6 §6.9" was wrong). Comma = dimension (not disjoint ranges); row-major sub-array; exact-size write; string/bytestring arrays as 2-D substring. Fuzz found + fixed 2 remote-panic DoS bugs (`UAString::substring` UTF-8 byte-slice; extent underflow). | Part 4 §7.27 | Complete. |
| 5 | ✅ **DONE (feature 018, PR #47)** — **JSON encoding edges**. Real fix: XML-ExtensionObject inside JSON now **fails closed** (decoding error, not a silent null) when the `xml` feature is off. The other two claims were **STALE**: DataValue `SourcePicoseconds`/`ServerPicoseconds` already round-trip, and `Variant::XmlElement` already round-trips (`{"Type":16,"Body":...}`) — both now locked by tests (the `todo!()` is removed). | Part 6 §5.4 | Complete. |
| 5b | ✅ **DONE (feature 019, PR #48)** — **JSON DateTime full precision**: the JSON encoder now emits lossless fractional seconds (`SecondsFormat::AutoSi`) so 100-ns-tick precision round-trips (§5.4.2.6). JSON-only scope; `to_rfc3339()`/XML/`Display`/binary unchanged. | Part 6 §5.4.2.6 | Complete. |

## Tier 3 — Optional facets (only if you target them; NOT base/embedded violations)

| # | Gap | Facet | Notes |
|---|-----|-------|-------|
| 6 | ✅ **DONE (feature 022)** — **Writable address space / Node Management**: the in-memory node manager now implements AddNodes/DeleteNodes/AddReferences/DeleteReferences (Object+Variable node classes), gated by the new opt-in `clients_can_modify_address_space` config flag (default OFF = read-only, unchanged). Part 4 §5.7 status codes; additive (CoreNodeManager/overrides untouched). Deferred: GeneralModelChangeEventType emission, persistence, full 9-node-class AddNodes, server-assigned (null) ids on the default (use `handle_new_node` to opt in). | NodeManagement | Opt-in per node manager. |
| 7 | ✅ **DONE (feature 023)** — **Query**: the prior "CoreNodeManager doesn't implement Query" was STALE — `InMemoryNodeManager::query` → QueryFirst/QueryNext handlers, used by CoreNodeManager, already work (verified: 67 FolderType nodes, pagination w/o loss, continuation release). The real gap was the missing CLIENT API, now added (`Session::query_first`/`query_next`) with first end-to-end coverage. Confirmed: non-default `view` → `BadViewIdUnknown`. | Query | Client API + e2e tests; server already worked. |
| 8 | ✅ **DONE (features 024 + 036)** — **RegisterServer / RegisterServer2**: implemented with a bounded in-memory LDS registry on ServerInfo; FindServers returns registered (online) servers; RegisterServer2 mDNS discovery configurations are honored when `discovery-mdns` is compiled and multicast discovery is opted in, otherwise the per-config result remains `BadNotSupported` while registration still succeeds. **FindServersOnNetwork / LDS-ME mDNS**: implemented behind the off-by-default `discovery-mdns` feature, merging pull-based registrations with multicast-discovered servers and capability filtering discovered records. | LDS registration + LDS-ME multicast | Done; mDNS remains opt-in and dependency-gated. |
| 9 | ✅ **Method Call DONE (feature 021)**; ✅ **Audit hierarchy DONE** — typed method callbacks are implemented and the Audit*EventType hierarchy now covers certificate/session/channel/cancel/write/method/node-management paths. | Methods / Auditing | Complete for the implemented service surface; exact CTT auditing claims still depend on the server profile being asserted. |

---

## Recommendation
- Treat the original prose-scanned conformance gaps above as mostly closed; the current highest-value
  conformance work is to run the demo server against the OPC Foundation **CTT** and promote behavioral
  failures into focused Spec Kit features.
- Existing live follow-ups are narrower: reliable notification-delivery edge tests (feature 029),
  embedded-profile build aliases/example, live third-party PubSub CTR interop, and operational OCSP
  fetching/responder infrastructure if a deployment requires online revocation.

Each item → one speckit feature, ECC-style: extract the normative SHALL/MUST → check impl → fix →
independent tests anchored to spec text / official vectors / crafted PKI fixtures.

## Security audit remediation round 2 outcome (feature 025, 2026-06-22)
Verify-before-fix triaged the 2026-06-22 review findings. Result:
- **FIXED (real): OAuth2/JWT** — issuer pinning (was: any trusted cert verified a JWT → confused deputy)
  + require explicit oauth2_issuer/audience/issuer_certificate_path, fail closed (was: hardcoded
  defaults). PR for feature 025.
- **DONE (feature 026): PubSub Part-14 message security** — the round-2 finding was framed as "the
  secured path is AES-CBC with a static IV; add a MessageNonce", but the secured path was an entirely
  proprietary `OPCUAPS1` envelope (not Part-14 at all). Feature 026 replaced it with the full OPC UA
  Part 14 §7.2.4.4 secured-NetworkMessage format: new `PubSub-Aes128-CTR`/`PubSub-Aes256-CTR` crypto
  policies (AES-CTR via `ctr::Ctr32BE`), the real SecurityHeader (SecurityFlags/SecurityTokenId/
  MessageNonce), per-message nonce → unique AES-CTR IV (kills the IND-CPA reuse), HMAC-SHA256 over the
  whole message (encrypt-then-MAC, verify-then-decrypt), SecurityTokenId key selection (fail closed),
  and a bounded subscriber anti-replay window. Verified with spec-anchored KAT vectors (Tables 155-157)
  + an independent-implementation interop cross-check (both directions). REMAINING GAP: live
  third-party interop (OPC Foundation .NET / open62541 PubSub-CTR) is not runnable in this CI — the
  .NET interop harness is plaintext UADP only; tracked as a future verification task.
- **NO FIX — verified false-positive: cert validation** — KeyUsage/EKU/BasicConstraints "fail-open when
  absent" is RFC-5280-correct + tested (`leaf_without_key_usage_extension_is_accepted`); usage enforced
  when present; sigs + CRL sigs verified; revocation modes intentional. The review agent applied generic
  X.509 strictness to an OPC-UA-profile impl. (Open minor checks: BasicConstraints pathLen, the
  trust_unknown_certs 1-element-chain sig path — backlog, low priority.)
- **NO FIX — fail-safe-by-design: Safety SPDU** — strict reject-on-sequence-gap is the SAFE behavior for
  a SIL-3 channel; a tolerant window would be a safety regression. Gap recovery is a deferred Part-15
  re-sync handshake (a feature), not a fix. Documented in validator.rs. CRC = black-channel (unkeyed,
  per-spec), documented.
- **NO FIX — bounded/completeness: decoder + audit** — eager `with_capacity` is bounded by
  MAX_ARRAY_LENGTH=1000 (≤tens of KB, + max_message_size) — not a meaningful amplification. Audit: auth
  FAILURES are already emitted; success/extra-event auditing is OPC-UA completeness, not a security hole
  (deferred).
