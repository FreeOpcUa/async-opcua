# Conformance Coverage Scoreboard

A Conformance-Unit / service-area view of what the async-opcua conformance suite exercises, and with
which oracle. This is the "what does the tester actually check" map that the official UACTT produces
per Conformance Unit — here it is open, in-repo, and CI-run. It complements
[`SPEC-TRACEABILITY.md`](../multi-ai-test-suites/SPEC-TRACEABILITY.md) (which is indexed by spec
section); this file is indexed by conformance area.

**Oracle legend** — the grounding behind each check (strongest first):
- **ref-stack** — the OPC Foundation OPC UA .NET Standard reference stack (the implementation UACTT is built on)
- **interop** — an independent stack drives our server: node-opcua (JS), open62541 (C), asyncua (Python)
- **vector** — golden vectors/registry from the OPC Foundation (encoding corpus, NodeId registry) or OpenSSL
- **self** — clause-anchored test against our own implementation (no independent stack implements it, or it is internal)

Status: ✅ covered · 🟡 partial · ⬜ gap

## Service sets (Part 4)

| Conformance area | Spec | Tests | Oracle | Status |
|---|---|---|---|---|
| Discovery — GetEndpoints / FindServers | §5.4 | `discovery.rs`; all 4 interop harnesses; dotnet `DiscoveryChecks` | ref-stack + interop | ✅ |
| Discovery — RegisterServer / FindServersOnNetwork | §5.4 | `discovery.rs` | self | ✅ (registered servers + opt-in LDS-ME mDNS) |
| SecureChannel — Open/Renew across policy×mode | §5.5 | `conformance.rs` matrix; dotnet `SecurityMatrixChecks` (5 endpoints); `wss.rs`; `legacy_crypto.rs` | ref-stack + interop | ✅ |
| Session — Create/Activate/Close + identity tokens | §5.6 | `conformance.rs` token matrix; `hardening.rs` (session binding); dotnet `IdentityTokenChecks` | ref-stack + interop | ✅ |
| NodeManagement — Add/Delete Nodes/References | §5.7 | `node_management.rs` | self | ✅ (gated `clients_can_modify_address_space`) |
| View — Browse / BrowseNext / TranslateBrowsePaths / Register | §5.8 | `browse.rs`; **`walk_runner.rs`** (full crawl, op-limits, continuation points); dotnet `ViewChecks`; all interop | ref-stack + interop + self | ✅ |
| Query — QueryFirst / QueryNext | §5.9 | `query.rs` | self | ✅ |
| Attribute — Read (all datatypes, attributes, NumericRange) | §5.10.2 | `read.rs`; **`address_space_oracle.rs`** (685 type nodes vs registry); dotnet `ReadChecks` (14 scalar types); all interop | vector + ref-stack | ✅ |
| Attribute — Write (+ read-back, type mismatch) | §5.10.4 | `write.rs`; dotnet `WriteChecks` | ref-stack | ✅ |
| Attribute — HistoryRead (raw) | §5.10.3 | `hda.rs`; `read.rs::history_read_raw`; dotnet `HistoryChecks`; HistoryRead interop | ref-stack + interop | ✅ |
| Method — Call (+ error paths) | §5.11 | `methods.rs`; dotnet `MethodChecks` (NoOp/HelloWorld/Add + missing-args/unknown); interop | ref-stack + interop | ✅ |
| MonitoredItem — Create/Modify/Delete, filters, sampling | §5.12 | `subscriptions.rs`, `datachange_overflow.rs`, `sampling_transition.rs`, `triggering.rs`; dotnet (data-change + event filter) | ref-stack + interop | ✅ |
| Subscription — Create/Modify/SetPublishingMode/Publish/Republish/Transfer | §5.13 | `subscriptions.rs`; dotnet `SubscriptionChecks` | ref-stack + interop | ✅ |

## Cross-cutting conformance areas

| Conformance area | Spec | Tests | Oracle | Status |
|---|---|---|---|---|
| Encoding — Binary built-in types | Part 6 §5.2 | **`conformance_vectors.rs`** (8 types byte-identical vs ref corpus); `encoding.rs` | vector (ref corpus) | ✅ |
| Encoding — JSON / XML | Part 6 §5.3/5.4 | `tests/json.rs`, `tests/xml.rs` | self | 🟡 (cross-stack JSON/XML vectors deferred — JSON encoding variance) |
| String parsers (NodeId/ExpandedNodeId/NumericRange/Guid) | Part 6 §5.1.12 | **`conformance_vectors.rs`** parser vectors | vector (ref corpus) | ✅ (found+fixed ExpandedNodeId bug) |
| Address space / standard type system | Part 5 | **`address_space_oracle.rs`** (NodeClass+BrowseName of 685 type nodes vs NodeId registry) | vector (registry) | ✅ |
| Events & Alarms / Conditions | Part 9 | `alarms.rs`, `programs.rs`; dotnet event filter | ref-stack + self | ✅ |
| PubSub (UADP NetworkMessage) | Part 14 | `pubsub.rs`, `codec/uadp` golden vector; open62541 UADP decode | interop + self | ✅ |
| Cryptography — ECC ECDSA signatures | Part 6 §6.8 | **`ecc_signature_vectors.rs`** (P1363 + DER vs OpenSSL); `ecc.rs` | vector (OpenSSL) | ✅ |
| Cryptography — ECC key exchange / secrets | Part 6 §6.8 | `ecc_ephemeral_key.rs`, `ecc_encrypted_secret.rs` | self | ✅ |
| Certificate validation (chain/usage/CRL/OCSP) | Part 4 §6.1.3 | `cert_chain.rs` | self + vector (fixtures) | ✅ |
| HistoryRead — Processed / Aggregates | Part 13 | `aggregates_tests.rs`, `history_tests.rs` | self + vector (registry ids) | 🟡 (found+fixed NodeId bug; only TimeAverage/Min/Max/StdDevSample implemented) |
| DoS / robustness / malformed input | — | `adversarial.rs`, `hardening.rs`, `recursion_dos.rs`, `fuzz/` targets | self | ✅ |

## Independent oracles wired in (the "better than UACTT" differentiator)

- **OPC Foundation .NET Standard reference stack** — `interop/dotnet` (~65 checks); the stack UACTT is built on.
- **open62541 (C), node-opcua (JS), asyncua (Python)** — `interop/{open62541,*,asyncua}`; three more independent lineages.
- **OPC Foundation encoding fuzz corpus** — vendored binary built-in-type vectors.
- **OPC Foundation NodeId registry** — vendored `NodeIds.csv` for the address-space oracle and aggregate-id checks.
- **OpenSSL** — ECDSA P1363/DER signature known-answer vectors.
- **`opc-ua-reference` MCP** — authoritative spec text for grounding (used to confirm fixes).

## Conformance bugs found by this suite

| Bug | Found by | Fix |
|---|---|---|
| `ExpandedNodeId::from_str` rejected valid `svr`/`nsu`-optional forms | parser vectors | PR #129 |
| Aggregate engine used wrong AggregateFunction NodeIds (Count/Delta/non-nodes) | aggregate-id check vs registry | PR #131 |
| `Server_ServerArray` returned null/empty (not `String[]`) | .NET ref-stack interop | PR #125 |
| UADP NetworkMessage wire-format (PublisherId type, DataSetWriterId, Status width) | open62541 PubSub interop | PR #123 |

## Known gaps (not yet covered)

- Cross-stack **JSON/XML encoding** vectors (JSON encoding has legitimate variance → byte-equality fragile; would be round-trip-only).
- **FindServersOnNetwork** over mDNS (needs an LDS-ME; UA-LDS could serve as the counterparty).
- **Aggregates** beyond the 4 implemented (Interpolative, Count, Delta, Range, TimeAverage2, … — full Part-13 set).
- Audit events; see `SPEC-TRACEABILITY.md` for the spec-section-level gap list.
