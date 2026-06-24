# Unified multi-AI test protocol for async-opcua

Three independent models cross-checked the test coverage from their own perspective — Claude (the
running campaign), Codex (gpt-5.5, `codex/SUITE.md` + candidate code), and Antigravity (Gemini 3.5,
`antigravity.md`). The premise: different models surface materially different cases; the union beats
any one. This merges them into one prioritized backlog.

## Cross-check self-corrections (proposed as gaps, but ALREADY covered)
Cross-referencing the proposals against the existing suite caught two stale "gaps" — useful in
itself (it confirms the coverage and avoids redundant work):
- **TransferSubscriptions old-session StatusChangeNotification** (Antigravity #5, citing AUDIT.md) —
  already covered by `transfer_subscriptions_notifies_old_session`.
- **EventQueueOverflowEventType** (Antigravity #8, citing 029 Gap D) — already covered by
  `event_queue_overflow_inserts_overflow_event` (SelectClause-filtering expansion still optional).

## Tier A — potential REAL BUGS (probe first; this is where the cross-check pays off)
| # | Case | Source | Why high-signal |
|---|------|--------|-----------------|
| A1 | **Stale EURange on Percent deadband** — `monitored_item.rs` caches `eu_range` at create; rewriting the variable's EURange node mid-life isn't picked up | Antigravity #6 | Cites a specific line; clear "cached-and-never-refreshed" smell; real SCADA op |
| A2 | **MonitoredItem on a deleted node** (writable address space) → must emit Bad_NodeIdUnknown, not panic | Antigravity #7 | unwrap-on-missing-node panic / DoS risk |
| A3 | **Circular hierarchical references** via AddNodes → recursive Browse/Translate stack overflow | Antigravity #10 | unbounded recursion → remote DoS panic |
| A4 | **Identity-token signature / policyId / empty-secret edges** (X509 user-sig tamper; username wrong policyId / empty / null password) | Codex P1 + Antigravity #3 | **convergent**; auth-bypass class if verified against wrong key |

## Tier B — novel adversarial transport (cheap on the existing MITM platform)
| # | Case | Source |
|---|------|--------|
| B1 | **SecureChannelId confusion** — rewrite bytes 8..12 of a valid MSG to name a different channel | Codex P0 |
| B2 | **Abort chunk** (`A`) mid-request → clean abandon + server health | Codex P0 |
| B3 | **Chunk reorder / duplicate / fragmented reassembly** of a large multi-chunk Write | Codex (impl) + Antigravity #11 (**convergent**) |
| B4 | **SecureChannel renewal token overlap** — old+new SecurityTokenId valid during grace, old rejected after | Antigravity #1 |
| B5 | **Slow-loris half-open handshake** — dribbled OPN / many half-open conns must time out | Antigravity #4 |
| B6 | **Cross-channel session hijack** — ActivateSession for session-A's token over channel B (cert B) rejected | Antigravity #2 (verify vs feature 014 binding) |

## Tier C — novel functional / conformance coverage
| # | Case | Source |
|---|------|--------|
| C1 | **SetTriggering** positive delivery + link removal (trigger Reporting item drives a linked Sampling item) | Codex P0 ×2 |
| C2 | **DataChange queue overflow** observed end-to-end via raw Publish (overflow info bit on oldest retained) | Codex P0 |
| C3 | **Sampling→Reporting** transition queue semantics (no stale create-value) | Codex P1 |
| C4 | **Structured ExtensionObject** binary round-trip matrix (null/empty arrays, nested DiagnosticInfo, null LocalizedText) | Codex P1 |
| C5 | **NumericRange OOB / rank-mismatch** on multi-dim arrays (explicit cases on top of feature-017 fuzzing) | Antigravity #9 |
| C6 | **Concurrent RegisterServer** online/offline race → no duplicate/half-deleted FindServers entries | Codex P2 |
| C7 | **AddNodes mixed-batch** rollback / reference consistency (one good, one bad-type, one dependent) | Codex P2 |

## Execution order
1. **Tier A** first — these are the ones that might be real defects (the whole point of the cross-check). Probe A1/A2/A3 with red-first tests; if green, lock them in; if red, fix.
2. **Tier B** next — fast to add on the `adversarial.rs` MITM harness; each asserts "rejected + server survives."
3. **Tier C** for breadth.

Candidate code from Codex lives under `codex/` (SetTriggering, SecureChannelId/abort, datachange overflow, node-opcua subscription edges) — review and adapt rather than wire in as-is.
