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

## Status
- **Tier A — DONE** (`async-opcua/tests/integration/tier_a.rs`). Probed all four; none was a crash/bypass.
  A2/A3/A4 locked in as regression tests; A1 confirmed (deliberate EURange cache) and documented at the
  `eu_range` field in `subscriptions/monitored_item.rs` — no live-refresh fix (would be a redesign).
  A4 X509 user-token-signature tamper (`adversarial.rs`, rejected `BadSecurityChecksFailed: Signature
  mismatch`) added once the MITM harness made it cheap. Still deferred: A1 live-refresh; A4 wrong-policyId
  (client auto-picks the policyId — needs raw request construction, marginal over the audit + tamper test).
- **Tier B — DONE.** B1/B2/B6 (`adversarial.rs` / `hardening.rs`); B3 duplicated-reassembly-chunk
  (`adversarial.rs`, rejected `BadSequenceNumberInvalid`); B4 renewal token-grace
  (`async-opcua-core/.../secure_channel.rs` unit tests — overlap kept, expired pruned); B5 slow-loris
  half-open handshake (`adversarial.rs`, `hello_timeout`).
- **Tier C** — in progress (one PR per item). C1 SetTriggering DONE (`triggering.rs`): positive
  delivery + link removal; confirmed the linked Sampling item's queue also holds its initial sample
  (the stale-create-value question is C3's scope). C2 DataChange queue overflow DONE
  (`datachange_overflow.rs`): oldest retained value carries the Overflow bit; no server bug — the
  candidate's sampling_interval=0.0 coalesces writes (maps to "use subscription interval"), so the test
  uses the 100 ms minimum + spaced writes. C3 Sampling→Reporting transition DONE
  (`sampling_transition.rs`): a Sampling item accumulates samples; on transition to Reporting the queue
  is flushed in order (initial create-value then the change) — `set_monitoring_mode` doesn't clear the
  queue; no stale/duplicated value, none lost; no server bug. C4 ExtensionObject round-trip DONE
  (`async-opcua-types/.../tests/encoding.rs`): structured EO (EUInformation/Argument) + nested
  DiagnosticInfo + LocalizedText edges round-trip. Spec-checked both normalizations against the PDFs:
  empty-string LocalizedText locale/text → null is spec-correct (Part 6 Table 24); but Argument None
  array_dimensions → Some([]) was a DEVIATION — Part 3 Table 28 says ArrayDimensions "shall be null if
  valueRank <= 0" — so FIXED the Argument encode (emit null, not empty) + normalize on decode; scalar
  Argument now round-trips None→None. C5 NumericRange fewer-dims DONE + FIXED
  (`async-opcua-types/.../variant/mod.rs`): a single Index/Range against a multi-dimensional array was
  flattened into a 1-D slice instead of being rejected; Part 4 §7.27 says "all dimensions shall be
  specified", so it now returns BadIndexRangeNoData. (Read/write OOB, rank-mismatch-too-many,
  oversized-clamp were already covered by feature-017.) C6 concurrent RegisterServer DONE (`info.rs`):
  the registry is an RwLock<HashMap> keyed by URI, so concurrent online/offline leaves no
  duplicate/half-deleted entries; lock-in, no bug. C7 remains. (Separately, the interop subscription
  check was de-flaked in PR #110 — client-driven writes instead of CurrentTime's server timer.)

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
