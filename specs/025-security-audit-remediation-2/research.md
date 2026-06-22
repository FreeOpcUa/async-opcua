# Research: Security Audit Remediation (round 2)

Per-finding fix decision. All findings confirmed in code (file:line in plan.md). Each fix: minimal,
fail-closed, with a Claude fail-before/pass-after test. Judgment calls are explicit.

## US1 — certificate validation
- **Fail-open usage**: make KeyUsage/EKU/BasicConstraints absence fail-closed **per the OPC UA
  application-instance-cert profile** (Part 6 §6.2.2), NOT generic X.509 — i.e. require what OPC UA
  requires for app-instance certs; do NOT over-tighten and reject valid OPC UA certs. **Guard:** Claude's
  tests must include the repo's existing valid fixture certs still passing (no false-reject regression).
- **pathLenConstraint**: enforce it during chain walk (reject when exceeded). Minimal.
- **trust_unknown_certs sig-skip**: `verify_chain_signatures` must not `continue` past an unverified
  non-self-signed cert; a self-anchored non-self-signed leaf must have its signature verified or be
  rejected. Fix the misleading comment. (Smallest correct change to the verify loop.)
- **Revocation** — JUDGMENT: do NOT silently flip `Lenient`→`Strict` (would break deployments without
  CRLs). Instead: (a) FIX the real bug — make CRL-issuer + serial matching robust (compare DER/structural
  identity, not lossy `to_string()` / `as_bytes()`); (b) ensure `Strict` mode genuinely fails closed; (c)
  DOCUMENT that Strict is the secure posture. Default unchanged unless trivially safe.

## US2 — OAuth2 / JWT
- **Issuer pinning**: add a server config field for the OAuth2 issuer signing certificate (path), and
  `verify_signature` accepts ONLY that issuer cert — not "any file in the channel trust dir". Smallest
  diff: a configured issuer cert/key, fail closed if the token doesn't verify against it.
- **Required issuer/audience**: when issued-token auth is enabled, unset `oauth2_issuer`/`oauth2_audience`
  → validation fails closed (reject), no hardcoded-default acceptance. Documented behavior change (only
  affects misconfigured OAuth deployments).

## US3 — PubSub
- **Per-message IV** (CONFIRMED real): derive the IV per message per Part 14 (e.g. from the
  MessageNonce / sequence, not the static `key_nonce[..block]`). Sender writes a per-message nonce;
  receiver derives the same IV. Smallest correct change to `keys()`/encrypt/decrypt to thread a
  per-message nonce. **Guard:** round-trip test (encrypt→decrypt) still works AND two messages get
  distinct IVs.
- **Replay**: subscriber must reject a sequence_number it has already accepted (monotonic / bounded
  window). Minimal per-writer last-seen-sequence check.
- **decrypt-then-MAC** — JUDGMENT: verify against Part 14 (OPC UA symmetric signs the message;
  confirm whether the signature covers the encrypted bytes). Fix ONLY if it's a real exposure with a
  contained change; otherwise document the construction. The IV + replay fixes are the priority.

## US4 — Safety SPDU
- **Sequence window**: replace strict `seq == expected` with a bounded forward window (accept
  expected..expected+N, reject already-seen / too-far), handle first-packet (no prior expected) and
  explicit wraparound (don't silently `wrapping_add`-accept a replay). Minimal state: last-accepted seq +
  a small window constant.
- **Timeout**: bound future-dated timestamps (a timestamp ahead of now beyond max_delay is stale/invalid,
  not zero-delay-fresh).
- **CRC** — DOCUMENT ONLY: add a doc comment that the unkeyed CRC-32C is the OPC UA Safety black-channel
  integrity check (authentication is the secure channel's job). No code change.

## US5 — decoder + audit
- **Eager alloc**: `with_capacity(capped_len)` → reserve incrementally or cap the initial reservation to
  a small constant (e.g. min(len, 4096)); the loop still bounds total. Apply to `encoding.rs:627` +
  `variant/mod.rs:425`. Behavior identical, allocation bounded by actual elements read.
- **Audit success**: emit AuditActivateSession (and CreateSession) success events where the `// TODO:
  Audit` markers are; reuse the existing audit dispatch. Completeness only.

## Verification anchoring
Each finding → a Claude test that FAILS on current code and PASSES after the fix (characterization),
anchored to the threat model: crafted cert (absent ext / non-self-signed anchor / pathlen / revoked +
mismatched-encoding CRL), forged JWT (non-issuer trusted cert; unset config), PubSub (two-message IV
distinctness + replay reject + round-trip), SPDU (reorder/drop/wrap/future-timestamp), decode (small
message claiming max len), audit (success event emitted). Valid inputs must still pass (no false reject).
