# Implementation Plan: Security Audit Remediation (round 2)

**Branch**: `025-security-audit-remediation-2` | **Date**: 2026-06-22 | **Spec**: [spec.md](./spec.md)
**Input**: Feature specification from `/specs/025-security-audit-remediation-2/spec.md`

## Summary

Verify-then-fix the confirmed 2026-06-22 security findings, fail-closed, smallest diff (ponytail). Per
user story: US1 cert validation fail-open/sig-skip/pathlen/revocation; US2 OAuth2/JWT issuer pinning +
required config; US3 PubSub per-message IV + replay; US4 Safety SPDU sequence window/wraparound/timeout
(+ document the black-channel CRC); US5 decoder eager-alloc + success audit. codex applies the fixes
(ponytail); Claude writes a fail-before/pass-after test per finding.

## Technical Context

**Language/Version**: Rust (workspace edition 2021). **No new dependency.**
**Primary Dependencies (touched)**: async-opcua-crypto (`cert_chain.rs`, `identity/jwt_validator.rs`),
async-opcua-server (`info.rs`, `session/manager.rs|controller.rs`, `services/node_access.rs`, audit),
async-opcua-pubsub (`security/codec.rs`), async-opcua-safety (`validator.rs`), async-opcua-types
(`encoding.rs`, `variant/mod.rs`).
**Testing**: per-finding characterization tests (unit where the logic is pure: cert_chain, jwt, codec,
validator, encoding; integration for audit), authored + run by Claude; run single-threaded.
**Constraints**: fail-closed; smallest correct diff; no new dep; clippy clean on all-features +
no-default / json-off legs; existing suites pass; deliberate default changes documented.
**Scale/Scope**: ~10 fixes across 6 crates + a test per fix. Large but mechanical once grounded.

### Verified findings (read in code — grounds each fix)

- **US1 cert** (`async-opcua-crypto/src/cert_chain.rs`): `validate_leaf_certificate_usage`
  (~481) & issuer usage (~518) no-op when KeyUsage/EKU/BasicConstraints **absent** (fail-open);
  pathLenConstraint ignored. `verify_chain_signatures` (~228-248) does `None => continue` so a
  1-element chain (non-self-signed leaf made anchor via `trust_unknown_certs`) is **never signature-
  verified**; the comment claims otherwise. Revocation `RevocationMode::Lenient` default (~36) + CRL
  match by `to_string()`-DN (~628) and serial `as_bytes()` (~709) — lossy.
- **US2 oauth** (CONFIRMED): `identity/jwt_validator.rs:125` `verify_signature` iterates EVERY file in
  the trusted-certs dir and accepts if ANY verifies → no issuer pinning. `info.rs:838` defaults
  `oauth2_issuer`/`oauth2_audience` to `"opcua-issuer"`/`"opcua-server"` when unset (fail-open).
- **US3 pubsub** (CONFIRMED): `async-opcua-pubsub/src/security/codec.rs:259` IV =
  `key_set.key_nonce()[..block_size]` — STATIC per key epoch (AES-CBC IV reuse). Subscriber decode
  (~69) discards `sequence_number` (no replay check). SignAndEncrypt is decrypt-then-MAC (~151/165).
- **US4 safety** (`async-opcua-safety/src/validator.rs:40-71`): strict `seq == expected` (desync on
  reorder/loss) + silent `wrapping_add`; future-dated timestamp treated as 0 delay. CRC = unkeyed
  CRC-32C (black-channel — document, don't change).
- **US5** (`async-opcua-types/src/encoding.rs:627`, `variant/mod.rs:425`): `with_capacity(capped_len)`
  eager-reserves before reading. Audit: `session/manager.rs`/`controller.rs` `// TODO: Audit` — success
  ActivateSession/CreateSession not emitted.

## Constitution Check

- **I. Correctness Over Completion**: every fix fails closed; each is confirmed by a fail-before test;
  non-reproducing findings documented, not patched. ✅
- **IV. Security Is Paramount**: this feature IS the security hardening — pre-auth cert path + auth +
  pubsub/safety untrusted input. No validation simplified away. ✅
- **II/III. Do It Right Once / Discipline**: ponytail-minimal fixes, no new abstraction/dep; one commit
  per user story. ✅
- **V. Leave It Better**: closes the audit; documents the deliberate default changes + the black-channel
  CRC. ✅
- **Verification division**: codex fixes (ponytail), Claude writes independent fail-before/pass-after
  tests anchored to the threat model + OPC UA Parts 2/4/6/14. ✅

**Gate: PASS** — no violations. (Two deliberate default changes — revocation strictness, required OAuth2
issuer config — are documented behavior changes, not violations.)

## Project Structure

```
specs/025-security-audit-remediation-2/  spec.md plan.md research.md tasks.md contracts/ checklists/
async-opcua-crypto/src/cert_chain.rs            # US1 (codex) fail-closed usage/pathlen + sig-verify; revocation
async-opcua-crypto/src/identity/jwt_validator.rs# US2 (codex) issuer-pinned JWT verify
async-opcua-server/src/info.rs                  # US2 (codex) require oauth issuer/audience (fail closed)
async-opcua-pubsub/src/security/codec.rs        # US3 (codex) per-message IV + replay reject
async-opcua-safety/src/validator.rs             # US4 (codex) seq window/wraparound/timeout + CRC doc
async-opcua-types/src/encoding.rs, variant/mod.rs # US5 (codex) bounded reservation
async-opcua-server/src/session/{manager,controller}.rs # US5 (codex) success audit events
# Claude: a fail-before/pass-after test per finding, co-located (unit) or integration where needed.
```

**Structure decision**: fix each in place, fail-closed, minimal. Two documented default changes. No new
crate/dep. Tests are the verification gate (fail-before proves the bug; pass-after proves the fix).

## Complexity Tracking

No constitution violations; no entries. (Largest risk is breadth, not added complexity — ponytail keeps
each fix minimal.)
