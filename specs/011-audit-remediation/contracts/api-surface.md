# Public Surface Changes: Audit Remediation

This is a library + configurable server; the "contracts" are the public config schema and any
public API touched. All changes are additive or fail-closed; no breaking removal except the latent,
zero-caller `read_bytes` (pending confirmation).

## Configuration schema (server `Limits` / `DecodingOptions`)

Additive fields (serde `#[serde(default)]`, so existing configs keep parsing):

- `limits.subscriptions.max_notifications_per_publish`: default changes `0` → bounded non-zero.
  **Behavior change**: a config relying on `0`-means-unlimited now gets a bound; documented in
  release notes and `deploy-profiles.md`.
- PubSub decode limits (names per data-model): `max_dataset_fields`, `max_dataset_messages`,
  `max_secured_payload_len` — new, defaulted to accept conformant traffic.
- Config validation: `max_chunk_count == 0 && max_message_size == 0` is now **rejected** at load
  (previously accepted → unbounded). Fail-closed.

## Behavioral contracts (no signature change)

- `HistoryRead`/`HistoryReadNext` (`read_raw_modified`): same request/response wire contract;
  continuation tokens remain opaque to clients. Internal representation changes only.
- `ActivateSession`: same wire contract; adds a fail-closed rejection
  (`BadNonceInvalid`/`BadSessionIdInvalid`) for the stale-nonce race. Legitimate activation and
  secured-policy transfer unchanged.

## Public API

- `MessageHeader::read_bytes` (async-opcua-core): either gains `max_message_size` enforcement
  (same signature) or is **removed** (zero callers in-tree). If removed, note as a (theoretical)
  breaking change for external callers in release notes; prefer enforcement if any external use is
  plausible.

## Invariants preserved (verified by tests)

- Wire byte-identity on notification/response/republish paths (existing 98-test integration suite +
  byte-equality checks).
- Generated code untouched (`verify-clean-codegen`).
- `cargo clippy --all-targets --all-features -- -D warnings` clean.
