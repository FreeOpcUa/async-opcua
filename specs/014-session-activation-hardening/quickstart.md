# Quickstart / Verification: Session-Activation Hardening (Part 4 §5.6)

All commands from the workspace root. Tests are authored and run by Claude (verification division).

## Baseline gate (before any change)

```bash
cargo fmt --all --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test -p async-opcua-server
cargo test -p async-opcua --test integration_tests   # loopback regression (note pre-existing flakiness)
```

## US1 — client certificate ↔ channel binding at ActivateSession (FR-001)

Server `manager.rs` unit tests (`session/manager.rs` test module):
- ActivateSession where the session's CreateSession client cert == the channel's peer cert → **activates**.
- ActivateSession where they differ → `Bad_SecurityChecksFailed`.
- `None` policy → no cert-binding check; unchanged.
- Missing/malformed certificate on either side → rejected, **no panic**.

## US2 — conformance lock-in (FR-005)

- Integration (loopback) test: activate a secured session on channel A, then issue a session service
  (e.g. Read/Browse) on a second channel B → `Bad_SecureChannelIdInvalid`.
- CreateSession with an `endpointUrl` host not advertised and not in the server cert SAN →
  rejected (`Bad_CertificateHostNameInvalid` / `Bad_TcpEndpointUrlInvalid`).
- Malformed/oversized/truncated CreateSession & ActivateSession fields → rejected, no panic
  (negative tests; optionally extend a fuzz target later).

## Backward-compat / regression

- Existing self-signed RSA + ECC loopback connect/activate/use flows unchanged across all policies.
- `None` security policy path byte-identical.
- `activate_session_rejects_stale_nonce_after_intervening_activation` and `cross_channel_transfer_rules`
  still pass.

## Final gate (per story)

```bash
cargo fmt --all --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test -p async-opcua-server && cargo test -p async-opcua --test integration_tests
```
One commit per story; coding to codex; tests authored + run by Claude.
