# Behavior Contract: Session-Activation Hardening (Part 4 §5.6)

**No public API change.** This is an internal server-side validation addition.

## Server behavior (additive)

- `async-opcua-server` `activate_session` (`session/manager.rs`): when the negotiated security policy
  is not `None`, ActivateSession now additionally requires the session's CreateSession client
  certificate to equal the certificate that secured the activating channel
  (`SecureChannel::remote_cert()`). A mismatch is rejected with `Bad_SecurityChecksFailed`. No new
  config, no new public type, no wire-format change.
- The stale `manager.rs:213` endpoint-URL TODO comment is removed (the check it references already
  exists via `validate_endpoint_hostname`).

## Invariants preserved (verified by tests)

- `None` security policy: ActivateSession behavior byte-identical (no channel cert, check skipped).
- Conformant clients (cert presented at CreateSession == channel cert) activate unchanged.
- Activated secured session still cannot be *used* from another channel (existing
  `validate_secure_channel_id` on every request) — now covered by a regression test.
- Reconnection affordance (re-activate an activated secured session on a new channel) preserved; the
  cert-binding check then applies to the new channel's certificate.
- No panic on attacker-supplied/missing activation certificate fields; `clippy --all-targets
  --all-features` clean.
