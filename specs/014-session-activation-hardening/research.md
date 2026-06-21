# Research & Design Decisions: Session-Activation Hardening (Part 4 §5.6)

Source: read-only investigation of the server session code (2026-06-21), three parallel code-path
maps (CreateSession, ActivateSession, session↔channel binding). **Headline finding: most of the
§5.6 hardening this spec assumed was missing is already implemented.** The genuine remaining gap is
narrow. Scope is recalibrated below.

## What is ALREADY enforced (verified, with anchors)

- **Session↔channel binding on EVERY session-scoped request (all modes)** —
  `SessionController::validate_request` (`controller.rs:752`) calls
  `Session::validate_secure_channel_id(channel.secure_channel_id())` (`controller.rs:768` →
  `instance.rs:236`) **unconditionally** before dispatch. An activated session **cannot** be driven
  (Browse/Read/Write/Publish/…) from a different secure channel than it belongs to — for all security
  policies. This is the bulk of "session hijack" protection. **Already done.** (SC-001 largely met.)
- **Unactivated / `None` cross-channel transfer forbidden at ActivateSession** —
  `is_cross_channel_transfer_forbidden` (`manager.rs:52`) + call at `manager.rs:580`. Unit-tested
  (`cross_channel_transfer_rules`, `manager.rs:674`).
- **Client signature verification** — `verify_client_signature` (`manager.rs:349`) verifies the
  `clientSignature` over (server certificate ‖ session nonce) using the session's stored client
  certificate via `opcua_crypto::verify_signature_data`. Correct per spec. **Already done.** (FR-003)
- **Per-activation server nonce freshness + replay protection** — a fresh nonce is generated each
  ActivateSession (`manager.rs:528`) and stored on the session (`instance.rs:263`); a stale-nonce
  activation is rejected (`BadNonceInvalid`, `manager.rs:597`). Regression-tested:
  `activate_session_rejects_stale_nonce_after_intervening_activation` (`manager.rs:721`).
  **Already done.** (FR-004 / SC-002 substantially met.)
- **User identity token nonce binding** — `info.authenticate_endpoint` (`info.rs:466`) binds every
  token type to the passed server nonce: username/issued tokens are decrypted with it
  (`decrypt_identity_token_secret`), x509 tokens verify a signature over (server cert ‖ nonce) via
  `verify_x509_identity_token` (`user_identity.rs:345`). **Already done.**
- **Endpoint-URL host validation** — `info.validate_endpoint_hostname` (`info.rs:257`), called at
  `manager.rs:225`, checks the request endpoint-URL host against the advertised endpoints AND, failing
  that, the **server certificate's SubjectAltName** host names (`X509::is_hostname_valid`). The TODO
  comment at `manager.rs:213` is **stale** — the check it asks for exists 12 lines below it.
  **Already done.** (FR-005 / SC-003 met.)

## The genuine remaining gap (the real delta)

1. **Client certificate ↔ secure-channel binding at ActivateSession** — the `// TODO` at
   `manager.rs:593`. The session's client certificate (from CreateSession,
   `session.client_certificate()`, `instance.rs:287`) is **not** compared against the activating
   secure channel's peer certificate (`SecureChannel::remote_cert()`, `core/comms/secure_channel.rs:260`).
   The clientSignature is checked with the *session's stored* cert, but nothing ties the CreateSession
   `client_certificate` to the cert that actually secured the channel — a client may present a
   different application certificate in CreateSession than the one in its OpenSecureChannel. §5.6
   requires these to be the same identity. **Narrow, real, ~1 added check** → reject mismatch
   (`Bad_SecurityChecksFailed` / `Bad_NoValidCertificates`).

2. **Re-activation cross-channel transfer for *activated, secured* sessions is permitted** —
   `is_cross_channel_transfer_forbidden` returns `false` for an activated non-`None` session
   (`manager.rs:52`), allowing a secured session to be re-activated on a *different* channel. This is a
   deliberate reconnection affordance (a §5.6 reconnection allowance), and re-activation still requires
   a valid client signature + user token, so it is not a trivial hijack. **[DECISION — confirm with
   user]** whether to keep the reconnection affordance (recommended) or tighten to strict
   same-channel-only binding (risks breaking legitimate reconnect/transfer flows).

## Test-coverage gaps (lock-in value even where behavior exists)

- No integration test that an activated **secured** session is rejected when a *service request*
  arrives on a different channel (the `controller.rs:768` path) — behavior exists, untested end-to-end.
- No test for the client-cert↔channel mismatch at ActivateSession (the gap above; will be added with
  the fix).
- No test that a CreateSession endpoint URL with a non-matching host is rejected
  (`validate_endpoint_hostname` exists, but the create_session-level negative path is untested).

## Decision — recalibrated scope

- **D1 (primary):** Implement the client-cert↔channel binding at ActivateSession (`manager.rs:593`),
  comparing `session.client_certificate()` to `channel.remote_cert()` (by DER/thumbprint), rejecting
  mismatch with the precise status code. Remove the now-satisfied stale TODO at `manager.rs:213`.
- **D2 (lock-in):** Add the missing regression tests (cross-channel service-request rejection for a
  secured session; cert-mismatch at ActivateSession; endpoint-host mismatch at CreateSession;
  malformed-field/no-panic) — Claude-authored, so the already-correct behavior cannot silently
  regress.
- **D3 (confirm):** Keep the activated-secured-session reconnection affordance as-is (do NOT tighten
  re-activation to strict same-channel) unless the user wants strict §5.6 binding.
- **Implication:** This feature is **much smaller** than the spec's five user stories implied — US2
  (token replay) and US3 (endpoint URL) are already satisfied; US1 reduces to the one cert-binding
  check + lock-in tests. The spec should be trimmed accordingly before tasks.

## Constraints carried forward

Pure-Rust; reuse `verify_signature_data` / `X509` / the feature-013 cert engine; no panics on
attacker-supplied CreateSession/ActivateSession fields; `None` path unchanged; conformant clients
unaffected; `clippy --all-targets --all-features` clean.
