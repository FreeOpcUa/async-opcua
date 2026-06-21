# Public Surface & Wire Behavior: ECC Token EphemeralKey Exchange

All changes are **additive**; no breaking change to RSA/None or existing no-ECDH flows.

## async-opcua-crypto (`ecc.rs`)

- New EphemeralKey **sign** (server) + **verify** (client) helpers over the existing
  `EphemeralPublicKey` / curve encoding (e.g. `sign_ephemeral_key(signing_key, &public_key, …) ->
  signature` and `verify_ephemeral_key(server_cert, &ephemeral_key) -> Result<(), Error>`). Behind the
  `ecc` feature. The exact signed-data layout is pinned from Part 4 §7.15 / Part 6 §6.8.1 at task time.
- Reuses `generate_ephemeral_keypair`, `EphemeralPublicKey`, `encode_public_key`/`decode_public_key`.

## async-opcua-server (`session/manager.rs`)

- CreateSession/ActivateSession read `ECDHPolicyUri` from the request `AdditionalHeader`
  (`AdditionalParametersType`); when valid, generate + sign an EphemeralKey and place `ECDHKey`
  (`EphemeralKeyType`) in the response `AdditionalHeader`; invalid policy → `Bad_SecurityPolicyRejected`
  in place of the key. Per-session EphemeralKey state + §6.8.2 lifecycle + anti-replay (a consumed key
  is never accepted again). No change when no `ECDHPolicyUri` is present.

## async-opcua-client (`session/services/session.rs`)

- Place the chosen `ECDHPolicyUri` in the request `AdditionalHeader`; read `ECDHKey` from the response,
  verify its signature against the server certificate and the curve point, and retain the most-recent
  verified server EphemeralKey for feature 016 to use.

## Behavioral contracts / invariants (verified by tests)

- RSA, `None`, and ECC-without-ECDHPolicyUri sessions are byte-identical to today.
- A server EphemeralKey is authenticated (signed); the client rejects an unverifiable one.
- A consumed server EphemeralKey is never accepted again (anti-replay, §6.8.2).
- Malformed `AdditionalHeader` / `EphemeralKeyType` bytes never panic; `clippy --all-targets
  --all-features` clean; no new C dependency.
- No `EccEncryptedSecret` is produced or consumed here — that is feature 016.
