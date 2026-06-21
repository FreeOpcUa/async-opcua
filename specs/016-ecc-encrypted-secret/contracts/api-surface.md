# API Surface: ECC EncryptedSecret

All additions behind `#[cfg(feature = "ecc")]`. Panic-free on attacker input; fail-closed; single
uniform decrypt error.

## `async-opcua-crypto/src/ecc.rs`

```rust
/// §6.8.3 KDF: derive the AES-256-CBC EncryptingKey + InitializationVector for an EccEncryptedSecret.
/// salt = L | "opcua-secret" | sender_public_key | receiver_public_key ; IKM = ECDH shared secret.
/// Hash per curve (SHA-256/P-256, SHA-384/P-384). No SigningKey (integrity is asymmetric).
pub fn derive_secret_keys(
    curve: EccCurve,
    shared_secret: &[u8],
    sender_public_key: &[u8],
    receiver_public_key: &[u8],
) -> Result<EccSecretKeys, Error>;   // { encrypting_key: AesKey, iv: Vec<u8> } (Zeroizing)
```

The EccEncryptedSecret envelope build/parse + signature lives in `ecc.rs` (or a small submodule) but is
exposed to the identity-token layer through the two `user_identity.rs` functions below — keep the
envelope codec internal where possible.

## `async-opcua-crypto/src/user_identity.rs` (mirror the legacy_* API)

```rust
/// Client side: wrap `secret` as an EccEncryptedSecret (Part 4 §7.40.2.5) for the negotiated ECC policy,
/// using a fresh client EphemeralKey (sender), the retained server EphemeralKey (receiver), the current
/// server nonce, and the client signing key/cert for the asymmetric Signature.
pub fn ecc_encrypt_secret(
    security_policy: SecurityPolicy,
    server_nonce: &[u8],
    receiver_ephemeral_public_key: &EphemeralPublicKey,  // retained server ECDHKey
    signing_key: &PrivateKey,                            // client app-instance cert key
    signing_cert: &X509,                                 // for Certificate field / cert known to server
    secret_to_encrypt: &[u8],
) -> Result<ByteString, Error>;                          // the serialized EccEncryptedSecret bytes

/// Server side: parse + verify + decrypt an EccEncryptedSecret, returning the plaintext secret.
/// Verifies the asymmetric Signature against `signer_cert` BEFORE decrypting; checks Nonce ==
/// `server_nonce`; derives keys from ECDH(server_ephemeral_private, SenderPublicKey). Single uniform
/// error on ANY failure.
pub fn ecc_decrypt_secret(
    security_policy: SecurityPolicy,
    encrypted: &[u8],
    server_nonce: &[u8],
    server_ephemeral_private: &EphemeralPrivateKey,   // from Session.ecdh_ephemeral_key
    signer_cert: &X509,                               // client cert known from the channel
) -> Result<ByteString, Error>;
```

## Server wiring — `async-opcua-server/src/info.rs` + `session/manager.rs`

- `decrypt_identity_token_secret`: add an ECC branch — when the channel policy is ECC and the token
  carries an `EccEncryptedSecret`, call `ecc_decrypt_secret` with the session's server EphemeralKey
  private + the client cert from the channel + the current server nonce.
- `manager.rs` (ActivateSession): after a successful ECC secret decrypt, **mark the server EphemeralKey
  consumed** on the session; feed the real consumed flag into `decide_ecdh_key_action` (replacing the
  015a hardwired `false`); reject reuse of a consumed key / a replayed secret.

## Client wiring — `async-opcua-client/src/session/services/session.rs`

- In the identity-token encryption path (today `legacy_encrypt_secret` at the UserName/Issued sites):
  when the negotiated policy is ECC and a server `ECDHKey` was retained (015a), produce an
  `EccEncryptedSecret` via `ecc_encrypt_secret` instead of the legacy RSA secret. RSA/None unchanged.

## Fuzz — `fuzz/fuzz_targets/fuzz_ecc.rs`

- Extend with `ecc_decrypt_secret` over attacker-controlled envelope bytes (fixed curve + key) → zero
  panics.

## Invariants

- Legacy RSA + `None` identity-token paths byte-identical; `ecc`-off build unchanged.
- Decrypt verifies signature before decrypting; all failures → one uniform error; no panic; derived keys
  zeroized; secrets never logged.
