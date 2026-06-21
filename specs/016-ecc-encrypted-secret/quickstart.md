# Quickstart / Verification: ECC EncryptedSecret (Part 4 §7.40.2.5 / Part 6 §6.8.3)

All commands from the workspace root. Tests authored + run by Claude (verification division), anchored to
the §7.40.2.5 layout, the §6.8.3 KDF, and **RFC 5869** HKDF vectors — not codex loopback.

## Baseline gate (before any change)

```bash
cargo fmt --all --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test -p async-opcua-crypto -p async-opcua-server -p async-opcua-client
```

## US1 — server decrypts an ECC UserName password

- A crafted `EccEncryptedSecret` (known P-256/P-384 ephemeral keys, the §6.8.3 KDF, the current server
  nonce) decrypts to the exact password; the signature is verified before decrypt.
- Wrong server nonce, tampered ciphertext/signature/header → **single uniform** `BadIdentityTokenRejected`,
  no panic.

## US2 — client encrypts a UserName secret

- The client produces an `EccEncryptedSecret` (sender = fresh client ephemeral, receiver = retained
  server `ECDHKey`, nonce = current server nonce) that the server (US1) decrypts back to the original.
- Round-trip on P-256 **and** P-384.

## US3 — IssuedIdentityToken secret

- An `IssuedIdentityToken` whose `tokenData` is an `EccEncryptedSecret` round-trips client→server; same
  nonce-binding + uniform-error rejection.

## US4 — consumed-key anti-replay (closes 015a deferral)

- After a successful ActivateSession that consumed the server EphemeralKey, presenting the same key /
  the same secret again is rejected.
- The next ActivateSession issues a fresh key — `decide_ecdh_key_action` now driven by the real
  `previous_key_consumed = true` state.

## US5 — backward compatibility

- RSA / `None` / no-ECC identity-token flows are byte-identical to today; `--no-default-features` build
  identical; policy selects RSA vs ECC vs None correctly.

## KDF anchor (SC-002)

- HKDF Extract+Expand matches **RFC 5869 Appendix A** vectors (SHA-256; SHA-384 path via a known vector).
- The §6.8.3 `SecretSalt` (`L | "opcua-secret" | SenderPublicKey | ReceiverPublicKey`) + Table 71 split
  reproduce a known fixture's EncryptingKey/IV.

## Negative / fuzz (SC-006)

- Malformed / truncated / oversized `EccEncryptedSecret` bytes → rejected, **no panic**
  (`fuzz_ecc` extended; bounded `Length`/`KeyDataLength`/padding before allocation).

## Final gate (per story)

```bash
cargo fmt --all --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test -p async-opcua-crypto -p async-opcua-server -p async-opcua-client
cargo build -p async-opcua-server -p async-opcua-client --no-default-features   # ecc-off identical
```
One commit per user story; coding to codex; tests authored + run by Claude.
