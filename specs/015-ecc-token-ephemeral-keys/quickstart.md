# Quickstart / Verification: ECC Token EphemeralKey Exchange (Part 6 §6.8.2)

All commands from the workspace root. Tests authored + run by Claude (verification division), anchored
to Part 6 §6.8.2 and Part 4 §7.15 (Table 136) — not codex loopback alone.

## Baseline gate (before any change)

```bash
cargo fmt --all --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test -p async-opcua-crypto -p async-opcua-server -p async-opcua-client
```

## US1 — server issues a signed EphemeralKey

- CreateSession with `ECDHPolicyUri = ECC_nistP256`/`ECC_nistP384` in the request AdditionalHeader →
  response AdditionalHeader has `ECDHKey` (`EphemeralKeyType`); `publicKey` is a valid curve point; the
  `signature` verifies against the server certificate.
- Invalid/unsupported `ECDHPolicyUri` → `Bad_SecurityPolicyRejected` (no key), no panic.
- No `ECDHPolicyUri` → no key returned; flow unchanged.

## US2 — client requests + verifies + retains

- Client puts `ECDHPolicyUri` in the request AdditionalHeader; reads `ECDHKey` from the response;
  verifies the signature vs the server cert; retains the most recent verified key.
- A forged / wrong-signature server `ECDHKey` is rejected client-side (not retained), no panic.

## US3 — fresh key + anti-replay

- After a successful ActivateSession that consumed the server EphemeralKey, presenting that same key
  again is rejected.
- The §6.8.2 new-vs-retain rules hold (valid policy → new key; invalid → `Bad_SecurityPolicyRejected`;
  absent + previous used → new; absent + previous unused → retain).

## US4 — backward compatibility

- RSA / `None` / ECC-without-ECDHPolicyUri sessions connect/activate exactly as before.
- `--no-default-features` (and `ecc` off) build identical to today.

## Negative / fuzz

- Malformed / truncated / oversized AdditionalHeader and `EphemeralKeyType` bytes → rejected with a
  protocol error, **no panic**.

## Final gate (per story)

```bash
cargo fmt --all --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test -p async-opcua-crypto -p async-opcua-server -p async-opcua-client
```
One commit per user story; coding to codex; tests authored + run by Claude.
