# Public Surface Changes: NIST ECC Security Policies

All changes are **additive**; no breaking change to existing RSA/None policies.

## SecurityPolicy (public enum)

- New variants `EccNistP256`, `EccNistP384`, with their URIs in `FromStr`/`Display`/round-trip and
  `supported()` gated on the `ecc` feature. Unknown/legacy handling unchanged. Existing variants and
  their behavior are untouched.

## Configuration / endpoints (server) and connection (client)

- Server endpoint config can list ECC policies (same endpoint schema; additive — existing configs
  parse unchanged). Client can request an ECC policy. Policy/security-level **negotiation** selects
  ECC for ECC-capable peers and continues to select RSA for RSA-only peers (no change to RSA
  negotiation).

## Cargo features

- New `ecc` feature (on the crypto/core/client/server crates) enabling the curve deps + ECC paths.
  With it disabled: ECC URIs are recognized but report **unsupported** (fail-closed); RSA/None builds
  and behavior are byte-identical. Default-enabled assumed (revisit at review).

## Behavioral contracts (no signature change to existing APIs)

- `OpenSecureChannel`: for ECC policies the nonce fields carry ephemeral EC public keys and keys come
  from ECDH+HKDF; the public service/API shape is unchanged. RSA/None flows untouched.
- Message `Sign` / `SignAndEncrypt` semantics identical from the caller's view; only the underlying
  asym signature (ECDSA) and key source differ for ECC channels.

## Invariants preserved (verified by tests)

- Wire byte-identity for all existing RSA/None paths.
- Generated code untouched (`verify-clean-codegen`).
- `cargo clippy --all-targets --all-features -- -D warnings` clean.
- No secret/nonce/private-key logging; no panics on attacker-controlled ECC handshake input.
