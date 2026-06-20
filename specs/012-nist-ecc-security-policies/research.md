# Research & Design Decisions: NIST ECC Security Policies

Sources: OPC UA Part 6 §6.8 (ECC), §6.8.1 (Secure Channel Handshake), §6.8.3 (ECC Encrypted Secret);
Part 4 §7.15 (EphemeralKeyType); Part 7 (policy facets); RFC 5869 (HKDF). Confirmed details are
marked **[spec-confirmed]**; details to verify against the spec text + a reference implementation
during US1 implementation are marked **[verify-on-impl]**.

## Crates (pure-Rust)

- **Decision**: `p256` + `p384` (RustCrypto) for the curves; `ecdsa` for signatures; `elliptic-curve`
  `ecdh` (`diffie_hellman`) for key agreement; `hkdf` for derivation. Reuse existing `aes`/`cbc`/
  `hmac`/`sha2`/`x509-cert`/`rand`.
- **Rationale**: mature, stable, audited-adjacent NIST curve support; satisfies the pure-Rust /
  no-C-toolchain constraint. (Brainpool's `bp256/bp384` are pre-release/unaudited → deferred.)
- **Alternatives rejected**: `aws-lc-rs`/OpenSSL (reintroduces C dependency the project keeps
  optional); `ring` (no P-384 ECDH / limited).

## Security policy identity [spec-confirmed]

- **Decision**: URIs `http://opcfoundation.org/UA/SecurityPolicy#ECC_nistP256` and `#ECC_nistP384`.
  Each policy fixes: curve (P-256 / P-384), hash (SHA-256 / SHA-384), symmetric (AES-128 / AES-256),
  KeyDerivation (HKDF with the policy hash).

## Ephemeral key exchange (replaces RSA nonce encryption) [spec-confirmed]

- **Decision**: ephemeral-**ephemeral** ECDH. Client generates `(JC, KC)`, sends public `JC`; server
  verifies the request signature, generates `(JS, KS)`, returns public `JS`. The `ClientNonce` /
  `ServerNonce` fields of OpenSecureChannel **carry the ephemeral public keys**.
- **Encoding**: NIST curve ephemeral public key = `x ‖ y`, each coordinate zero-padded big-endian
  OctetString → **64 bytes (P-256), 96 bytes (P-384)** (uncompressed point, no `0x04` prefix per the
  x‖y wording — **[verify-on-impl]** whether a prefix byte is present).
- **Shared secret** = ECDH(own ephemeral private, peer ephemeral public) → the curve field element x
  (32 / 48 bytes), used as HKDF IKM.

## Key derivation (HKDF) [spec-confirmed structure; exact bytes verify-on-impl]

- **Salts** (direction-separated):
  - `ServerSalt = L ‖ UTF8("opcua-server") ‖ ServerNonce ‖ ClientNonce`
  - `ClientSalt = L ‖ UTF8("opcua-client") ‖ ClientNonce ‖ ServerNonce`
  - `L` = total derived key-material length as a **16-bit little-endian** integer; Nonces = the
    ephemeral public keys.
- **HKDF**: Extract = `HMAC-Hash(Salt, IKM=sharedSecret)`; Expand with `Info = Salt`; Hash per policy.
- **Output layout** (per direction), sliced from the expanded keystream:
  | Key | Offset | Length (P-256 / P-384) |
  |-----|--------|------------------------|
  | SigningKey | 0 | 32 / 48 |
  | EncryptingKey | SigLen | 16 / 32 |
  | IV | SigLen+EncLen | 16 / 16 |
  - **Client** keys derived from `ClientSalt`; **Server** keys from `ServerSalt`.
- **[verify-on-impl]**: exact `L` value (sum of both directions vs one), the precise UTF-8 label
  bytes, and HKDF-Expand counter handling — cross-check against open62541 / UA-.NET ECC.

## Asymmetric signatures (ECDSA) [spec-confirmed alg; encoding verify-on-impl]

- **Decision**: ECDSA — P-256 with SHA-256, P-384 with SHA-384 — over the OpenSecureChannel /
  asymmetric-signed handshake messages, verified against the peer's EC application certificate.
- **[verify-on-impl]**: OPC UA asymmetric signature wire encoding is the **raw fixed-length `r ‖ s`**
  concatenation (not ASN.1/DER). Use the `ecdsa` crate's fixed `Signature` form; confirm against spec.

## Symmetric layer [spec-confirmed: reuse]

- **Decision**: non-AEAD policies use **AES-CBC + HMAC-SHA256/384** — identical structure to the RSA
  policies' symmetric protection. Reuse the existing chunk encrypt/sign/verify code; only the key
  *source* (HKDF vs RSA-derived) and asym signature (ECDSA vs RSA) change. (AEAD/AES-GCM is an
  alternative the spec allows but is NOT the standard nistP256/P384 secure-channel suite — out of
  scope.)

## EC application certificates

- **Decision**: parse/validate X.509 certs carrying P-256/P-384 `id-ecPublicKey` via `x509-cert`;
  reuse existing thumbprint (SHA-1, spec-mandated) and chain/trust validation. Reject a cert whose
  curve ≠ negotiated policy.

## Feature gating

- **Decision**: all ECC code behind an `ecc` cargo feature; assume default-enabled (pure-Rust, mature
  curves) but switchable to opt-in if review prefers. With it off, ECC policies report "unsupported"
  (fail-closed) and RSA/None are byte-identical.

## Open risks (recorded)

- **Interop validation (SC-007)**: loopback proves self-consistency, not spec-correctness. Without a
  third-party ECC peer, a misread of §6.8 could pass loopback yet fail real interop. Mitigation:
  drive every primitive from published vectors, and cross-check the KDF/handshake bytes against an
  open reference impl (open62541 / UA-.NET) before claiming interop.
- The `[verify-on-impl]` items above are the concrete spots to confirm during US1/US3.

## Deferred (out of scope, recorded)

- Brainpool (`ECC_brainpoolP256r1/P384r1`) — pre-release/unaudited Rust arithmetic; PubSub-ECC; ECC
  user-identity-token encryption; any C/OpenSSL backend.
