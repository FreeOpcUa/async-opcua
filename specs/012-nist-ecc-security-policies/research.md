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

### Working algorithm set (well-known OPC UA values — confirm vs profiles.opcfoundation.org at US1)

| Policy | Curve | AsymmetricSignature | KeyDerivation | SymmetricEncryption | SymmetricSignature | Sig/Enc/IV len |
|--------|-------|---------------------|---------------|---------------------|--------------------|----------------|
| `ECC_nistP256` | secp256r1 (P-256) | ECDSA-SHA256 (`…xmldsig-more#ecdsa-sha256`) | HKDF-SHA256 | AES-128-CBC | HMAC-SHA256 | 32 / 16 / 16 |
| `ECC_nistP384` | secp384r1 (P-384) | ECDSA-SHA384 (`…xmldsig-more#ecdsa-sha384`) | HKDF-SHA384 | AES-256-CBC | HMAC-SHA384 | 48 / 32 / 16 |

These map cleanly to RustCrypto: `p256`/`p384` (+`ecdsa`, `sha256` feature), `hkdf`, existing
`aes`/`cbc`/`hmac`/`sha2`. URIs confirmed (UA-.NETStandard `SecurityPolicies.cs`); the Sig/Enc/IV
lengths are fixed by the algorithms themselves (HMAC-SHA256/384 output = 32/48; AES-128/256 key =
16/32; AES block IV = 16) — no longer open.

## Ephemeral key exchange (replaces RSA nonce encryption) [SPEC-PINNED — Part 6 §6.8.1, verbatim 2026-06-20]

- ephemeral-**ephemeral** ECDH. Client generates `(JC, KC)`, sends public `JC`; server verifies the
  request signature, generates `(JS, KS)`, returns public `JS`. New pairs each channel open
  ("EphemeralKeys").
- The `ClientNonce` / `ServerNonce` fields of OpenSecureChannel **ARE** the ephemeral public keys
  (§6.8.1: "the ClientNonce is the Public Key for the Client's EphemeralKey").
- **Encoding [CONFIRMED]**: NIST curves → EphemeralKey = `x ‖ y`, each coordinate **zero-padded
  big-endian OctetString** → **64 B (P-256) / 96 B (P-384)**. No `0x04`/SEC1 prefix — the spec
  specifies bare x‖y. (Exact public-key + signature encoding is otherwise deferred to the Part 7
  SecurityPolicy — see signatures below.)
- **Shared secret (IKM) [CONFIRMED]** = ECDH(own private, peer public) → the **x-coordinate**, encoded
  as a zero-padded big-endian OctetString (32 B P-256 / 48 B P-384).
- **Renewal [CONFIRMED]**: if `SecureChannelEnhancements = TRUE`, on renewal the current IKM is
  **XORed** with the newly-negotiated IKM before deriving the new keys (§6.8.1 Step 2 note).

## Key derivation (HKDF) [SPEC-PINNED — Part 6 §6.8.1 Steps 1–3, verbatim 2026-06-20]

- **Step 1 — Salts** (direction-separated), CONFIRMED verbatim:
  - `ServerSalt = L | UTF8(opcua-server) | ServerNonce | ClientNonce`
  - `ClientSalt = L | UTF8(opcua-client) | ClientNonce | ServerNonce`
  - **`L`** = length of derived key material in bytes, **16-bit little-endian** integer.
  - **`UTF8(label)`** = UTF-8 of the literal — exactly **`opcua-server`** / **`opcua-client`**
    (lowercase, hyphen, no NUL).
  - `ServerNonce`/`ClientNonce` = the ephemeral public keys (x‖y); `|` = byte concatenation.
- **Step 2 — Extract**: `PRK = HMAC-Hash(Salt, IKM)`; Hash = policy `KeyDerivationAlgorithm`
  (SHA-256 P-256 / SHA-384 P-384); IKM = ECDH shared secret (x-coord, zero-padded BE); `PRK` = hash size.
- **Step 3 — Expand** = standard **RFC 5869 HKDF-Expand**, CONFIRMED verbatim:
  `N = ceil(L/HashLen)`, `T(0)=""`, `T(i)=HMAC-Hash(PRK, T(i-1) | Info | byte(i))` for i=1..N, `OKM = first L octets of T(1)|…|T(N)`; the single-byte counter is `0x01, 0x02, …`. **`Info = Salt`**
  (Info = ClientSalt for client keys; ServerSalt for server keys).
- **Output layout** (Tables 67/68), CONFIRMED — client keys from `IKM=sharedSecret, Salt=Info=ClientSalt`;
  server keys from `…ServerSalt`:
  | Key | Offset | Length |
  |-----|--------|--------|
  | SigningKey | 0 | DerivedSignatureKeyLength |
  | EncryptingKey | DerivedSignatureKeyLength | EncryptionKeyLength |
  | IV | DerivedSignatureKeyLength + EncryptionKeyLength | InitializationVectorLength |
  - The three length constants come from the **SecurityPolicy (Part 7)** — for the standard non-AEAD
    nistP256/P384 policies: P-256 = (Sig 32, Enc 16, IV 16); P-384 = (Sig 48, Enc 32, IV 16)
    **[confirm exact constants in Part 7]**.
  - **AEAD note**: when `AuthenticatedEncryption` is used, `DerivedSignatureKeyLength = 0` in the `L`
    calc, and the per-message IV is `ClientInitializationVector`/`ServerInitializationVector` XORed
    with `(TokenId, LastSequenceNumber)` (Table 69). Our scope is **AES-CBC + HMAC (non-AEAD)**, so the
    derived IV is used directly.
- Once keys are derived, **"ECC SecureChannels behave the same as RSA SecureChannels"** — the
  symmetric protect/verify code is reused unchanged.

## Asymmetric signatures (ECDSA) [alg spec-confirmed; encoding deferred to Part 7]

- ECDSA — P-256/SHA-256, P-384/SHA-384 — signs the OpenSecureChannel request/response (and is verified
  against the peer's EC application certificate). For ECC, OpenSecureChannel messages are **signed but
  NOT asymmetrically encrypted** (no RSA-style nonce encryption; confidentiality comes from the ECDH
  keys). [Part 6 §6.8.1]
- **Signature/public-key wire encoding [CONFIRMED — UA-.NETStandard source, 2026-06-20]**: ECDSA
  signature = **raw fixed-length `r ‖ s`** (IEEE P1363 `FixedFieldConcatenation`), **NOT** ASN.1/DER —
  UA-.NETStandard uses `DSASignatureFormat.IeeeP1363FixedFieldConcatenation` and a `ConvertDerToIeeeP1363`
  helper; its P-384 test asserts ES384 + P1363. → 64 B (P-256) / 96 B (P-384); use the RustCrypto
  `ecdsa::Signature` (fixed) form, not the DER form.
  - **Cross-confirmed against UA-.NETStandard `Nonce.cs`**: ephemeral public key = `X ‖ Y` with **no**
    prefix (`Array.Copy(Q.X…); Array.Copy(Q.Y…)`); shared secret = **raw ECDH x-coordinate**
    (`DeriveRawSecretAgreement`); HKDF = HMAC-SHA256/384 Extract + iterative Expand. Policy URIs
    confirmed in `SecurityPolicies.cs` (`…#ECC_nistP256`/`#ECC_nistP384`).
  - **Finding:** Part 7's *PDF* is only the Profile/Conformance framework; the per-facet algorithm
    tables live in the online DB (profiles.opcfoundation.org). All values we needed are now pinned
    from Part 6 §6.8 (verbatim) + the UA-.NETStandard reference — no remaining `[verify-on-impl]`.
- **ChannelThumbprint [Part 6 §6.7.5]**: when `SecureChannelEnhancements = TRUE`, the
  OpenSecureChannel **Response** signature is computed over `Response-bytes ‖ Request-signature` (the
  ChannelThumbprint = that response signature); NOT done on renewal. ECC policies set
  SecureChannelEnhancements — implement this MITM-hardening signature, and the Channel-Bound-Signature
  use of the thumbprint (Part 4).

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
- All former `[verify-on-impl]` crypto items are now CLOSED — pinned from Part 6 §6.8 (verbatim) and
  cross-confirmed against UA-.NETStandard source (signature P1363, ephemeral X‖Y, raw-x IKM, URIs).
  The **only** residual risk is end-to-end **interop validation** (SC-007): loopback + vectors prove
  self-consistency and primitive-correctness; a third-party ECC peer (open62541 / UA-.NETStandard
  running) is still the gold standard and should be used if available before claiming interop.

## Deferred (out of scope, recorded)

- Brainpool (`ECC_brainpoolP256r1/P384r1`) — pre-release/unaudited Rust arithmetic; PubSub-ECC; ECC
  user-identity-token encryption; any C/OpenSSL backend.
- **Mixed RSA+ECC on one server (multi-cert)** — a server holds a single application instance
  certificate (`CertificateStore::read_own_cert`/`read_own_pkey`), and a given cert is either RSA or
  EC. ECDSA handshakes need the EC cert; RSA handshakes need the RSA cert. So a single-cert server is
  inherently **ECC-only or RSA-only**. Serving both on one server needs a second application cert plus
  per-policy cert selection at OpenSecureChannel time — a real but bounded follow-up. US5 delivers the
  feature-gating (ecc-off → recognized-but-unsupported, fail-closed) and curve-strict negotiation;
  mixed-mode multi-cert is deferred. (Mixed deployments today: run RSA and ECC on separate endpoints/hosts.)
- **ChannelThumbprint (§6.7.5)** — the MITM-hardening OpenSecureChannel *response* signature over
  `Response-bytes ‖ Request-signature`. Not exercised by loopback (both peers ours). Implement before
  claiming production/interop completeness.
