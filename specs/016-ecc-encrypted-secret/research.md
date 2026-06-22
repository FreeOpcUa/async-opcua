# Research: ECC EncryptedSecret (Part 4 §7.40.2.5 / Part 6 §6.8.3)

Pinned from the actual spec PDFs in `~/opcua-specs` (Part 4 Services **1.05.07**, Part 6 Mappings
**1.05.07**) — not guessed. These are the normative facts the implementation MUST follow.

## Decision 1 — `EccEncryptedSecret` wire layout (Part 4 §7.40.2.3 + Table 186)

**Decision**: hand-serialize the EncryptedSecret envelope; it is NOT a codegen struct (only the
`EccEncryptedSecret` DataType NodeId exists). Field order (UA Binary encoding):

| # | Field | Type | Notes |
|---|-------|------|-------|
| Common header | TypeId | NodeId | the `EccEncryptedSecret` DataType NodeId (ExtensionObject prefix) |
| | EncodingMask | Byte | **always `1`** |
| | Length | Int32 | length of everything that follows **including the Signature** |
| | SecurityPolicyUri | String | the ECC policy URI |
| | Certificate | ByteString | signing cert DER **chain**; **MAY be null/empty** when the signing cert is the Client ApplicationInstance Certificate already known to the server over the SecureChannel (our case) |
| | SigningTime | DateTime | when the signature was created |
| | KeyDataLength | UInt16 | length of the (unencrypted, for ECC) KeyData that follows |
| KeyData (NOT encrypted for ECC) | SenderPublicKey | ByteString | the sender's EphemeralKey public key |
| | ReceiverPublicKey | ByteString | the receiver's EphemeralKey public key |
| Payload (AES-CBC encrypted) | Nonce | ByteString | the last ServerNonce from Create/ActivateSession Response |
| | Secret | ByteString | the password / issued tokenData (UTF-8 if a String) |
| | PayloadPadding | Byte[*] | each byte = LSB of PayloadPaddingSize |
| | PayloadPaddingSize | UInt16 | length of PayloadPadding |
| Signature | Signature | Byte[*] | asymmetric signature, appended after encryption |

**Rationale**: Tables 183 & 186. The three prefix fields (TypeId/EncodingMask/Length) are the
ExtensionObject encoding from Part 6.
**Critical correction to the spec's assumption**: for **ECC**, KeyData is **not encrypted** and carries
the two ephemeral *public* keys (the symmetric keys are *derived*, never transmitted). This differs from
`RsaEncryptedSecret` (Table 185), where KeyData is the RSA-encrypted SigningKey/EncryptingKey/IV.

## Decision 2 — §6.8.3 key derivation (the KDF)

**Decision**: derive **only** EncryptingKey + InitializationVector (Table 71) — there is **no derived
SigningKey** for ECC. RFC 5869 HKDF:

- **Step 1 — Salt**: `SecretSalt = L | UTF8("opcua-secret") | SenderPublicKey | ReceiverPublicKey`
  where `L` = length of derived key material (= EncryptionKeyLength + IVLength) as a **16-bit
  little-endian** integer; `SenderPublicKey`/`ReceiverPublicKey` are the bytes from the EccEncryptedSecret.
- **Step 2 — Extract**: `PRK = HMAC-Hash(SecretSalt, IKM)`, `IKM` = ECDH shared secret = the
  **x-coordinate, zero-padded big-endian** (`ecdh_shared_secret` already returns this).
- **Step 3 — Expand**: standard RFC 5869 Expand with **`Info = SecretSalt`** (Info equals the Salt).
- **Table 71 split**: `EncryptingKey` = OKM[0 .. EncryptionKeyLength]; `InitializationVector` =
  OKM[EncryptionKeyLength .. EncryptionKeyLength + IVLength]`.
- **Hash per curve** (KeyDerivationAlgorithm of the policy): **SHA-256 for P-256, SHA-384 for P-384**.
- **Lengths (per-curve — confirmed from `policy/aes.rs` at T001, NOT uniform AES-256)**:
  **ECC_nistP256 ⇒ `SymmetricEncryption = Aes128Cbc`, EncryptionKeyLength = 16 (AES-128-CBC); P-384 ⇒
  `Aes256Cbc`, EncryptionKeyLength = 32 (AES-256-CBC)**. IVLength = 16 (AES block) for both. So
  `L = EncryptionKeyLength + 16` (32 for P-256, 48 for P-384). The existing `key_lengths(curve)` returns
  `(signing, enc, iv)` = P256 `(32,16,16)` / P384 `(48,32,16)` — use its `enc`+`iv` (drop `signing`).
  `AesKey::new(key)` selects AES-128 vs AES-256 by key length automatically.

**Rationale**: §6.8.3 Step 1 (verbatim salt), §6.8.1 Steps 2–3 (HKDF, referenced by §6.8.3), Table 71.
**Reuse**: `Hkdf::<Sha256/384>::new(Some(salt), ikm)` then `expand(salt, &mut okm)` — exactly matches
Extract(salt, ikm)+Expand(info=salt). The existing `build_hkdf_salt`/`split_derived_keys` are for §6.8.1
(3 keys incl. signing); add a §6.8.3 variant (`derive_secret_keys`) with the `opcua-secret` label, the
public keys (not nonces), and only the 2 outputs.

## Decision 3 — Integrity = asymmetric ECDSA signature (NOT a symmetric MAC)

**Decision**: the EccEncryptedSecret `Signature` is an **asymmetric** signature computed with the
SigningCertificate's private key and the policy's `AsymmetricSignatureAlgorithm` — **ECDSA** (P-256 ⇒
ECDSA-SHA256, P-384 ⇒ ECDSA-SHA384; raw `r||s`), over the serialized envelope **after** encryption.
Reuse the existing `SecurityPolicy::asymmetric_sign` / `asymmetric_verify_signature` (already used by
015a's `sign_ephemeral_public_key`; the runtime dispatch routes ECC policies to `ecc::ecdsa_sign`,
overriding the `AsymmetricSignature` type param shown in `policy/aes.rs`).

- **Data to sign** (Figure 39): all serialized bytes from the start of the structure up to but **not
  including** the Signature (common header + KeyData + encrypted payload). Pin the exact start boundary
  (whether TypeId/Length are included) at implementation by matching the serialize order above; the
  signer and verifier MUST use identical bytes.
- **Signer identity**: the Client ApplicationInstance Certificate. The `Certificate` field is normally
  **null** in our context, so the **server verifies against the client cert it already holds from the
  SecureChannel** (do NOT trust an attacker-supplied cert chain to self-authenticate the secret without
  validating it against the channel/trust store).
- **Order on decrypt** (§6.8.3 + §7.40.2.3): deserialize header → **validate SigningCertificate +
  verify Signature** → decrypt payload → verify padding → extract Secret. Signature is checked **before**
  decryption.

**Rationale**: Table 186 ("Signature calculated using the Certificate and the
AsymmetricSignatureAlgorithm"); §6.8.3 ("Receivers shall validate the SigningCertificate and signature
before decrypting the Secret"). **This corrects the spec's "signing/encrypting key split" note, which
described the RSA model.**

## Decision 4 — Padding (§6.8.3 formula)

**Decision**: implement verbatim:
```
BlockSize   = InitializationVector.Length            // 16 for AES-CBC (non-AEAD)
Data.Length = 4 + Nonce.Length + 4 + Secret.Length + 2   // two ByteString length prefixes + UInt16 size
PayloadPaddingSize = (Data.Length % BlockSize == 0) ? 0 : BlockSize - (Data.Length % BlockSize)
if (PayloadPaddingSize + Secret.Length < BlockSize) PayloadPaddingSize += BlockSize
```
Every padding byte = LSB of PayloadPaddingSize. The formula guarantees padding is never zero-when-needed
and the encrypted payload is a multiple of the AES block.
**Rationale**: §6.8.3 padding clause.

## Decision 5 — Nonce binding & anti-replay (FR-004/FR-005; closes the 015a deferral)

**Decision**:
- The envelope `Nonce` MUST equal the session's **current server nonce** (the one from the most recent
  Create/ActivateSession Response). The server rejects any other nonce → non-replayable.
- The server marks its EphemeralKey **consumed** the moment it successfully decrypts an identity-token
  secret with it; a second secret relying on that same (now consumed) server EphemeralKey is rejected.
- This real consumed-state replaces 015a's hardwired `previous_key_consumed = false` feeding
  `decide_ecdh_key_action`, so the next ActivateSession issues a fresh key (the `Issue(prev)` branch now
  fires from real state) — **never accept the same EphemeralKey twice**.
**Rationale**: §7.40.2.5 Nonce semantics + §6.8.2 anti-replay + features 014/015a replay protection +
the explicit 015a scope deferral (memory: consumed-key anti-replay → 016).

## Decision 6 — Fail-closed, single uniform error (no oracle)

**Decision**: every decrypt failure — malformed envelope, bad `Length`/`KeyDataLength`, signature
invalid, wrong/absent/consumed key, wrong nonce, AES/padding failure — returns **one** uniform error
(`BadIdentityTokenRejected`) with no branch- or timing-distinguishable behaviour, and never panics on
attacker-supplied bytes. Bound `Length`/`KeyDataLength`/`PayloadPaddingSize`/ByteString lengths against
the available buffer **before** allocating. Derived keys are `Zeroizing`.
**Rationale**: Constitution IV; padding-oracle / Bleichenbacher-class attack avoidance; the existing
fail-closed ECC key-derivation precedent (obs 2955).

## Decision 7 — Sender/Receiver mapping (client→server identity token)

**Decision**: when the **client** encrypts for the server:
- `SenderPublicKey` = the client's freshly created EphemeralKey public key (curve from the policy).
- `ReceiverPublicKey` = the **retained verified server `ECDHKey`** (`Session.retained_server_ephemeral_key`
  from 015a).
- shared secret = `ecdh_shared_secret(client_ephemeral_private, server_ephemeral_public)`.

When the **server** decrypts: it holds its own EphemeralKey private (`Session.ecdh_ephemeral_key`) and
reads `SenderPublicKey` (the client ephemeral) from the envelope; shared secret =
`ecdh_shared_secret(server_ephemeral_private, client_ephemeral_public)` — identical by ECDH symmetry.
Mismatched curve/policy between the channel and the envelope ⇒ reject.
**Rationale**: §6.8.3 ("the sender creates its own EphemeralKey" once it has the receiver's); ECDH symmetry.

## Decision 8 — Backward compatibility & feature gating

**Decision**: add an ECC branch to `decrypt_identity_token_secret` (server) and the client encrypt path
keyed on the negotiated policy being `EccNistP256`/`EccNistP384`; the legacy RSA (`legacy_*`) and `None`
paths are untouched and byte-identical. All new code is `#[cfg(feature = "ecc")]`.
**Rationale**: FR-007; mirror the legacy_encrypt_secret/legacy_decrypt_secret structure.

## Decision 9 — Test anchoring (verification division)

**Decision**: Claude-authored tests, anchored to **external** ground truth:
- **RFC 5869** Appendix A HKDF test vectors for the SHA-256 HKDF (and the SHA-384 path via a known
  vector) — proves Extract+Expand, independent of any in-tree loopback (the division caught a rigged
  HKDF test on 012).
- A **crafted EccEncryptedSecret fixture** (known ephemeral keys + known plaintext) decoded per the
  Table 186 byte layout → asserts the recovered secret and that the byte offsets match the spec.
- **Round-trip** client-encrypt ↔ server-decrypt on real P-256 and P-384 keys.
- **Negative**: wrong server nonce, tampered ciphertext/signature/header, consumed key, replayed secret,
  malformed/truncated/oversized bytes → all the **same** uniform error, no panic.
**Rationale**: feature-012 rigged-HKDF incident; Constitution I/IV; SC-002/SC-004/SC-006.

## Out of scope / deferred (recorded)

- The non-legacy **RSA** EncryptedSecret (Table 185) and **RSA-DH** finite-field EphemeralKeys (§6.9) —
  not required for ECC identity tokens.
- **AuthenticatedEncryption** (AES-GCM) EncryptedSecret variant — the 012 ECC policies use AES-CBC +
  asymmetric signature; confirm at implementation and reject AEAD-only policies if any.
- GDS; the deferred mixed RSA+ECC multi-cert server (feature 012).
