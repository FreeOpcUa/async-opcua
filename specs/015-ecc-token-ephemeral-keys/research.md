# Research & Design Decisions: ECC Identity-Token Secrets

Sources: **OPC UA Part 4 §7.40.2.3** (EncryptedSecret format, Tables 183/186 — note the section is
**§7.40.2.3**, not §7.41.2.3 as the spec draft said; the numbering shifted in 1.05.07) and **Part 6
§6.8.2/§6.8.3** (the ECC UserIdentityToken EphemeralKey handshake + the EccEncryptedSecret KDF),
extracted from `~/opcua-specs` (Part 4 1.05.07, Part 6 1.05.07). Code state verified 2026-06-21.

## Headline: this feature is LARGER than the spec implied — it's protocol + crypto, not just crypto

The spec framed it as "reuse the 012 ECC primitives to add an ECC secret path." The normative text
shows EccEncryptedSecret needs a **new EphemeralKey-exchange protocol** that the current
CreateSession/ActivateSession handshake does **not** provide, plus a distinct on-wire structure and
KDF. There are **four** layers, almost none of which exist today:

1. **EphemeralKey exchange via AdditionalHeader (Part 6 §6.8.2)** — NEW protocol mechanism.
   - Client puts `ECDHPolicyUri` (String) in the **RequestHeader.AdditionalHeader** of CreateSession
     (and ActivateSession), inside an `AdditionalParametersType` name-value list (Table 70).
   - Server returns `ECDHKey` = **`EphemeralKeyType`** (a signed ephemeral public key) in the
     **ResponseHeader.AdditionalHeader** of CreateSession/ActivateSession; on a bad ECDHPolicyUri it
     returns `Bad_SecurityPolicyRejected` in place of the key.
   - The client builds the EccEncryptedSecret using the **most recent** server EphemeralKey; the server
     issues a **new** EphemeralKey per the §6.8.2 rules and **MUST NOT accept the same EphemeralKey
     again** (anti-replay). `EphemeralKeyType` carries `publicKey` + a `signature` the server creates.
   - **Status today: not implemented.** Nothing reads/writes `ECDHKey`/`ECDHPolicyUri` or populates the
     request/response `AdditionalHeader`. `EphemeralKeyType` exists only as a generated type.
2. **EccEncryptedSecret structure (Part 4 Table 183/186)** — NEW serialization. ExtensionObject prefix
   (TypeId/EncodingMask=1/Length) + common header (SecurityPolicyUri, Certificate, SigningTime,
   KeyDataLength) + KeyData (`SenderPublicKey` + `ReceiverPublicKey`, NOT encrypted for ECC) +
   encrypted payload (Nonce ‖ Secret ‖ PayloadPadding ‖ PayloadPaddingSize) + Signature. **Status: not
   implemented** (only the legacy RSA `LegacyEncryptedSecret`, Table 193, exists).
3. **The §6.8.3 KDF + symmetric encrypt + integrity** — NEW. Two EphemeralKeys → ECDH shared secret →
   HKDF with `SecretSalt = L ‖ UTF8("opcua-secret") ‖ SenderPublicKey ‖ ReceiverPublicKey` (L = 16-bit
   LE derived-key length); `IKM = shared secret`, `Salt = Info = SecretSalt`; Table 71 derives
   `EncryptingKey` (offset 0) + `InitializationVector` (offset = key len). Encrypt the payload with the
   policy's symmetric algorithm; **Signature is created with the SigningCertificate (asymmetric) after
   encryption** — receivers validate the cert + signature **before** decrypting. For Authenticated
   Encryption (AES-GCM) policies the GCM tag is appended after PayloadPaddingSize and the AAD is all
   the headers. **Status: only the low-level `generate_ephemeral_keypair`/ECDH/HKDF primitives (012)
   exist; the secret KDF (the `opcua-secret` salt) + this serialization are not implemented.**
4. **Wiring** into the server decrypt (`decrypt_identity_token_secret`, `info.rs`) and client encrypt
   (`session.rs`) identity-token paths, dispatching ECC vs legacy-RSA by policy.

## Pinned facts

- Correct spec refs: **Part 4 §7.40.2.3/§7.40.2.5** (EncryptedSecret / EccEncryptedSecret), **Part 6
  §6.8.2** (token EphemeralKey handshake) + **§6.8.3** (ECC encrypted-secret KDF).
- `generate_ephemeral_keypair`, `EphemeralPrivateKey`/`EphemeralPublicKey`, `ecdh_shared_secret`, and
  the HKDF derivation already exist in `async-opcua-crypto/src/ecc.rs` (feature 012) and are
  RFC-vector-validated — reuse them. The **secret KDF salt differs** from the channel salt
  (`opcua-secret` vs the channel's client/server labels), so a new derivation entry point is needed.
- The 012 ECC policies are `AesPolicy<EccNistP256Symmetric>` / `<EccNistP384Symmetric>`
  (`security_policy.rs`). **[CONFIRM at planning]** whether these are AES-CBC+HMAC or AES-GCM — this
  decides the integrity path (asymmetric Signature over the structure for CBC; GCM tag for GCM) and the
  padding/AAD rules (§6.8.3). The spec example uses `ECC-nistP256-AesGcm`.
- The `Certificate` field for the user-token-over-SecureChannel case MAY be null/empty when the signing
  cert is the client ApplicationInstance certificate already known to the server.

## Decision: split or scope up (needs user input — see report)

This is **not** a small feature. Realistic decomposition:
- **015a — Token EphemeralKey exchange** (Part 6 §6.8.2): AdditionalHeader `ECDHPolicyUri`/`ECDHKey`
  plumbing on client + server; server ephemeral key generation, signing, per-session tracking, and
  anti-replay; `EphemeralKeyType` signing/verification.
- **015b — EccEncryptedSecret** (Part 4 §7.40.2.5 + Part 6 §6.8.3): the structure (de)serialization,
  the `opcua-secret` KDF, symmetric encrypt/decrypt + integrity, nonce binding; server-decrypt +
  client-encrypt wiring for UserName + Issued tokens.

015b depends on 015a (it needs the exchanged ephemeral keys). Either ship as one large multi-story
feature, or as two sequential features. Recommend confirming with the user before writing tasks,
because the spec's user-story split (US1 decrypt / US2 encrypt / US3 issued / US4 rollout) omits the
EphemeralKey-exchange layer entirely and the effort is materially higher than the spec suggested.

## Constraints carried forward

Pure-Rust (reuse 012 RustCrypto ECDH/HKDF/AES; no OpenSSL/C); fail-closed + single uniform decrypt
error (no oracle); panic-free on attacker bytes; legacy RSA + `None` byte-identical; behind the `ecc`
feature; `clippy --all-targets --all-features` clean. EphemeralKey anti-replay (§6.8.2) is a hard
requirement, aligning with the nonce-replay protection from feature 014.

## DECIDED (2026-06-21)

User chose the split. **This feature (015) = phase A: the EphemeralKey exchange (§6.8.2).** The
`EccEncryptedSecret` structure + KDF + secret encrypt/decrypt + identity-token wiring
(§7.40.2.5 / §6.8.3) is **feature 016**, which depends on this. The spec/plan/data-model/contracts/
quickstart in this directory are scoped to phase A.
