# Data Model: ECC EncryptedSecret

## EccEncryptedSecret envelope (Part 4 §7.40.2.5, Table 186)

Hand-serialized binary structure (UA Binary encoding). Fields in serialization order:

- **TypeId** — NodeId of the `EccEncryptedSecret` DataType (ExtensionObject prefix).
- **EncodingMask** — Byte, always `1`.
- **Length** — Int32, byte length of everything after this field, *including* the Signature. Validate
  against the available buffer before reading (bound, fail-closed).
- **SecurityPolicyUri** — String, the ECC policy URI (`ECC_nistP256`/`ECC_nistP384`).
- **Certificate** — ByteString, signing-cert DER chain; null/empty in the UserIdentityToken-over-channel
  case (server uses the known client ApplicationInstance cert).
- **SigningTime** — DateTime.
- **KeyDataLength** — UInt16, byte length of the (unencrypted) KeyData.
- **KeyData**: { **SenderPublicKey**: ByteString, **ReceiverPublicKey**: ByteString } — ephemeral public
  keys (curve-encoded per policy). Not encrypted for ECC.
- **Payload** (AES-CBC encrypted as one blob — AES-128 P-256 / AES-256 P-384): { **Nonce**: ByteString, **Secret**: ByteString,
  **PayloadPadding**: Byte[*], **PayloadPaddingSize**: UInt16 }.
- **Signature** — Byte[*], asymmetric ECDSA over all preceding bytes (per Figure 39).

**Validation rules (decrypt)**: bound Length/KeyDataLength/ByteString-lengths/PayloadPaddingSize before
allocating → validate SigningCertificate + verify Signature → decrypt payload → verify padding (every
byte = LSB of size; size in range) → check Nonce == current server nonce → extract Secret. Any failure →
single uniform `BadIdentityTokenRejected`, no panic.

## §6.8.3 derived keys

- **Inputs**: ECDH shared secret (x-coord, zero-padded big-endian), SenderPublicKey, ReceiverPublicKey,
  curve (→ hash + lengths).
- **SecretSalt** = `L(le16) | "opcua-secret" | SenderPublicKey | ReceiverPublicKey`, `L = EncKeyLen + IvLen`
  (EncKeyLen per curve: 16 P-256 / 32 P-384; IvLen=16).
- **Outputs (Table 71)**: `EncryptingKey` (EncKeyLen per curve — **16 for P-256/AES-128-CBC, 32 for
  P-384/AES-256-CBC**), `InitializationVector` (IvLen=16). No SigningKey (integrity is asymmetric).
  `Zeroizing`. (`L = EncKeyLen + 16`.)

## Server EphemeralKey consumed-state (closes 015a deferral)

- Per-session: the server EphemeralKey is `issued` (015a) → becomes `consumed` after it successfully
  decrypts an identity-token secret.
- Transition: `issued --(successful decrypt)--> consumed`. A consumed key MUST NOT decrypt again and MUST
  drive `decide_ecdh_key_action(..., previous_key_consumed = true)` → `Issue(prev)` (fresh key) on the
  next ActivateSession.
- Replay guard: a second EccEncryptedSecret relying on the consumed server EphemeralKey (or an identical
  duplicate envelope) is rejected.

## Identity-token secret (plaintext)

- `UserNameIdentityToken.password` (ByteString) or `IssuedIdentityToken.tokenData` (ByteString) — the
  `Secret` carried in the payload. UTF-8 for string passwords.

## Relationships

- Consumes 015a: client `Session.retained_server_ephemeral_key` (ReceiverPublicKey on encrypt); server
  `Session.ecdh_ephemeral_key` (its private key on decrypt; the consumed-state lives here).
- Reuses 012/015a primitives: `ecdh_shared_secret`, `Hkdf::<Sha256/384>`, `AesKey` (AES-128/256-CBC per curve),
  `SecurityPolicy::asymmetric_sign`/`asymmetric_verify_signature`.
