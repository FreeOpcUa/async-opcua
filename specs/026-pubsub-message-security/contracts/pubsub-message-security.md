# Contract: PubSub Message Security (crypto policy + UADP codec)

Behavioral contract for the public surface this feature adds/changes. Anchored to Part 14
§7.2.4.4 (see [research.md](./research.md)). "MUST" items are acceptance criteria for tests.

## 1. SecurityPolicy (async-opcua-crypto)

New variants `PubSub-Aes128-CTR`, `PubSub-Aes256-CTR`.

- `to_uri()` / `from_uri()` MUST round-trip the OPC UA URIs
  `http://opcfoundation.org/UA/SecurityPolicy#PubSub-Aes128-CTR` and `…#PubSub-Aes256-CTR`.
- `encrypting_key_length()` MUST be 16 (Aes128) / 32 (Aes256).
- `symmetric_signature_size()` MUST be 32 (HMAC-SHA256).
- A new accessor MUST expose the policy's KeyNonce length = 4 and MessageNonce length = 8.
- `symmetric_encrypt(keys, src, dst)` MUST perform AES-CTR (no padding, `dst.len() == src.len()`)
  using a counter block built per Table 157; `symmetric_decrypt` is the same operation (CTR is its
  own inverse). The counter block + key MUST come from `keys`/the per-message nonce, NOT a static
  key-epoch IV.
- `symmetric_sign` / `symmetric_verify_signature` MUST be HMAC-SHA256 over the caller-supplied byte
  range.
- Mismatched key/nonce lengths MUST return an `Err` (no silent truncation).

### AES-CTR known-answer (MUST, SC-003)
Given fixed `EncryptingKey`, `KeyNonce[4]`, `MessageNonce[8]`, and plaintext, the ciphertext MUST
equal an independently computed vector where the first keystream block =
`AES_enc(KeyNonce ‖ MessageNonce ‖ 0x00000001)`, the second uses `…0x00000002`, etc., XORed with
plaintext. (Vector computed from the spec, not from this implementation.)

## 2. UADP secured NetworkMessage codec (async-opcua-pubsub)

### Encode (`Sign` and `SignAndEncrypt`)
- MUST set ExtendedFlags1 bit 4 (SecurityHeader enabled).
- MUST emit the SecurityHeader (SecurityFlags, SecurityTokenId, NonceLength=8, MessageNonce) in
  spec order, with bit2=0 (no SecurityFooter for AES-CTR).
- `SignAndEncrypt` MUST set SecurityFlags bits 0+1; `Sign` MUST set bit 0 only.
- MUST generate a fresh MessageNonce = `Random[4] ‖ NetworkMessageSequenceNumber(UInt32)` per
  message; two messages under one key set MUST have different MessageNonces and (for encrypt)
  different ciphertext for identical plaintext (SC-001).
- For `SignAndEncrypt`: MUST AES-CTR-encrypt only the Payload region in place, then compute
  HMAC-SHA256 over the **entire** NetworkMessage (headers + ciphertext) and append it as Signature.
- MUST NOT emit the legacy `OPCUAPS1` magic.

### Decode
- MUST select the key set by SecurityTokenId; unknown/absent token → `Err` (fail closed).
- MUST verify the Signature over the whole message **before** decrypting (verify-then-decrypt);
  bad signature → `Err`.
- MUST then AES-CTR-decrypt the Payload and decode the DataSetMessages.
- MUST reject, with a security error and without panic or unbounded allocation: truncated message;
  NonceLength/SecurityFooterSize/payload length that overflows or exceeds `max_secured_payload_len`;
  reserved SecurityFlags bit set; encrypted-bit set with NonceLength≠8; SecurityFlags/SecurityMode
  mismatch vs the codec's configured mode; tampered header/ciphertext/signature.

### Replay (subscriber, US4)
- MUST reject a NetworkMessage whose SequenceNumber was already accepted within the window (replay)
  or is older than the window floor (stale).
- MUST accept the first message of a stream and strictly increasing sequence numbers, and MUST
  tolerate benign reordering within a fixed window W.
- MUST reset replay state on SecurityTokenId change (SequenceNumber resets to 1 per spec).
- Replay state MUST be bounded (fixed window; no unbounded cache).

## 3. Interop (US5)
- A signed+encrypted NetworkMessage encoded here MUST be decodable + verifiable by an external
  Part-14 stack, and vice versa, for `Sign` and `SignAndEncrypt` on ≥1 policy per key size — OR
  spec-anchored known-answer vectors captured from the external stack MUST pass, with the
  live-interop gap documented (FR-012/SC-004).

## 4. Non-functional
- No new runtime dependency beyond the approved `ctr` crate (FR-011).
- Clippy `-D warnings` across `--all-features`, `--no-default-features`, `json`-off legs.
- No secret (key, nonce, plaintext) logged.
