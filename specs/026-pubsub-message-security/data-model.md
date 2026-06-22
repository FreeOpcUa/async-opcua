# Data Model: Part-14 Conformant UADP PubSub Message Security

Entities are wire structures and in-memory security state. All sizes/offsets are from Part 14
1.05.06 (see [research.md](./research.md)).

## SecurityHeader (wire, §7.2.2.2.3)

Present iff ExtendedFlags1 bit 4 is set. Wire order:

| Field | Type | Size | Rules |
|---|---|---|---|
| SecurityFlags | Byte | 1 | bit0 Signed, bit1 Encrypted, bit2 SecurityFooter, bit3 ForceKeyReset, bits4-7 reserved=0. bit0 MUST be 1 if bit1 is 1. Receiver MUST reject if any reserved bit is set. |
| SecurityTokenId | UInt32 (IntegerId) | 4 | Selects the key set in the SecurityGroup. MUST be 0 iff bits1&2 both 0. |
| NonceLength | Byte | 1 | =8 for AES-CTR. MUST be 0 iff bits1&2 both 0. |
| MessageNonce | Byte[NonceLength] | 8 (CTR) | Per-message unique nonce (see MessageNonce entity). |
| SecurityFooterSize | UInt16 | 2 | Present only if bit2=1. **Omitted for AES-CTR** (no footer). |

**Validation**: NonceLength and SecurityFooterSize are attacker-controlled length fields — bounds-check
before reading/allocating; reject (security error) on truncation, overflow, reserved-bit set,
flags/length inconsistency (e.g. encrypted bit set but NonceLength≠8), or SecurityTokenId not held.

## MessageNonce (wire, Table 156 — 8 bytes)

| Sub-field | Type | Size | Rule |
|---|---|---|---|
| Random | Byte[4] | 4 | Pseudo-random; fresh per NetworkMessage. |
| SequenceNumber | UInt32 | 4 | NetworkMessage sequence number (§7.2.3); resets to 1 after key/SecurityTokenId update. |

## AES-CTR counter block (derived, Table 157 — 16 bytes, not on the wire)

| Sub-field | Bytes | Source |
|---|---|---|
| KeyNonce | 0–3 | KeyNonce from key data (Table 155). |
| MessageNonce | 4–11 | The 8-byte SecurityHeader MessageNonce. |
| BlockCounter | 12–15 | 32-bit **big-endian**, starts at 1, +1 per 16-byte block. |

## NetworkMessage additions (`UadpNetworkMessage`, `codec/uadp.rs`)

Current struct: `{ publisher_id, writer_group_id, dataset_messages }`. Conformance adds:

| Field | Type | Notes |
|---|---|---|
| network_message_number | u16 | GroupHeader field (currently absent). |
| sequence_number | u32 | **NetworkMessage-level** SequenceNumber (GroupHeader); distinct from the existing DataSetMessage-level u16. Feeds MessageNonce + replay. |

GroupHeader on the wire gains NetworkMessageNumber + SequenceNumber (gated by GroupFlags bits), per
Figure A.3.

## Key data (Table 155) → SecurityKeySet

`GetSecurityKeys` returns concatenated `SigningKey ‖ EncryptingKey ‖ KeyNonce`, split by the policy:

| Policy | SigningKey | EncryptingKey | KeyNonce | Total |
|---|---|---|---|---|
| PubSub-Aes128-CTR | 32 | 16 | 4 | 52 |
| PubSub-Aes256-CTR | 32 | 32 | 4 | 68 |

`SecurityKeySet { signing_key: Vec<u8>(32), encryption_key: AesKey(16|32), key_nonce: Vec<u8>(4) }`
— note CTR `key_nonce` is **4 bytes** (the counter-block prefix), not the 16-byte CBC IV the current
code expects.

## SecurityToken binding

`SecurityGroup` (currently `{ group_id, current_key, next_key, key_lifetime }`) gains token-id
awareness so a decoded `SecurityTokenId` selects `current` vs `next` (or rejects). Mirrors the
server `SecurityGroupKeys { security_policy_uri, first_token_id, keys[], key_lifetime,
current_key_started_at }` (token N → keys[N - first_token_id]).

## ReplayWindow (in-memory, `security/replay.rs`, US4)

| Field | Type | Notes |
|---|---|---|
| token_id | u32 | Current SecurityTokenId; window resets when this changes. |
| highest_seq | u32 | Highest accepted NetworkMessage SequenceNumber. |
| window | fixed bitmap (W bits, e.g. 64) | Marks recently-seen sequence numbers below `highest_seq`. |

**Transitions**: first message seeds `highest_seq`. seq > highest_seq → accept, shift window. seq
within `[highest_seq-W+1, highest_seq]` and unseen → accept, set bit. seq seen, or < window floor →
**reject (replay/stale)**. SecurityTokenId change → reset (seq restarts at 1 per spec). Wraparound
handled per §7.2.3 reset semantics. Bounded memory (FR-009).

## State / lifecycle

- **Publisher encode**: pick current key set + its SecurityTokenId → increment NetworkMessage
  SequenceNumber → build MessageNonce (Random‖seq) → encode headers + SecurityHeader (plaintext) →
  AES-CTR encrypt Payload in place → HMAC-SHA256 over the whole message → append Signature.
- **Subscriber decode**: parse headers + SecurityHeader → select key set by SecurityTokenId (reject
  if absent) → verify Signature over the whole message (reject if bad) → AES-CTR decrypt Payload →
  replay-check NetworkMessage SequenceNumber (reject if replayed/stale) → decode DataSetMessages.
