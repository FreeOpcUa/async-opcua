# Research: Part-14 Conformant UADP PubSub Message Security

All wire-format facts below are confirmed against the **local authoritative spec**
`~/opcua-specs/OPC 10000-14 - UA Specification Part 14 - PubSub 1.05.06.pdf` (extracted via
`pdftotext -layout`), cross-checked with Part 14 §7.2.4.4.3 / §7.2.2.2.3 / Annex A.4 and the
OPC Foundation online reference. Section/Table numbers are quoted so the implementer can re-open
the exact page.

## Confirmed wire format (Part 14 §7.2.4.4 + Annex A.4, Figure A.3 / Tables 155–157)

### NetworkMessage header flag that enables security
- **ExtendedFlags1 bit 4 = "SecurityHeader enabled"** (§7.2.2.2, line "Bit 4: SecurityHeader enabled").
  When set, the SecurityHeader is present; otherwise omitted. For a signed/signed+encrypted
  message: ExtendedFlags1 bits 3,5,6 = false, bits 4 and 7 = true (§A.2.1.5/A.4).

### NetworkMessage-level SequenceNumber (NEW — current impl lacks it)
- Figure A.3 places a **NetworkMessage SequenceNumber** (and NetworkMessageNumber) in the
  **Group Header** region, before the SecurityHeader. The MessageNonce's `SequenceNumber`
  (Table 156) is this NetworkMessage sequence number "as defined in 7.2.3". The current
  `UadpNetworkMessage` has only a DataSetMessage-level `sequence_number` (u16); conformance adds
  the NetworkMessage-level SequenceNumber (UInt32) — it is what replay protection (US4) keys on.

### SecurityHeader fields, in wire order (§7.2.2.2.3)
| Field | Type | Notes |
|---|---|---|
| SecurityFlags | Byte | bit0 Signed, bit1 Encrypted, bit2 SecurityFooter enabled, bit3 ForceKeyReset, bits4-7 reserved (must be 0; receiver skips messages with reserved bits set). "bit0 shall be true if bit1 is true." |
| SecurityTokenId | IntegerId (UInt32) | ID of the security token identifying the key in the SecurityGroup; relation via DataSetWriterIds. If bits 1 and 2 are 0, shall be 0. |
| NonceLength | Byte | For AES-CTR **shall be 8**. If bits 1 and 2 are 0, shall be 0. |
| MessageNonce | Byte[NonceLength] | Unique per NetworkMessage per key; layout per §7.2.4.4.3.2 (Table 156). |
| SecurityFooterSize | UInt16 | **Omitted** when SecurityFooter bit (bit2) is 0. |

### Message order (§7.2.2.2.3, Figure A.3)
`UADPFlags ‖ ExtendedFlags1[‖ExtendedFlags2] ‖ PublisherId ‖ [DataSetClassId] ‖ GroupHeader
(WriterGroupId, GroupVersion, NetworkMessageNumber, SequenceNumber) ‖ [PayloadHeader] ‖
[Timestamp][PicoSeconds] ‖ [PromotedFields] ‖ SecurityHeader ‖ Payload(encrypted if bit1) ‖
[SecurityFooter if bit2] ‖ Signature(when signed)`

- **Only the Payload region is encrypted** (AES-CTR, in place, no size change). Headers are
  plaintext but covered by the signature.
- **Signature is over the ENTIRE NetworkMessage including the ciphertext** (§7.2.4.4.3.2: "The
  signature is calculated on the entire NetworkMessage including any encrypted data."). →
  encrypt-then-MAC on send; verify-then-decrypt on receive (satisfies FR-006).

### Key data (Table 155) and AES-CTR specifics (Tables 156–157)
- **Key data layout (Table 155)**: `SigningKey[sig-key-len] ‖ EncryptingKey[enc-key-len] ‖
  KeyNonce[enc-nonce-len]`, concatenated, returned by `GetSecurityKeys`.
- **MessageNonce (Table 156, 8 bytes)**: `Random Byte[4]` (pseudo-random OK) ‖ `SequenceNumber
  UInt32`. SequenceNumber **resets to 1 after the key and SecurityTokenId are updated**.
- **AES-CTR counter block (Table 157, 16 bytes)**:
  `KeyNonce Byte[4]` (offset 0–3, from key data) ‖ `MessageNonce Byte[8]` (offset 4–11, the first
  8 bytes of the SecurityHeader Nonce) ‖ `BlockCounter Byte[4]` (offset 12–15, **32-bit
  big-endian**, **starts at 1**, +1 per 16-byte block). No padding; ciphertext length = plaintext
  length.

### Per-policy lengths (derived from Table 155/157 + AES + the policy's HMAC-SHA256 signature)
| Policy | EncryptingKey | KeyNonce | SigningKey (HMAC-SHA256) | Signature | Key-data total |
|---|---|---|---|---|---|
| `PubSub-Aes128-CTR` | 16 | 4 | 32 | 32 (HMAC-SHA256) | 52 |
| `PubSub-Aes256-CTR` | 32 | 4 | 32 | 32 (HMAC-SHA256) | 68 |

KeyNonce = 4 bytes is fixed by Table 157 (`KeyNonce Byte[4]`). The signature algorithm
(SymmetricSignatureAlgorithm) is HMAC-SHA256 for both CTR policies — to be re-confirmed against
the Part 7 facet during US1, but it matches the existing `Basic256Sha256` HMAC-SHA256/32-byte
signature already in the crypto crate.

> NOTE: the current `security/codec.rs` truncates `key_nonce` to the 16-byte AES block as the CBC
> IV. For CTR the KeyNonce is only the 4-byte counter-block prefix — the SecurityKeySet `key_nonce`
> for CTR policies is 4 bytes, not 16.

## Decisions

### D1 — AES-CTR via the RustCrypto `ctr` crate (`Ctr32BE`) — USER APPROVED
- **Decision**: add `ctr` (RustCrypto) and use `Ctr32BE<aes::Aes128>` / `Ctr32BE<aes::Aes256>`.
- **Rationale**: `Ctr32BE` treats the **last 32 bits** of the 16-byte counter block as a big-endian
  counter incremented per block — an exact match for Table 157 (fixed 12-byte `KeyNonce‖MessageNonce`
  prefix + 32-bit BE BlockCounter). The initial counter block is `KeyNonce(4) ‖ MessageNonce(8) ‖
  0x00000001` (BlockCounter starts at 1). `ctr` is the same RustCrypto family as the `cbc` crate
  already in the tree, shares the already-compiled `cipher` traits (no new transitive deps), is
  maintained, and has no known advisory (passes cargo-deny). Using a vetted mode crate over
  hand-rolled CTR honors "Security Is Paramount" + "Do It Right Once" and ponytail's "pick the impl
  correct on edge cases."
- **Alternatives considered**: hand-roll CTR over the existing `aes` block cipher (zero new deps,
  ~15 lines) — rejected by the user in favor of the audited crate; aws-lc-rs CTR — rejected (the
  symmetric path uses RustCrypto, not aws-lc-rs; would mix backends).
- **Version**: `ctr = "0.9"` (cipher 0.4, matching `cbc` 0.1 / `aes` 0.8). Add to workspace `Cargo.toml`
  and `async-opcua-crypto/Cargo.toml`. The Part-14-specific counter-block construction (the only
  subtle part) is verified by the Table-157 known-answer vector (SC-003), not by trusting the crate.

### D2 — Interleaved security, not a post-hoc envelope
- **Decision**: delete the `OPCUAPS1` envelope (`security/codec.rs`) entirely; integrate security
  into the UADP encode/decode (`codec/uadp.rs`) so the SecurityHeader is emitted between the
  header region and the Payload, only the Payload region is AES-CTR-encrypted in place, and the
  signature covers the whole NetworkMessage.
- **Rationale**: the spec layout is interleaved (D-section above); a post-hoc wrapper cannot produce
  a conformant, interoperable message. This is the deliberate breaking change called out in FR-013.
- **Alternatives**: keep wrapping and only swap the cipher — rejected (still non-conformant, still
  no interop, still leaks the whole plaintext structure including headers that the spec signs in clear).

### D3 — Per-message MessageNonce
- **Decision**: on encode, build MessageNonce = `Random[4]` (from the existing
  `opcua_crypto::random::bytes`) ‖ `SequenceNumber` (the NetworkMessage UInt32, incrementing per
  message within a key epoch, reset to 1 on SecurityTokenId/key change). Put the 8 bytes in the
  SecurityHeader Nonce; derive the counter block per Table 157.
- **Rationale**: SequenceNumber monotonicity within a key epoch guarantees IV uniqueness (the fix);
  Random adds defense in depth. Ceiling: UInt32 sequence space (~4.3e9 messages) per key epoch;
  key rotation occurs far sooner. `// ponytail: IV-unique while seq doesn't wrap within a key epoch
  — key rotation (well before 2^32 msgs) resets it; document, don't over-engineer.`

### D4 — Bounded subscriber replay window
- **Decision**: per SecurityGroup/SecurityTokenId, track the highest accepted NetworkMessage
  SequenceNumber plus a fixed-size sliding **anti-replay bitmap window** (IPsec-style, e.g. 64
  entries) to tolerate benign UDP reordering while rejecting duplicates and stale messages. Reset
  the window when the SecurityTokenId changes (the spec resets SequenceNumber to 1 on key update).
- **Rationale**: bounded memory (FR-009), fail-closed on replay (FR-008), and tolerant of the
  reordering real UDP transport produces. `// ponytail: fixed W-entry window; widen W only if a
  deployment shows legitimate reordering beyond it.`
- **Alternatives**: strict monotonic (drops legitimately reordered UDP packets — too brittle);
  unbounded seen-set (violates FR-009).

### D5 — SecurityFooter not emitted for AES-CTR
- **Decision**: SecurityFlags bit2 = 0; no SecurityFooter, SecurityFooterSize omitted.
- **Rationale**: AES-CTR adds no padding (Table 157 / §7.2.4.4.3.2: "No padding is added"); Annex
  A.4 shows bit2 = 0 for the sign+encrypt layout. Nothing to put in a footer.

### D6 — Reuse existing SKS plumbing; bind SecurityTokenId
- **Decision**: reuse `SecurityGroupKeys` / `GetSecurityKeys` (server) and the PubSub
  `SecurityKeySet`/`SecurityGroup`; carry `SecurityTokenId` on the wire and select the key set by it
  on decode (fail closed when no matching token is held). The PubSub `SecurityGroup` gains
  token-id awareness (it currently tracks only current/next without ids).
- **Rationale**: FR-007; no SKS protocol change (out of scope). Key-data is parsed into
  `SecurityKeySet::from_parts(signing, encrypting, key_nonce)` using the Table-155 split for the
  selected policy.

### D7 — Interop verification approach (US5)
- **Decision (primary)**: capture **Table-157 / Table-156 known-answer vectors** and at least one
  full signed+encrypted NetworkMessage vector from an external Part-14 stack, commit them as fixtures,
  and assert byte-exact encode + successful decode/verify here. **Stretch**: extend
  `dotnet-tests/external-tests` `pubsub_tests.rs` (currently plaintext UADP only) to SignAndEncrypt
  for a live round-trip; open62541 (`3rd-party/open62541`) as a second cross-check.
- **Rationale**: a live external harness in CI is environment-sensitive; spec-anchored KAT vectors
  give deterministic conformance proof now (FR-012/SC-004), with the live-interop gap documented in
  the backlog if the live harness can't run in CI.

## Open items deferred to implementation (not blocking the plan)
- Confirm the Part 7 facet lists HMAC-SHA256 as the SymmetricSignatureAlgorithm for both CTR
  policies (expected; matches Basic256Sha256). If a CTR policy specifies a different MAC, adjust the
  signing-key/signature size in US1.
- Confirm whether `Ctr32BE` applies keystream starting from the supplied counter value (block 0 uses
  the IV as-is) — pin exactly with the Table-157 KAT before wiring the codec.
