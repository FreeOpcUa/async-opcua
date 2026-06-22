# Feature Specification: Part-14 Conformant UADP PubSub Message Security

**Feature Branch**: `026-pubsub-message-security`
**Created**: 2026-06-22
**Status**: Draft
**Input**: User description: round-2 security finding split-out — replace the proprietary secured-UADP envelope with OPC UA Part 14 conformant NetworkMessage security (AES-CTR, SecurityHeader/MessageNonce/SecurityFooter), eliminating the static-IV reuse and adding subscriber replay protection, verified for interop against an external Part-14 stack.

## Background & Problem Statement

The async-opcua PubSub crate today secures UADP NetworkMessages with a **proprietary
envelope** (`async-opcua-pubsub/src/security/codec.rs`): an 8-byte magic `OPCUAPS1`, a
security-mode byte, big-endian length fields, the policy URI, then AES-CBC ciphertext with
block padding and an appended HMAC. This format is **not** OPC UA Part 14 §7.2 and therefore
cannot interoperate with any other OPC UA implementation (.NET reference stack, open62541,
Unified Automation, etc.).

Two confirmed security defects live in this path:

1. **Static initialization vector (IND-CPA key/IV reuse).** The AES-CBC IV is
   `key_nonce[..block_size]` (`security/codec.rs:260`) — a constant for the entire key epoch.
   Every `SignAndEncrypt` NetworkMessage encrypted under one key set uses the **same IV**, so
   identical plaintext blocks produce identical ciphertext blocks across messages, leaking
   plaintext equality and enabling classic CBC chosen-prefix/cut-and-paste attacks. Confirmed
   in round-2 security review.
2. **No replay protection.** The decode path reads the NetworkMessage `SequenceNumber` and
   discards it; a captured secured NetworkMessage can be replayed verbatim and is accepted.

Per OPC UA Part 14, secured UADP NetworkMessages use **AES-CTR** encryption (the
`PubSub-Aes128-CTR` / `PubSub-Aes256-CTR` symmetric policies), HMAC-SHA256 signatures, and a
**SecurityHeader** carrying a per-message `MessageNonce` from which the per-message AES-CTR
initialization vector is derived. Those policies and that header do not exist in this codebase.

This feature makes the secured UADP path conform to Part 14, which (a) eliminates the static-IV
reuse, (b) adds replay protection, and (c) makes the secured path interoperable with external
Part-14 stacks. Security correctness is paramount; the implementation is the smallest correct
diff within the Part-14 conformance target, and every decode error fails closed.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - AES-CTR PubSub symmetric policies (Priority: P1)

A PubSub publisher/subscriber operating under a `PubSub-Aes128-CTR` or `PubSub-Aes256-CTR`
security group can sign (HMAC-SHA256) and encrypt (AES-CTR) NetworkMessage bodies using keys
derived from the SKS-provisioned key material, with the AES-CTR counter block (IV) constructed
exactly as Part 14 §7.2.4 specifies from the per-message nonce and key material.

**Why this priority**: Everything else depends on the cipher being correct and spec-exact.
Without the CTR policies there is no conformant encryption primitive to build the header and
nonce handling on. CTR (a stream mode) is also what structurally removes the CBC block-padding
and the fixed-IV reuse class entirely.

**Independent Test**: Encrypt-then-decrypt round-trips for both key sizes recover the plaintext;
encryption output matches a Part-14-derived known-answer test vector (fixed key + fixed nonce →
fixed ciphertext) computed independently from the OPC UA spec, not from this implementation.

**Acceptance Scenarios**:

1. **Given** a `PubSub-Aes128-CTR` key set and a plaintext, **When** the payload is encrypted and
   then decrypted with the same key set and nonce, **Then** the recovered plaintext equals the
   original and no block padding is added (ciphertext length equals plaintext length).
2. **Given** a fixed key, fixed message nonce, and fixed plaintext drawn from a spec-anchored
   vector, **When** encrypted, **Then** the ciphertext bytes equal the independently computed
   expected vector.
3. **Given** a `PubSub-Aes256-CTR` key set, **When** signing a payload, **Then** the signature is
   HMAC-SHA256 of the correct byte range and verifies; a tampered byte makes verification fail.
4. **Given** a key set whose key/nonce lengths do not match the policy, **When** used, **Then**
   the operation fails closed with a security error (no truncation or silent acceptance).

---

### User Story 2 - Part-14 SecurityHeader and SecurityFooter (Priority: P2)

A secured UADP NetworkMessage on the wire carries the real Part-14 SecurityHeader
(SecurityFlags, SecurityTokenId, NonceLength, MessageNonce, and SecurityFooterSize) and the
SecurityFooter, replacing the proprietary `OPCUAPS1` envelope. The signature covers the
spec-defined byte range and encryption covers the spec-defined byte range, so a conformant peer
can parse and verify the message.

**Why this priority**: The header/footer framing is what makes the message conformant and
interop-capable, and it carries the `SecurityTokenId` that binds the message to an SKS key set
and the `MessageNonce` consumed by US3. It depends on US1's cipher but is independent to test.

**Independent Test**: Encode a secured NetworkMessage, then parse the raw bytes field-by-field
and confirm each SecurityHeader/SecurityFooter field matches Part 14 §7.2.2; round-trip
encode→decode recovers the original NetworkMessage for both `Sign` and `SignAndEncrypt`.

**Acceptance Scenarios**:

1. **Given** a NetworkMessage and a key set, **When** encoded with `SignAndEncrypt`, **Then** the
   output begins with the Part-14 NetworkMessage header and SecurityHeader (not the `OPCUAPS1`
   magic), with SecurityFlags indicating signed+encrypted and a non-empty MessageNonce.
2. **Given** a secured NetworkMessage, **When** decoded, **Then** the SecurityTokenId is read and
   used to select the matching key set; an unknown SecurityTokenId fails closed.
3. **Given** a secured NetworkMessage truncated at any offset, or with a length/size field that
   overflows or exceeds the configured maximum, **When** decoded, **Then** decoding fails closed
   with a security error and never panics or over-allocates.
4. **Given** a `Sign`-only message, **When** decoded, **Then** the signature over the
   header+payload+footer range verifies and the payload is recovered without decryption.

---

### User Story 3 - Per-message MessageNonce and IV (Priority: P3)

Each encoded secured NetworkMessage carries a freshly generated MessageNonce, and the AES-CTR
initialization vector is derived per-message from it, so no two messages encrypted under the same
key set ever share an IV. This is the direct remediation of the static-IV finding.

**Why this priority**: This is the core security fix the feature exists to deliver. It depends on
the header (US2) to carry the nonce and the cipher (US1) to consume the IV, so it sequences
after them, but it is the defect that motivated the work.

**Independent Test**: Encode the same NetworkMessage twice under one key set and assert the two
MessageNonces differ and the two ciphertexts differ; assert that forcing the pre-fix static-IV
behavior makes the test fail (characterization).

**Acceptance Scenarios**:

1. **Given** one key set, **When** the same plaintext NetworkMessage is encoded twice, **Then**
   the two MessageNonces differ and the two ciphertext bodies differ.
2. **Given** the per-message nonce, **When** the IV is constructed, **Then** it matches the Part-14
   §7.2.4 derivation (verified against the spec-anchored vector from US1), and reusing a nonce is
   never required for correct decode.
3. **Given** a decoded message, **When** verifying freshness inputs, **Then** a zero-length or
   missing MessageNonce on an encrypted message fails closed.

---

### User Story 4 - Subscriber replay / freshness rejection (Priority: P4)

A subscriber rejects a secured NetworkMessage that replays a previously accepted
SequenceNumber (respecting Part-14 wraparound/reset rules), so a captured-and-replayed message
is not accepted as fresh.

**Why this priority**: Replay protection is a real exposure but is independent of the encryption
fix and can ship after the conformant framing exists. It needs the decoded SequenceNumber that
US2 surfaces.

**Independent Test**: Feed a subscriber a valid secured message, then feed the identical bytes
again; the first is accepted and the second is rejected. Out-of-window/old sequence numbers are
rejected; in-order increasing sequence numbers (including a legitimate wrap/reset) are accepted.

**Acceptance Scenarios**:

1. **Given** a subscriber that accepted sequence number N, **When** a message with sequence number
   N (or any already-seen value within the window) arrives, **Then** it is rejected as a replay.
2. **Given** a subscriber, **When** sequence numbers arrive strictly increasing, **Then** all are
   accepted; **When** a Part-14-legal wraparound occurs, **Then** subsequent messages are accepted.
3. **Given** a long-running stream, **When** many messages are processed, **Then** replay-tracking
   memory stays bounded (a fixed window / last-seen check, not an unbounded nonce cache).

---

### User Story 5 - External interop verification (Priority: P5)

Secured UADP NetworkMessages produced by this implementation are decoded and verified by an
external Part-14 implementation, and messages produced by the external implementation are decoded
and verified here, for both `Sign` and `SignAndEncrypt` on at least one policy per key size.

**Why this priority**: Interop is the proof that "conformant" is real, but it depends on all the
prior stories being complete and is the most environment-sensitive (external toolchain). It can be
delivered last and, if a live cross-stack harness is infeasible in CI, downgraded to spec-anchored
known-answer vectors captured from the external stack with the gap documented.

**Independent Test**: A cross-stack harness (extending the existing .NET reference interop tests,
and/or open62541) round-trips a secured message in both directions and asserts byte-level decode
plus signature/decryption success; failing either direction fails the test.

**Acceptance Scenarios**:

1. **Given** a secured NetworkMessage encoded here, **When** the external Part-14 stack parses and
   verifies it, **Then** it recovers the original DataSet payload and signature/decryption succeed.
2. **Given** a secured NetworkMessage encoded by the external stack, **When** decoded here, **Then**
   the payload is recovered and the signature verifies.
3. **Given** CI cannot run a live external stack, **When** interop is exercised, **Then** at minimum
   spec-anchored known-answer vectors captured from the external stack pass, and the live-interop
   gap is documented in the backlog.

### Edge Cases

- A secured message whose SecurityTokenId references a key set the receiver does not hold → fail
  closed (cannot select keys).
- NonceLength = 0 (or absent) on an encrypted message → fail closed (no IV can be derived).
- SecurityFooterSize / NonceLength / payload-length fields that overflow `usize` math or exceed the
  configured maximum secured payload length → fail closed, no over-allocation, no panic.
- A message that is signed-but-not-encrypted decoded by a codec configured for `SignAndEncrypt`
  (and vice versa) → SecurityFlags mismatch fails closed.
- Tampered ciphertext, tampered signature, or tampered SecurityHeader → signature verification
  fails closed.
- Sequence number wraparound at the Part-14 boundary → accepted (not treated as replay), while a
  genuine replay of a recent value → rejected.
- Receiving the very first message of a stream (no prior sequence number) → accepted and seeds the
  replay window.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The system MUST provide the OPC UA Part 14 symmetric security policies
  `PubSub-Aes128-CTR` and `PubSub-Aes256-CTR`, with AES-CTR encryption, HMAC-SHA256 signatures,
  and the key/signing-key/nonce lengths specified by Part 14 for each policy.
- **FR-002**: Encryption of secured NetworkMessage bodies MUST use AES-CTR (a stream mode with no
  block padding); the encrypted byte range MUST equal the Part-14-specified range.
- **FR-003**: The AES-CTR initialization vector (counter block) MUST be constructed exactly as OPC
  UA Part 14 §7.2.4 specifies from the per-message MessageNonce and key material; the exact byte
  layout MUST match the spec (resolved in research) and MUST be validated against an independently
  computed, spec-anchored known-answer vector.
- **FR-004**: Each encoded secured NetworkMessage MUST carry a freshly generated MessageNonce such
  that no two messages encrypted under the same key set share an IV.
- **FR-005**: Secured NetworkMessages MUST be framed with the Part-14 SecurityHeader
  (SecurityFlags, SecurityTokenId, NonceLength, MessageNonce, SecurityFooterSize) and SecurityFooter;
  the proprietary `OPCUAPS1` envelope MUST be removed.
- **FR-006**: The signature MUST cover the Part-14-specified byte range
  (SecurityHeader + payload + SecurityFooter as applicable) and MUST be verified before any use of
  decrypted plaintext where the spec sequences verification before consumption.
- **FR-007**: The SecurityTokenId MUST identify the SKS key set used; decoding MUST select keys by
  SecurityTokenId and MUST fail closed (security error) when no matching key set is held.
- **FR-008**: A subscriber MUST reject a secured NetworkMessage that replays an
  already-accepted SequenceNumber, honoring Part-14 wraparound/reset semantics, and MUST accept the
  first message of a stream and strictly increasing sequence numbers.
- **FR-009**: Replay/freshness tracking MUST use bounded memory (a fixed window or last-seen value),
  not an unbounded per-message nonce cache; the bound and its upgrade path MUST be documented in code.
- **FR-010**: Every decode/verify failure (truncation, length/size overflow, exceeded maximum,
  unknown token, nonce/footer/flags inconsistency, bad padding-equivalent, bad signature, failed
  decryption, replay) MUST fail closed with a security error and MUST NOT panic or over-allocate.
- **FR-011**: The implementation MUST add no new runtime dependency; it MUST reuse the AES/cipher
  stack already present for secure-channel crypto. Any unavoidable new dependency MUST be called out
  explicitly for approval before adoption.
- **FR-012**: Secured NetworkMessages produced by this implementation MUST be decodable and
  verifiable by an external Part-14 implementation, and vice versa, for both `Sign` and
  `SignAndEncrypt` on at least one policy per key size; where a live external harness is infeasible
  in CI, spec-anchored known-answer vectors captured from the external stack MUST stand in and the
  gap MUST be documented.
- **FR-013**: The change to the secured-UADP wire format is a deliberate breaking change; it MUST be
  documented as such. No backward-compatibility shim for the old `OPCUAPS1` format is required given
  the format was proprietary and pre-release (no compat shim unless a deployed consumer is identified).

### Key Entities *(include if feature involves data)*

- **SecurityHeader**: Per-message Part-14 header. Attributes: SecurityFlags (signed/encrypted/footer
  indicators), SecurityTokenId (selects SKS key set), NonceLength, MessageNonce (per-message),
  SecurityFooterSize.
- **MessageNonce**: Per-message random/counter value carried in the SecurityHeader; the AES-CTR IV is
  derived from it. Must be unique per message under a given key set.
- **SecurityFooter**: Trailing Part-14 structure (size declared in the header).
- **AES-CTR PubSub security policy**: Named policy (`PubSub-Aes128-CTR` / `PubSub-Aes256-CTR`)
  defining cipher, signature algorithm, and key/nonce lengths.
- **SecurityKeySet / SecurityTokenId**: SKS-provisioned signing key, encryption key, and key nonce,
  identified on the wire by SecurityTokenId (the GetSecurityKeys / SecurityGroupKeys plumbing already
  exists server-side and is reused, not changed).
- **Replay window**: Bounded subscriber-side state tracking accepted SequenceNumbers for freshness.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Encoding the same NetworkMessage twice under one key set yields two different
  ciphertexts and two different MessageNonces (0% IV reuse across messages).
- **SC-002**: A byte-for-byte replay of a previously accepted secured NetworkMessage is rejected
  100% of the time, while legitimate strictly-increasing and Part-14-wraparound sequences are
  accepted 100% of the time.
- **SC-003**: AES-CTR encryption output matches independently computed, spec-anchored known-answer
  vectors for both `PubSub-Aes128-CTR` and `PubSub-Aes256-CTR`.
- **SC-004**: A conformant external Part-14 implementation decodes and verifies messages produced
  here, and messages it produces are decoded and verified here, for `Sign` and `SignAndEncrypt` on at
  least one policy per key size (or, where infeasible in CI, spec-anchored external vectors pass with
  the live-interop gap documented).
- **SC-005**: Every malformed/hostile secured payload (truncation, overflow, unknown token,
  inconsistent flags/nonce/footer, tampered bytes) is rejected with a security error and zero panics
  or unbounded allocations across the fuzz/negative-test corpus.
- **SC-006**: No new runtime dependency is added; `cargo clippy --all-targets --all-features`, the
  `no-default-features` leg, and the `json`-off leg are clean under `-D warnings`, and the fork's full
  Actions CI is green.

## Assumptions

- The SKS server-side plumbing (`GetSecurityKeys` / `SecurityGroupKeys` and `SecurityTokenId`
  semantics) is sufficient to provision and identify key sets; this feature reuses it and does not
  change the SKS protocol.
- An AES/CTR-capable cipher is already available transitively via the existing secure-channel crypto
  stack (to be confirmed in the plan/research phase); if not, the no-new-dependency constraint is
  re-raised with the user before proceeding.
- The exact Part-14 byte layout for the SecurityHeader, MessageNonce, and AES-CTR IV derivation is
  resolved authoritatively from the OPC UA Part 14 (1.04/1.05) §7.2.2/§7.2.4 spec text during
  research, and encoded as match-the-spec requirements rather than guesses.
- The secured-UADP path is pre-release/proprietary; removing the `OPCUAPS1` envelope breaks no
  deployed external consumer (a compatibility shim is added only if such a consumer is identified).
- Verification division holds: production code is implemented by codex (no tests, no git); all tests
  are authored and run independently by Claude, anchored to Part 14 and the external interop stack,
  not to the implementation under test.
- PRs target the fork `occamsshavingkit/async-opcua`, not upstream `FreeOpcUa/async-opcua` (pending
  private disclosure).

## Out of Scope

- JSON NetworkMessage security (Part 14 JSON encoding) — UADP only.
- PubSub security for transports beyond what the existing codec path serves.
- Changes to the SKS protocol beyond consuming the existing `GetSecurityKeys` / `SecurityGroupKeys`.
- The unkeyed-CRC OPC UA Safety "black channel" (separate crate; per-spec by design, not a defect).
- Upstream (`FreeOpcUa`) PRs while private security disclosure is pending.
