# Quickstart: verifying Part-14 UADP PubSub message security

How to exercise and verify this feature during/after implementation. Spec facts: [research.md](./research.md).

## Build / lint (must be green before "done")

```bash
# crypto crate (CTR policies)
cargo test -p async-opcua-crypto --all-features
# pubsub crate (codec, security, replay)
cargo test -p async-opcua-pubsub --all-features
# the three clippy legs the fork CI gates on
cargo clippy --all-targets --all-features -- -D warnings
cargo clippy --no-default-features -p async-opcua -p async-opcua-types -p async-opcua-crypto -p async-opcua-pubsub -- -D warnings
# json-off leg
cargo clippy --all-targets --no-default-features --features <pubsub-min-without-json> -- -D warnings
cargo deny check            # ctr crate must pass advisories
```

## Spec-anchored verification (the ground truth — authored by Claude, not codex)

1. **AES-CTR KAT (US1, SC-003)** — `async-opcua-pubsub/tests/message_security_vectors.rs`:
   fixed EncryptingKey + KeyNonce[4] + MessageNonce[8] + plaintext → assert ciphertext equals the
   vector computed as `XOR(plaintext, keystream)` where keystream block k =
   `AES_enc(KeyNonce ‖ MessageNonce ‖ BE32(k))`, k from 1. Verify for Aes128 and Aes256.

2. **IV uniqueness / static-IV fix (US3, SC-001)**: encode the same NetworkMessage twice under one
   key set; assert the two MessageNonces differ AND the two ciphertexts differ. Confirm this test
   FAILS against the pre-fix static-IV path (characterization).

3. **SecurityHeader field check (US2)**: encode SignAndEncrypt, then parse raw bytes: ExtendedFlags1
   bit4=1; SecurityFlags bits0,1=1, bit2=0; SecurityTokenId present; NonceLength=8; 8-byte nonce; no
   `OPCUAPS1` magic.

4. **Fail-closed negative corpus (US2, SC-005)**: truncated message; NonceLength≠8 with encrypt bit;
   reserved SecurityFlags bit set; oversized payload (> `max_secured_payload_len`); unknown
   SecurityTokenId; flipped byte in header / ciphertext / signature → each returns `Err`, no panic.
   (Add a `cargo fuzz` or property target over the decode path if practical.)

5. **Replay (US4, SC-002)** — `async-opcua-pubsub/tests/replay_tests.rs`: feed a valid message, then
   the identical bytes → first accepted, second rejected. Out-of-window/old seq rejected;
   strictly-increasing accepted; benign reorder within W accepted; SecurityTokenId change resets.

6. **Interop (US5, SC-004)**: round-trip against `dotnet-tests/external-tests` (extend its
   `pubsub_tests.rs` to SignAndEncrypt) and/or open62541; or assert committed external KAT fixtures
   decode+verify here and our output matches the external bytes. Document any live-interop gap.

## Manual smoke (optional)

Use the demo PubSub publisher/subscriber with a CTR security group configured; capture a UDP
NetworkMessage and confirm with an external tool (Wireshark OPC UA PubSub dissector / open62541)
that the SecurityHeader and ciphertext parse as Part-14.

## Done criteria
- All six verification groups pass; the static-IV characterization test fails pre-fix / passes
  post-fix; clippy legs + cargo-deny green; fork Actions CI green; no `OPCUAPS1` / "experimental
  proprietary" remnants left in the tree (Principle V).
