# Feature Specification: ECC EncryptedSecret for Identity Tokens (Part 4 §7.40.2.5 / Part 6 §6.8.3)

**Feature Branch**: `016-ecc-encrypted-secret`
**Created**: 2026-06-21
**Status**: Draft
**Input**: Implement OPC UA Part 4 §7.40.2.5 `EccEncryptedSecret` — encrypt/decrypt the
`UserNameIdentityToken` (password) and `IssuedIdentityToken` (token data) secrets under the ECC NIST
security policies. **Phase B of two** — the follow-on to feature 015a (the EphemeralKey exchange,
Part 6 §6.8.2, merged PR #44). 016 consumes the exchanged ECC EphemeralKeys to actually wrap/unwrap
the identity-token secret, and wires the consumed-key anti-replay that 015a deferred.

## Context *(mandatory)*

Under an ECC `SecurityPolicy` (`ECC_nistP256` / `ECC_nistP384`), a client must encrypt the
`UserNameIdentityToken` password (and the `IssuedIdentityToken` token data) as an **`EccEncryptedSecret`**
(Part 4 §7.40.2.5, Tables 183/186) rather than the legacy RSA-OAEP secret (Table 193). The
`EccEncryptedSecret` is keyed off the ECC EphemeralKeys exchanged at CreateSession/ActivateSession:
ECDH between the client and server ephemeral keys → the Part 6 §6.8.3 HKDF → the policy's symmetric
(AES-256-CBC) + integrity layer, bound to the **current server nonce** so a captured secret cannot be
replayed.

Feature 015a delivered the exchange (server issues+signs `ECDHKey`, stores its keypair on the session;
client verifies + retains the server `ECDHKey`) but **no secret is wrapped yet**, so password / issued
identity-token authentication does **not** work over the ECC policies. Today async-opcua only
implements the legacy RSA secret path (`legacy_encrypt_secret` / `legacy_decrypt_secret`,
`decrypt_identity_token_secret`). This feature implements the `EccEncryptedSecret` itself and wires it
into the client (encrypt) and server (decrypt) identity-token paths — completing ECC identity-token
authentication.

## User Scenarios & Testing *(mandatory)*

### User Story 1 — Server decrypts an ECC-encrypted UserName password (Priority: P1) 🎯 MVP

As a server accepting a `UserNameIdentityToken` over an ECC channel, I want to decrypt the
`EccEncryptedSecret` password using the exchanged EphemeralKeys and the server nonce, so a client can
authenticate with a password under ECC.

**Why this priority**: It is the security-critical receiving side — without server-side decrypt, ECC
password auth cannot work at all, and the decrypt is the attacker-facing, fail-closed path.

**Independent Test**: Given a crafted `EccEncryptedSecret` (built from known P-256/P-384 ephemeral keys,
the §6.8.3 KDF, and the current server nonce), the server recovers exactly the original password; a
secret bound to the wrong server nonce, with tampered ciphertext, or with a bad integrity
value/signature is rejected with a single uniform error (no oracle), never a panic.

**Acceptance Scenarios**:

1. **Given** an ECC-secured session whose EphemeralKeys were exchanged in 015a and a
   `UserNameIdentityToken` carrying an `EccEncryptedSecret` produced for the current server nonce,
   **When** the server decrypts it, **Then** it recovers the exact password bytes and authentication
   proceeds.
2. **Given** an `EccEncryptedSecret` bound to a stale/wrong server nonce, **When** decrypted, **Then**
   it is rejected (`Bad_IdentityTokenRejected` / `Bad_SecurityChecksFailed`), not accepted.
3. **Given** an `EccEncryptedSecret` whose ciphertext, IV, or integrity value/signature has been
   tampered with, **When** decrypted, **Then** it is rejected with the **same** uniform error as any
   other decrypt failure (no padding-vs-MAC distinction), never a panic.

---

### User Story 2 — Client encrypts a UserName secret as an EccEncryptedSecret (Priority: P1)

As a client SDK sending a `UserNameIdentityToken` over an ECC channel, I want to wrap the password as an
`EccEncryptedSecret` using the retained server EphemeralKey, my own ephemeral key, and the server nonce,
so the server can decrypt it (US1) and the round-trip works end-to-end.

**Why this priority**: The sending side of the same exchange; together with US1 it makes ECC password
auth function end-to-end (and gives US1 a real producer to test against).

**Independent Test**: The client produces an `EccEncryptedSecret` for the negotiated ECC policy that the
server (US1) decrypts back to the original password on real P-256/P-384 keys; the wire layout matches
§7.40.2.5 and the KDF matches §6.8.3.

**Acceptance Scenarios**:

1. **Given** an ECC session with a verified retained server `ECDHKey`, **When** the client sends a
   `UserNameIdentityToken`, **Then** the password is carried as an `EccEncryptedSecret` (not the legacy
   RSA form) bound to the current server nonce.
2. **Given** a client-produced `EccEncryptedSecret`, **When** a conformant server (or the US1 path)
   decrypts it, **Then** the recovered password equals the original (client-encrypt ↔ server-decrypt
   round-trip on P-256 and P-384).

---

### User Story 3 — IssuedIdentityToken secret under ECC (Priority: P2)

As a client/server using an `IssuedIdentityToken` over an ECC channel, I want the issued token data
wrapped/unwrapped as an `EccEncryptedSecret` exactly like the UserName password, so issued-token auth
also works under ECC.

**Why this priority**: Same cryptographic envelope as US1/US2 applied to a second token type; high value
but mechanically derivative once US1/US2 exist.

**Independent Test**: An `IssuedIdentityToken` whose `tokenData` is an `EccEncryptedSecret` round-trips
client→server on P-256/P-384; the same nonce-binding and tamper/uniform-error rejection hold.

**Acceptance Scenarios**:

1. **Given** an ECC session, **When** an `IssuedIdentityToken` is sent, **Then** its token data is an
   `EccEncryptedSecret` bound to the current server nonce, and the server recovers the original token
   data.
2. **Given** a tampered/wrong-nonce issued-token `EccEncryptedSecret`, **When** decrypted, **Then** it is
   rejected with the uniform error, never a panic.

---

### User Story 4 — Consumed-key anti-replay enforced end-to-end (Priority: P1)

As a server operator, I want a server EphemeralKey to be **consumed exactly once** — after it has
decrypted an identity-token secret it must never be accepted again — and a replayed/duplicate
`EccEncryptedSecret` rejected, so a captured secret cannot be replayed. This wires the anti-replay that
015a deferred (`previous_key_consumed` was hardwired false).

**Why this priority**: The §6.8.2/§6.8.3 anti-replay is a hard security requirement and the explicit
reason 015a deferred enforcement to this feature; it must be correct, not theater.

**Independent Test**: After a successful ActivateSession that consumed the server EphemeralKey to decrypt
a secret, presenting the same EphemeralKey / the same `EccEncryptedSecret` again is rejected; the §6.8.2
`decide_ecdh_key_action` lifecycle, now driven by the **real** consumed state, returns a fresh key for
the next activation rather than reusing the consumed one.

**Acceptance Scenarios**:

1. **Given** a server EphemeralKey that has decrypted an identity-token secret, **When** the same key (or
   the same `EccEncryptedSecret`) is presented again, **Then** the server rejects it (anti-replay).
2. **Given** a consumed server EphemeralKey, **When** the next ActivateSession is processed, **Then** the
   §6.8.2 lifecycle issues a fresh key (the `previous_key_consumed=true` branch now fires from real
   state), never reusing the consumed key.

---

### User Story 5 — Rollout & backward compatibility (Priority: P3)

As an operator, I want ECC `EccEncryptedSecret` added behind the `ecc` feature without changing the
legacy RSA secret path or the `None` policy.

**Independent Test**: RSA endpoints still use the legacy secret (byte-identical), `None` sends the secret
unencrypted as before, and the `ecc`-off build behaves identically to today; the policy selects RSA vs
ECC vs None correctly.

**Acceptance Scenarios**:

1. **Given** an RSA endpoint or `None` policy, **When** an identity-token secret is sent/received,
   **Then** the legacy/None behavior is byte-identical to today.
2. **Given** the `ecc` feature disabled, **When** the crates are built, **Then** no ECC secret handling
   is compiled and behavior matches today.

### Edge Cases

- A malformed / truncated / oversized `EccEncryptedSecret` (attacker-controlled `tokenData` /
  `password` bytes) MUST be rejected with a protocol error and **never panic** (fuzzable).
- Decrypt failures (bad padding, bad MAC/signature, wrong nonce, wrong key, malformed length) MUST all
  return a **single uniform error** with no distinguishable behavior or timing (no padding/validity
  oracle).
- An `EccEncryptedSecret` presented when no ECC EphemeralKey was exchanged (or the retained key is
  absent/consumed) MUST be rejected, not silently accepted.
- A secret bound to a server nonce other than the session's current nonce MUST be rejected (replay).
- A duplicate/replayed `EccEncryptedSecret` or reused EphemeralKey MUST be rejected (US4).
- Mismatched curve / policy between the negotiated channel and the `EccEncryptedSecret` MUST be rejected.

## Requirements *(mandatory)*

- **FR-001**: The server MUST decrypt an `EccEncryptedSecret` (Part 4 §7.40.2.5, Tables 183/186) carried
  in a `UserNameIdentityToken` password under an ECC policy, deriving keys via the Part 6 §6.8.3 KDF
  (ECDH over the exchanged client/server EphemeralKeys → HKDF with the §6.8.3 salt) and the policy's
  symmetric+integrity layer, and MUST recover the exact plaintext secret.
- **FR-002**: The client MUST encrypt a `UserNameIdentityToken` password as an `EccEncryptedSecret` under
  an ECC policy using the retained verified server `ECDHKey`, its own ephemeral key, and the current
  server nonce — producing a secret the server (FR-001) decrypts to the original.
- **FR-003**: The same encrypt/decrypt MUST apply to the `IssuedIdentityToken` token data under ECC.
- **FR-004**: Every `EccEncryptedSecret` MUST be bound to the **current server nonce**; a secret bound to
  any other nonce MUST be rejected (non-replayable), consistent with the feature 014/015a replay
  protection.
- **FR-005**: A server EphemeralKey MUST be marked **consumed** once it decrypts an identity-token
  secret; a consumed key (or a replayed/duplicate `EccEncryptedSecret`) MUST be rejected, and the
  §6.8.2 `decide_ecdh_key_action` lifecycle MUST be driven by this **real** consumed state (replacing
  015a's hardwired `false`).
- **FR-006**: All decrypt failures (malformed, wrong nonce, tampered ciphertext, bad integrity/padding,
  wrong/absent/consumed key) MUST be **fail-closed** and return a **single uniform error** with no
  padding/validity oracle and no panic on attacker-supplied bytes.
- **FR-007**: The implementation MUST be pure-Rust (no OpenSSL/C), reusing the feature-012/015a ECC
  primitives and a RustCrypto HKDF; gated behind the existing `ecc` feature; the legacy RSA secret path
  and the `None` policy MUST remain byte-identical.

### Key Entities *(include if feature involves data)*

- **`EccEncryptedSecret`** (Part 4 §7.40.2.5, Tables 183/186): the ECC-wrapped identity-token secret —
  carries the sender (client) ephemeral public key, the policy/nonce binding, the AES-CBC ciphertext, and
  the integrity value/signature.
- **§6.8.3 ECC KDF**: ECDH(client ephemeral, server ephemeral) → HKDF with
  `SecretSalt = <length-prefixed> "opcua-secret" | SenderPublicKey | ReceiverPublicKey` (exact label
  bytes / length encoding / output key+IV lengths pinned from Part 6 §6.8.3 at planning) → signing key,
  encrypting key, IV.
- **Server EphemeralKey consumed-state**: per-session flag (issued → consumed) that drives the §6.8.2
  anti-replay; supplies the real `previous_key_consumed` input deferred from 015a.
- **Identity-token secret**: the `UserNameIdentityToken` password or `IssuedIdentityToken` token data
  being wrapped.

## Success Criteria *(mandatory)*

- **SC-001**: A client and server using `ECC_nistP256` or `ECC_nistP384` complete a
  `UserNameIdentityToken` password authentication end-to-end (client-encrypt ↔ server-decrypt) — verified
  on real P-256 and P-384 keys.
- **SC-002**: The §6.8.3 KDF matches external **RFC 5869 HKDF** test vectors (anchored to the RFC, not
  loopback), and a crafted `EccEncryptedSecret` fixture decrypts to its known plaintext per the exact
  §7.40.2.5 wire layout.
- **SC-003**: An `IssuedIdentityToken` secret round-trips under ECC (SC-001 equivalent for issued tokens).
- **SC-004**: A wrong-nonce, tampered, replayed, or consumed-key `EccEncryptedSecret` is rejected with a
  single uniform error and no panic; the same EphemeralKey is never accepted twice (anti-replay verified
  end-to-end).
- **SC-005**: RSA / `None` / no-ECC flows are byte-identical to today; the `ecc`-off build is identical;
  `cargo clippy --all-targets --all-features` is clean with no new C dependency.
- **SC-006**: Attacker-supplied `EccEncryptedSecret` bytes (malformed/truncated/oversized) are rejected
  without panic (negative/fuzz).

## Assumptions

- **Phase B of two**: builds directly on 015a (merged). The EphemeralKey exchange, server keypair storage
  (`Session.ecdh_ephemeral_key`), client retention (`Session.retained_server_ephemeral_key`), and the
  `decide_ecdh_key_action` lifecycle already exist; this feature consumes them.
- **Exact wire format pinned at planning**: the §7.40.2.5 `EccEncryptedSecret` field order/encoding
  (Tables 183/186) and the §6.8.3 KDF (salt label `"opcua-secret"`, length-prefix rules, HKDF hash per
  curve, output signing/encrypting key + IV lengths) are re-read from Part 4 §7.40.2.5 + Part 6 §6.8.3 in
  `~/opcua-specs` during `/speckit-plan` — **not guessed**.
- **Symmetric/integrity layer**: AES-256-CBC plus the policy's signature for integrity (the §7.40.2.5
  EncryptedSecret signing/encrypting key split). Whether the 012 ECC policies use AES-CBC+signature vs an
  AEAD path is confirmed against the policy definition at planning.
- **HKDF**: a RustCrypto `hkdf` crate (already in-tree or added) — no OpenSSL/C; the curve's hash (SHA-256
  for P-256, SHA-384 for P-384) per §6.8.3.
- **Out of scope / deferred (recorded)**: the modern (non-legacy) **RSA** EncryptedSecret format unless
  required for ECC; GDS; the deferred mixed RSA+ECC multi-cert server (feature 012); RSA-DH
  finite-field-group EphemeralKeys.
- **Verification division**: codex implements production code only; **Claude authors and runs all tests**
  independently — client-encrypt ↔ server-decrypt round-trips on real P-256/P-384 keys, crafted-fixture
  decrypt anchored to §7.40.2.5, the **RFC 5869** HKDF vectors for the KDF, wrong-nonce/tampered/replayed
  rejection, the uniform-error / no-oracle property, consumed-key/replayed-secret rejection, and
  negative/fuzz over attacker bytes — anchored to external ground truth, not codex loopback (the division
  caught a rigged HKDF test on feature 012).
- **Spec source**: Part 4 §7.40.2.5 (Tables 183/186) + Part 6 §6.8.3 text in `~/opcua-specs` (PDFs not
  committed).
