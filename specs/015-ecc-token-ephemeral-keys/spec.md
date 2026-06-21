# Feature Specification: ECC Token EphemeralKey Exchange (OPC UA Part 6 §6.8.2)

**Feature Branch**: `015-ecc-token-ephemeral-keys`
**Created**: 2026-06-21
**Status**: Draft
**Input**: User description (recalibrated by research, see `research.md`): support encrypted
identity-token secrets under the ECC policies. This is **phase A of two** — it delivers the
**EphemeralKey exchange** (Part 6 §6.8.2) that `EccEncryptedSecret` depends on. The actual secret
encryption/decryption (`EccEncryptedSecret`, Part 4 §7.40.2.5 / Part 6 §6.8.3) is the follow-on
feature (016).

## Context *(mandatory)*

To encrypt a `UserNameIdentityToken`/`IssuedIdentityToken` secret under an ECC SecurityPolicy, the
client and server must exchange ECC **EphemeralKeys** — and Part 6 §6.8.2 states the standard
CreateSession/ActivateSession handshake has **no mechanism** for this, so the exchange is carried in
the `AdditionalHeader` of the request/response headers. async-opcua implements none of this today
(only the low-level `generate_ephemeral_keypair`/ECDH primitives from feature 012 and the generated
`EphemeralKeyType` exist). This feature implements that exchange — the prerequisite for ECC
identity-token secrets — without yet building the `EccEncryptedSecret` itself (feature 016).

## User Scenarios & Testing *(mandatory)*

### User Story 1 — Server issues a signed EphemeralKey at CreateSession (Priority: P1) 🎯 MVP

As a client preparing to send an ECC-encrypted identity token, I want the server to give me its
ephemeral public key (proven authentic) at CreateSession, so I can later derive the secret-encryption
key against it.

**Why this priority**: It is the foundation — without the server's authenticated EphemeralKey the
client cannot build an `EccEncryptedSecret` at all. It is the server-issue side.

**Independent Test**: A CreateSession request carrying `ECDHPolicyUri = ECC_nistP256/384` in its
AdditionalHeader yields a response whose AdditionalHeader contains an `ECDHKey` (`EphemeralKeyType`)
whose `publicKey` is a valid curve point and whose `signature` verifies against the server certificate;
an unsupported/invalid `ECDHPolicyUri` yields `Bad_SecurityPolicyRejected` in place of the key.

**Acceptance Scenarios**:

1. **Given** an ECC-secured (or RSA-DH) channel and a CreateSession request whose AdditionalHeader
   declares a valid `ECDHPolicyUri`, **When** processed, **Then** the response AdditionalHeader carries
   an `ECDHKey` = `EphemeralKeyType` with a fresh ephemeral public key for that policy and a signature
   the client can verify against the server certificate.
2. **Given** a CreateSession with an invalid/unsupported `ECDHPolicyUri`, **When** processed, **Then**
   the response conveys `Bad_SecurityPolicyRejected` (in place of the EphemeralKey), not a panic.
3. **Given** a CreateSession with no `ECDHPolicyUri`, **When** processed, **Then** behavior is
   unchanged (no EphemeralKey returned), preserving today's flow.

---

### User Story 2 — Client requests + retains the server EphemeralKey (Priority: P1)

As a client SDK, I want to advertise my chosen `ECDHPolicyUri` and capture the server's `ECDHKey` from
the CreateSession/ActivateSession response, verifying its signature, so the most recent authentic
server EphemeralKey is available to the (016) secret encryption.

**Why this priority**: The client side of the same exchange; together with US1 it makes the
authenticated ephemeral key available end-to-end.

**Independent Test**: The client places `ECDHPolicyUri` in the request AdditionalHeader, reads the
`ECDHKey` from the response, verifies its signature against the server certificate, and retains the
most recent one; a missing/invalid/forged-signature EphemeralKey is rejected without panic.

**Acceptance Scenarios**:

1. **Given** an ECC channel, **When** the client calls CreateSession/ActivateSession, **Then** it sends
   its `ECDHPolicyUri` and stores the verified server `ECDHKey` (most recent wins).
2. **Given** a server `ECDHKey` whose signature does not verify against the server certificate, **When**
   received, **Then** the client rejects it (does not use an unauthenticated ephemeral key).

---

### User Story 3 — Fresh EphemeralKey + anti-replay at ActivateSession (Priority: P2)

As a server operator, I want to issue a new EphemeralKey per the §6.8.2 rules and **never accept the
same EphemeralKey twice**, so an attacker cannot replay a captured ephemeral key / encrypted secret.

**Why this priority**: The §6.8.2 anti-replay rule is a hard security requirement (aligns with the
nonce-replay protection from feature 014); the server's key lifecycle must be correct.

**Independent Test**: After a successful ActivateSession that consumed an EphemeralKey, the server does
not accept that same EphemeralKey again; the §6.8.2 rules for when to return a new key vs retain the
previous one hold.

**Acceptance Scenarios**:

1. **Given** a successful ActivateSession that used the server's EphemeralKey, **When** the same
   EphemeralKey is presented again, **Then** the server rejects it.
2. **Given** the §6.8.2 return rules (valid ECDHPolicyUri → new compatible key; invalid →
   `Bad_SecurityPolicyRejected`; absent + previous key used → new key; absent + previous key unused →
   retain), **When** ActivateSession is processed, **Then** the server's behavior matches the rules.

---

### User Story 4 — Rollout & backward compatibility (Priority: P3)

As an operator, I want this added behind the `ecc` feature without changing RSA/None or existing
no-ECDH flows.

**Independent Test**: RSA and `None` sessions, and ECC sessions that do not request an `ECDHPolicyUri`,
behave exactly as before; with the `ecc` feature off, behavior is identical to today.

**Acceptance Scenarios**:

1. **Given** an RSA/`None` endpoint or a request with no `ECDHPolicyUri`, **When** processed, **Then**
   behavior is byte-identical to today.

### Edge Cases

- Malformed / truncated / oversized `AdditionalHeader` or `EphemeralKeyType` bytes (attacker-controlled)
  MUST be rejected with a protocol error and **never panic**.
- An `EphemeralKeyType` whose `publicKey` is not a valid curve point, or whose `signature` does not
  verify, MUST be rejected.
- A duplicate / already-consumed server EphemeralKey MUST be rejected (anti-replay).
- An `ECDHPolicyUri` incompatible with the channel/endpoint MUST yield `Bad_SecurityPolicyRejected`.

## Requirements *(mandatory)*

- **FR-001**: When a CreateSession/ActivateSession request carries a valid `ECDHPolicyUri` in its
  `AdditionalHeader` (`AdditionalParametersType` name-value list, Part 6 Table 70), the server MUST
  generate a fresh ECC EphemeralKey for that policy, sign it so the client can authenticate it, and
  return it as `ECDHKey` (`EphemeralKeyType`) in the response `AdditionalHeader`.
- **FR-002**: An invalid/unsupported `ECDHPolicyUri` MUST yield `Bad_SecurityPolicyRejected` (conveyed
  in place of the EphemeralKey), never a panic; a request with no `ECDHPolicyUri` MUST behave as today.
- **FR-003**: The client MUST send its `ECDHPolicyUri` in the request `AdditionalHeader`, read the
  server's `ECDHKey` from the response, **verify its signature against the server certificate**, and
  retain the most recent authentic EphemeralKey.
- **FR-004**: The server MUST follow the §6.8.2 EphemeralKey lifecycle rules at ActivateSession (new
  key vs retain) and MUST **never accept the same EphemeralKey twice** (anti-replay).
- **FR-005**: All parsing of attacker-supplied `AdditionalHeader` / `EphemeralKeyType` bytes MUST be
  **fail-closed** and **panic-free**; signature/curve-point validation failures reject the key.
- **FR-006**: The implementation MUST reuse the in-tree pure-Rust ECC primitives (ephemeral keypair
  generation, the curve point encoding) — no OpenSSL/C; gated behind the existing `ecc` feature; RSA
  and `None` paths byte-identical.

### Key Entities *(include if feature involves data)*

- **EphemeralKey / `EphemeralKeyType`** (Part 4 §7.15, Table 136): an ECC ephemeral public key plus a
  signature created by the issuer (server) so the receiver (client) can authenticate it.
- **`ECDHPolicyUri`** (request AdditionalHeader): the SecurityPolicy the EphemeralKeys are for.
- **`ECDHKey`** (response AdditionalHeader): the issued `EphemeralKeyType` (or a StatusCode on error).
- **AdditionalHeader / `AdditionalParametersType`**: the name-value list (Part 6 Table 70) in the
  request/response headers carrying the exchange.

## Success Criteria *(mandatory)*

- **SC-001**: A client requesting `ECDHPolicyUri = ECC_nistP256` or `ECC_nistP384` at
  CreateSession/ActivateSession receives a server `ECDHKey` whose signature verifies against the server
  certificate and whose public key is a valid curve point — verified end-to-end (client↔server).
- **SC-002**: An invalid `ECDHPolicyUri` yields `Bad_SecurityPolicyRejected`; a forged/invalid server
  EphemeralKey signature is rejected client-side — both without panic.
- **SC-003**: The server never accepts the same EphemeralKey twice (anti-replay), and the §6.8.2
  new-vs-retain rules hold — verified by tests.
- **SC-004**: Malformed AdditionalHeader/EphemeralKeyType bytes are rejected without panic
  (negative/fuzz). RSA/`None`/no-ECDH flows unchanged; `ecc`-off build identical to today.
- **SC-005**: `cargo clippy --all-targets --all-features` clean; no new C dependency.

## Assumptions

- **Phase A of two**: this feature delivers only the EphemeralKey exchange. The `EccEncryptedSecret`
  structure, KDF (`opcua-secret` salt), and the actual secret encrypt/decrypt + identity-token wiring
  are **feature 016** (which depends on this).
- **Reuses feature 012 primitives**: `generate_ephemeral_keypair` / `EphemeralPublicKey` / the curve
  encoding exist; the EphemeralKey *signing* (server side) and *verification* (client side) and the
  exact signed-data layout are pinned from Part 4 §7.15 / Part 6 §6.8.1–2 at planning.
- **AdditionalHeader plumbing**: `AdditionalParametersType` and `EphemeralKeyType` are generated types;
  this feature wires them into the CreateSession/ActivateSession request/response header handling.
- **Out of scope / deferred**: `EccEncryptedSecret` and secret encrypt/decrypt (feature 016); RSA-DH
  finite-field-group EphemeralKeys; GDS; the deferred mixed RSA+ECC multi-cert server.
- **Spec source**: Part 4 §7.15 + Part 6 §6.8.1–2 text in `~/opcua-specs` (PDFs not committed).
- **Verification division**: codex implements; Claude authors/runs all tests independently —
  server-issue ↔ client-read round-trip of the AdditionalHeader exchange, EphemeralKey signature
  verify against the server cert, `Bad_SecurityPolicyRejected` on bad policy, anti-replay (same key
  rejected), malformed-header/EphemeralKeyType no-panic — anchored to §6.8.2 + Table 136 (and external
  interop where feasible), not codex loopback alone.
