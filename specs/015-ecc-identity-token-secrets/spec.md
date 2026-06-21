# Feature Specification: ECC Identity-Token Secrets (OPC UA Part 4 §7.41.2.3)

**Feature Branch**: `015-ecc-identity-token-secrets`
**Created**: 2026-06-21
**Status**: Draft
**Input**: User description: support encrypted UserName/Issued identity-token secrets under the ECC
NIST security policies (Part 4 §7.41.2.3); today only the legacy RSA secret format exists, so those
tokens cannot authenticate over an ECC channel.

## User Scenarios & Testing *(mandatory)*

When a client authenticates with a `UserNameIdentityToken` (password) or an `IssuedIdentityToken`
(token data), the secret is **encrypted** so it is not exposed on the wire, bound to the server's
current nonce so it cannot be replayed. async-opcua implements this only for RSA channels today (the
legacy secret format, Part 4 Table 193): the client encrypts via `legacy_encrypt_secret` and the
server decrypts via `decrypt_identity_token_secret`. Feature 012 added the ECC NIST security policies
(`ECC_nistP256` / `ECC_nistP384`), but there is **no ECC path for identity-token secrets** — so a
user connecting over an ECC channel cannot supply a username/password or an issued token. This
feature implements the Part 4 §7.41.2.3 secret encryption/decryption for the ECC policies, on both
the client (encrypt) and the server (decrypt), reusing the in-tree ECC primitives from feature 012,
keeping the secret bound to the current server nonce (replay protection from feature 014) and
fail-closed against malformed/tampered input.

### User Story 1 — Server decrypts an ECC-encrypted username-token password (Priority: P1) 🎯 MVP

As a server operator using an ECC security policy, I want the server to decrypt a client's
`UserNameIdentityToken` password that was encrypted under the ECC policy, so username/password users
can authenticate over ECC channels.

**Why this priority**: Without it, the most common credential type (username/password) simply cannot
be used on ECC endpoints — the headline gap. It is the decrypt side the server must get right and is
the foundation for the round-trip.

**Independent Test**: A correctly ECC-encrypted secret (bound to the server's current nonce) decrypts
to the original password; a secret bound to a stale/wrong nonce, a tampered ciphertext, or malformed
bytes is rejected with a single uniform error (no oracle) and never panics.

**Acceptance Scenarios**:

1. **Given** an ECC channel (P-256 or P-384) and a username token whose secret was encrypted per
   §7.41.2.3 against the server's current nonce, **When** the server processes ActivateSession,
   **Then** it recovers the original password and authentication proceeds.
2. **Given** an ECC-encrypted secret bound to a previous/stale server nonce, **When** decrypted,
   **Then** it is rejected (`Bad_IdentityTokenInvalid` / `Bad_IdentityTokenRejected`).
3. **Given** a tampered or malformed encrypted secret, **When** decrypted, **Then** it is rejected
   with a single uniform error and the server does not panic.

---

### User Story 2 — Client encrypts a username-token secret under ECC (Priority: P1)

As a client connecting to an ECC endpoint, I want the SDK to encrypt my `UserNameIdentityToken`
password per §7.41.2.3, so my credentials are protected and accepted by a conformant ECC server.

**Why this priority**: The encrypt side completes the usable round-trip; together with US1 it makes
ECC username auth work end-to-end (and is required to interoperate with other ECC servers).

**Independent Test**: A client-encrypted secret round-trips through the server decrypt (US1) to the
original password; the wire format matches §7.41.2.3 (verified against the spec layout / external
interop).

**Acceptance Scenarios**:

1. **Given** an ECC channel and a username/password, **When** the client builds the ActivateSession
   request, **Then** the secret is encrypted per §7.41.2.3, bound to the server nonce, and the server
   accepts it.
2. **Given** the `None` security policy or an RSA policy, **When** the client encrypts the secret,
   **Then** it uses the existing (plaintext / legacy-RSA) path unchanged.

---

### User Story 3 — IssuedIdentityToken secret under ECC (Priority: P2)

As a client/server using issued (e.g. token-server) credentials over ECC, I want the
`IssuedIdentityToken` token data encrypted/decrypted under the ECC policy the same way as the
username secret, so issued-token auth also works on ECC channels.

**Why this priority**: Same mechanism as US1/US2 applied to the issued-token field; lower frequency
than username/password but required for full §7.41.2.3 coverage.

**Independent Test**: An ECC-encrypted issued-token secret round-trips (client encrypt → server
decrypt) to the original token data; stale-nonce/tampered inputs are rejected uniformly.

**Acceptance Scenarios**:

1. **Given** an ECC channel and an issued token, **When** activated, **Then** the token data is
   recovered server-side and authentication proceeds.
2. **Given** a tampered/stale issued-token secret, **When** decrypted, **Then** it is rejected
   uniformly without panic.

---

### User Story 4 — Rollout & backward compatibility (Priority: P3)

As an operator of an existing deployment, I want ECC secret support added without changing RSA or
`None` behavior, gated behind the existing `ecc` feature.

**Why this priority**: Safety/adoption — existing RSA and None flows must be byte-identical; ECC
secret support is additive and feature-gated.

**Independent Test**: Existing RSA username/issued-token auth and the `None` path are unchanged
(regression); with the `ecc` feature off, behavior is identical to today; the unit + integration
suites pass.

**Acceptance Scenarios**:

1. **Given** an RSA or `None` endpoint, **When** a user authenticates, **Then** behavior is exactly
   as before this feature.
2. **Given** the `ecc` feature disabled, **When** building, **Then** the crate compiles and behaves
   identically to today (ECC policies remain rejected as unsupported).

### Edge Cases

- Malformed / truncated / oversized encrypted secret bytes (attacker-controlled) MUST be rejected with
  a protocol error and **never panic** (fuzzable input).
- A secret whose embedded nonce does not match the server's current nonce MUST be rejected (replay).
- All decrypt failures (bad nonce, bad padding, bad MAC/signature, wrong length) MUST surface a single
  uniform error — no distinguishable padding/validity oracle.
- Curve/policy mismatch between the secret's declared algorithms and the negotiated policy MUST be
  rejected.
- An empty/absent secret on a token that requires one is rejected; an anonymous token is unaffected.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The server MUST decrypt a `UserNameIdentityToken` secret encrypted per Part 4 §7.41.2.3
  under the negotiated ECC NIST policy (P-256 / P-384), recovering the original password, when the
  secret is bound to the server's current nonce.
- **FR-002**: The client MUST encrypt a `UserNameIdentityToken` secret per §7.41.2.3 under an ECC
  policy, bound to the server's current nonce, in a form a conformant server (and this server)
  accepts.
- **FR-003**: The server MUST decrypt, and the client MUST encrypt, the `IssuedIdentityToken` token
  data under the ECC policy by the same §7.41.2.3 mechanism.
- **FR-004**: The secret MUST be bound to the **current** server nonce; a secret bound to a
  stale/previous nonce MUST be rejected (replay protection, consistent with feature 014).
- **FR-005**: All decryption MUST be **fail-closed**: malformed, truncated, tampered, wrong-nonce, or
  wrong-policy secrets are rejected with a **single uniform error** (no padding/validity oracle) and
  MUST NOT panic on attacker-supplied bytes.
- **FR-006**: The implementation MUST reuse the in-tree pure-Rust ECC primitives (ECDH key agreement,
  HKDF derivation, the policy's AES + HMAC symmetric layer) — no OpenSSL / C dependency.
- **FR-007**: The existing **legacy RSA** secret path and the **`None`** security-policy path MUST be
  unchanged (byte-identical); ECC secret support is additive and gated behind the existing `ecc`
  feature.

### Key Entities *(include if feature involves data)*

- **Identity-token secret**: the sensitive value to protect — a `UserNameIdentityToken` password or an
  `IssuedIdentityToken` token data.
- **Encrypted secret (§7.41.2.3)**: the on-the-wire wrapped secret — declares its security-policy
  algorithms, carries the key-agreement material / ephemeral key, the server nonce binding, the
  encrypted payload, and an integrity value (MAC/signature).
- **Server nonce**: the current per-ActivateSession nonce the secret is bound to (replay protection).
- **ECC key material**: the channel's ECC keys / ephemeral ECDH material and derived symmetric keys
  (reused from feature 012).

## Success Criteria *(mandatory)*

- **SC-001**: A username/password user can authenticate over both `ECC_nistP256` and `ECC_nistP384`
  channels — verified by a client-encrypt ↔ server-decrypt round-trip recovering the exact password.
- **SC-002**: An issued-token user can authenticate over ECC channels (round-trip recovers the exact
  token data).
- **SC-003**: A secret bound to a stale/wrong nonce, a tampered ciphertext, or malformed bytes is
  rejected with a single uniform error and never panics — verified by negative and fuzz tests.
- **SC-004**: Existing RSA and `None` username/issued-token authentication is unchanged (regression),
  and with the `ecc` feature off the build/behavior is identical to today.
- **SC-005**: The ECC secret wire format matches Part 4 §7.41.2.3 — verified against the spec layout
  (and external-server interop where feasible), not only internal loopback.
- **SC-006**: `cargo clippy --all-targets --all-features` is clean; no new C-toolchain dependency.

## Assumptions

- **Reuses feature 012 ECC primitives**: ECDH, HKDF, and the AES-CBC + HMAC symmetric layer already
  exist and are RFC-vector-validated; this feature composes them into the §7.41.2.3 secret format
  rather than adding new crypto primitives. The exact key-agreement shape (ephemeral-ephemeral vs
  ephemeral-static, and the precise KDF inputs) is pinned from the spec text during planning.
- **Server nonce binding**: the secret binds to the current ActivateSession server nonce, consistent
  with the replay protection delivered in feature 014.
- **Scope**: UserName + Issued identity-token secrets, ECC policies, both client-encrypt and
  server-decrypt. The legacy RSA secret path and the `None` path are untouched.
- **Out of scope / deferred**: the modern (non-legacy) RSA EncryptedSecret format unless §7.41.2.3
  requires it for ECC; GDS / token-server issuance; the deferred mixed RSA+ECC multi-cert server
  (feature 012); X.509 user identity tokens (already handled via signatures, not secret encryption).
- **Spec source**: Part 4 §7.41 text in `~/opcua-specs` is the normative reference; the copyrighted
  PDFs are NOT committed to the repo.
- **Verification division**: coding goes to codex (implementation only); Claude authors and runs all
  tests independently — client↔server round-trips on real P-256/P-384 keys, crafted §7.41.2.3 decrypt
  fixtures, stale-nonce / tampered-ciphertext / uniform-error checks, and negative/fuzz over
  attacker-supplied secret bytes, anchored to the spec wire format and external interop where feasible
  (not codex loopback alone — this division caught a rigged HKDF test on feature 012).
