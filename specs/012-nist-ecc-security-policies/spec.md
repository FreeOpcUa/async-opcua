# Feature Specification: NIST ECC Security Policies (ECC_nistP256 / ECC_nistP384)

**Feature Branch**: `012-nist-ecc-security-policies`
**Created**: 2026-06-20
**Status**: Complete
**Input**: Add the OPC UA elliptic-curve security policies `ECC_nistP256` and `ECC_nistP384` to the
client and server secure channel, using a pure-Rust crypto backend. The stack today supports only
RSA-based policies; this adds the NIST ECC half of the OPC UA ECC policy family (brainpool deferred).

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Verified ECC cryptographic primitives (Priority: P1)

The library gains the elliptic-curve building blocks an ECC secure channel needs — ECDSA signing
and verification (P-256 with SHA-256, P-384 with SHA-384), ephemeral ECDH key agreement, and the
HKDF-based key derivation that turns a shared secret into the channel's session keys — each
validated against published test vectors.

**Why this priority**: Everything else (handshake, channel, second curve) depends on these
primitives being correct. They are independently unit-testable and are the foundation; getting them
wrong is a security failure, so they come first.

**Independent Test**: Run unit tests that sign/verify and derive keys against NIST/RFC test vectors
and known-answer pairs; assert exact matches and that verification rejects tampered inputs.

**Acceptance Scenarios**:

1. **Given** a P-256 key pair and SHA-256, **When** a message is signed and verified, **Then** valid signatures verify and any tampered byte fails verification.
2. **Given** two parties' ephemeral key pairs, **When** each runs ECDH, **Then** both derive the identical shared secret, which matches the test vector.
3. **Given** a shared secret and the spec's derivation inputs, **When** HKDF key derivation runs, **Then** the derived signing/encrypting keys and IV match the expected values.

---

### User Story 2 - EC application certificates (Priority: P1)

The server and client can load, validate, and use X.509 application certificates that carry NIST
EC (P-256 / P-384) public keys, so ECC endpoints can authenticate peers the same way RSA endpoints do.

**Why this priority**: An ECC secure channel in any mode beyond `None` needs to verify the peer's
ECDSA signature against its certificate; without EC certificate support the channel cannot
authenticate. Independently testable and required by the channel story.

**Independent Test**: Load a P-256 and a P-384 application certificate; assert the public key/curve
is parsed, the thumbprint is computed, an expired/untrusted cert is rejected, and a valid one passes
chain validation.

**Acceptance Scenarios**:

1. **Given** a valid P-256 application certificate, **When** it is loaded, **Then** its curve and public key are recognized and its thumbprint computed.
2. **Given** an expired or untrusted EC certificate, **When** it is validated, **Then** it is rejected with the appropriate status.
3. **Given** an EC certificate whose curve does not match the negotiated policy, **When** used, **Then** it is rejected.

---

### User Story 3 - Establish an ECC_nistP256 secure channel end to end (Priority: P1) 🎯 MVP

A client and server negotiate an `ECC_nistP256` endpoint and open a working secure channel in both
`Sign` and `SignAndEncrypt` modes — exchanging ephemeral EC public keys, deriving matching session
keys via ECDH+HKDF, and then exchanging signed/encrypted service messages — interoperable with
spec-compliant peers.

**Why this priority**: This is the feature's MVP — the first end-to-end elliptic-curve channel. It
integrates US1 + US2 into the OpenSecureChannel flow and delivers user-visible value (an ECC
endpoint that works).

**Independent Test**: Over loopback, a server advertising an `ECC_nistP256` endpoint and a client
connecting to it complete OpenSecureChannel and exchange service calls in `Sign` and in
`SignAndEncrypt`; both sides derive identical keys and messages round-trip.

**Acceptance Scenarios**:

1. **Given** a server with an `ECC_nistP256` `Sign` endpoint, **When** a client connects, **Then** the channel opens, both sides derive the same session keys, and signed service calls succeed.
2. **Given** an `ECC_nistP256` `SignAndEncrypt` endpoint, **When** a client connects, **Then** messages are encrypted+signed and round-trip correctly.
3. **Given** an opened ECC channel, **When** it is renewed, **Then** new keys are derived and traffic continues without interruption.

---

### User Story 4 - ECC_nistP384 (Priority: P2)

The same capability for `ECC_nistP384` (P-384 / SHA-384 / AES-256), for deployments requiring the
higher-strength curve.

**Why this priority**: Builds directly on US1–US3; valuable but secondary to having one working ECC
curve. Mostly parameterization of the P-256 work over P-384.

**Independent Test**: Repeat the US3 loopback test with an `ECC_nistP384` endpoint in both modes.

**Acceptance Scenarios**:

1. **Given** an `ECC_nistP384` endpoint, **When** a client connects in `Sign` or `SignAndEncrypt`, **Then** the channel opens and messages round-trip.

---

### User Story 5 - Negotiation, config, and rollout safety (Priority: P3)

Operators can configure ECC endpoints (server) and select ECC policies (client) through the normal
config surface; policy/security-level negotiation picks ECC appropriately; and the ECC code is
additive and feature-gateable so existing deployments are unaffected.

**Why this priority**: Makes the capability usable and safe to ship without disturbing the RSA/None
paths; lower urgency than the crypto/channel itself.

**Independent Test**: Configure a server with mixed RSA + ECC endpoints; assert config round-trips,
an ECC-capable client negotiates ECC while an RSA-only client still negotiates RSA, and existing
RSA/None behavior is byte-identical.

**Acceptance Scenarios**:

1. **Given** a server config listing both RSA and ECC endpoints, **When** it loads, **Then** all endpoints are advertised and selectable.
2. **Given** an RSA-only client, **When** it connects to that server, **Then** it still negotiates an RSA policy unchanged.
3. **Given** the ECC feature disabled at build time, **When** an ECC policy is requested, **Then** it is cleanly rejected as unsupported (fail-closed), and RSA/None are unaffected.

### Edge Cases

- A handshake declaring an ECC policy but carrying a malformed/short/garbage ephemeral public key → rejected with a protocol error, no panic.
- Curve/policy mismatch (P-256 key on a P-384 policy, or an RSA cert on an ECC policy) → rejected.
- Point-at-infinity / invalid curve point / non-canonical signature in attacker input → rejected (no panic, fail closed).
- Channel renewal under ECC derives fresh keys; a peer that reuses a stale ephemeral key is handled per spec.
- ECC feature compiled out: requesting an ECC policy returns "unsupported," never a panic.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The system MUST recognize the `ECC_nistP256` and `ECC_nistP384` security policies — their policy URIs, parsing/serialization, display, and "is supported" gating — as first-class policies alongside the existing ones.
- **FR-002**: The system MUST provide ECDSA signing and verification for P-256/SHA-256 and P-384/SHA-384 whose output matches published NIST/RFC test vectors and which rejects tampered data.
- **FR-003**: The system MUST perform ephemeral ECDH key agreement on P-256 and P-384 such that both peers compute the identical shared secret.
- **FR-004**: The system MUST derive the secure-channel session keys (signing key, encrypting key, initialization vector) from the ECDH shared secret using the key-derivation function mandated by the OPC UA specification for ECC policies, producing values that match the spec/test vectors.
- **FR-005**: For ECC policies, `OpenSecureChannel` MUST exchange ephemeral EC public keys (in place of the RSA-encrypted nonces used by RSA policies) and both peers MUST derive matching session keys from the exchange.
- **FR-006**: An ECC secure channel MUST support the `Sign` and `SignAndEncrypt` message security modes, reusing the existing symmetric message protection consistent with each policy.
- **FR-007**: The system MUST load and validate X.509 application certificates carrying P-256/P-384 EC public keys (thumbprint, validity, chain/trust validation), and MUST reject a certificate whose curve does not match the negotiated policy.
- **FR-008**: All ECC handshake and message processing on a path reachable from a remote peer MUST reject malformed, mismatched, or invalid input (bad points, wrong curve, short keys, non-canonical signatures) with a protocol error and MUST NOT panic.
- **FR-009**: A server MUST be able to advertise ECC endpoints and a client MUST be able to select ECC policies through the existing configuration/connection surface, with correct policy/security-level negotiation between ECC- and RSA-capable peers.
- **FR-010**: The system MUST support `ECC_nistP384` with the same channel capabilities as `ECC_nistP256`.
- **FR-011**: The ECC implementation MUST be additive and build-time gateable; with it disabled (or absent), existing RSA/None behavior MUST be byte-identical and ECC policies MUST be cleanly reported as unsupported.
- **FR-012**: Private keys, shared secrets, and nonces MUST NOT be logged; secret-dependent operations SHOULD be constant-time where the underlying primitives allow.
- **FR-013**: The change MUST keep `cargo clippy --all-targets --all-features` clean, the full unit + 98-test integration suites passing, and `verify-clean-codegen` green, with no generated-code edits.

### Key Entities *(include if feature involves data)*

- **ECC SecurityPolicy**: the `ECC_nistP256` / `ECC_nistP384` policies — curve, hash, symmetric suite, and URI.
- **Ephemeral EC key pair**: per-channel-open transient key whose public half is exchanged and whose private half feeds ECDH; never persisted, never logged.
- **ECDH shared secret**: the agreed secret, consumed only by key derivation, then discarded.
- **Derived session key set**: signing key, encrypting key, IV — per direction, regenerated on channel renewal.
- **EC application certificate**: long-lived X.509 cert with a P-256/P-384 public key, used to authenticate the peer's ECDSA signatures.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Over loopback, a client and server establish an `ECC_nistP256` channel in both `Sign` and `SignAndEncrypt` and successfully exchange service calls; both sides derive identical keys.
- **SC-002**: The same is true for `ECC_nistP384`.
- **SC-003**: ECDSA, ECDH, and the key-derivation outputs match published NIST/RFC/spec test vectors 100% of the time.
- **SC-004**: Crafted malformed or curve-mismatched ECC handshakes are rejected with a protocol error and zero process aborts across the negative/fuzz corpus.
- **SC-005**: Existing RSA/None channels are unchanged — wire byte-identity preserved and the full pre-existing test suite passes.
- **SC-006**: `cargo clippy --all-targets --all-features`, the full unit + integration suites, and `verify-clean-codegen` are all green.
- **SC-007**: If a spec-compliant ECC-capable reference peer is available, it interoperates with our client and server in both modes; if not, the gap is explicitly documented and correctness rests on spec/RFC vectors + loopback round-trip.

## Assumptions

- Pure-Rust crypto only (mature P-256/P-384 ECDSA/ECDH/HKDF); **no new C-toolchain dependency** and not routed through `aws-lc-rs`.
- The exact symmetric suite, KDF construction, and OpenSecureChannel ephemeral-key wire layout for ECC policies are taken from OPC UA Part 6/Part 7 and pinned in the plan/research phase (the description's "AES-CBC + HMAC-SHA256/384" is the working assumption, to be confirmed against the spec).
- The ECC code is feature-gated; default-enabled is assumed (pure-Rust, mature curves) but it can ship opt-in if review prefers — a build/plan decision, not a behavior change to existing policies.
- **Out of scope (deferred):** the brainpool policies `ECC_brainpoolP256r1` / `ECC_brainpoolP384r1` (usable Rust arithmetic exists only in pre-release/unaudited `bp256`/`bp384` 0.14-rc crates — revisit when they stabilize or gate behind an audited C backend); PubSub ECC security; ECC-based user-identity-token encryption (unless trivially shared with the existing path); any C/OpenSSL crypto backend.
- Interop validation against a third-party ECC peer may be unavailable in CI; SC-007 allows falling back to spec/RFC vectors + loopback with the gap documented.
- Reuses existing infrastructure: the secure-channel/chunking framework, symmetric AES/HMAC code, X.509 handling, and certificate trust validation — ECC changes the asymmetric/key-agreement half only.

## Closeout Findings

- Completed 2026-06-28. Final gate passed locally: `cargo fmt --all --check`,
  `cargo clippy --all-targets --all-features -- -D warnings`, `cargo test --workspace`, and the
  CI-equivalent clean-codegen sequence all exited successfully.
- Generated code remained clean after rerunning all three codegen configs and `cargo fmt --all`
  (`git diff --exit-code` clean).
- Existing RSA/None behavior remains covered by the full workspace test suite plus the targeted
  `async-opcua-crypto --no-default-features` policy test proving ECC is recognized-but-unsupported
  while RSA/None stay supported. No new source changes were required in the final closeout branch.
- Third-party ECC wire interop remains unvalidated because no open62541 or UA-.NETStandard ECC peer
  was available; SC-007 is closed via the documented-gap path in `research.md`.
