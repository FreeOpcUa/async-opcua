# Data Model: NIST ECC Security Policies

Entities are internal unless marked public. ECC adds the asymmetric/key-agreement half; symmetric
`SecurityKeys` (signing/encrypting/IV) and the chunk framework are existing types, reused.

## ECC SecurityPolicy (public, extends existing enum)

| Variant | Curve | Hash | Symmetric | KDF |
|---------|-------|------|-----------|-----|
| `EccNistP256` | NIST P-256 | SHA-256 | AES-128-CBC + HMAC-SHA256 | HKDF-SHA256 |
| `EccNistP384` | NIST P-384 | SHA-384 | AES-256-CBC + HMAC-SHA384 | HKDF-SHA384 |

- URI ↔ variant mapping; `supported()` true only when the `ecc` feature is built in.

## Ephemeral EC key pair (internal, transient)

| Field | Notes |
|-------|-------|
| private scalar | generated per channel open; never persisted, never logged; zeroized after ECDH |
| public point | sent on the wire as `x ‖ y` zero-padded big-endian (64 B P-256 / 96 B P-384) |

- Lifecycle: created at OpenSecureChannel; private half consumed by one ECDH; dropped immediately after.

## ECDH shared secret (internal, transient)

- The ECDH output field element (32 B / 48 B); used **only** as HKDF IKM; zeroized after derivation.

## Derived SecurityKeys (internal) — produced by HKDF, consumed by existing symmetric code

| Field | P-256 | P-384 | Source |
|-------|-------|-------|--------|
| SigningKey | 32 B | 48 B | HKDF keystream offset 0 |
| EncryptingKey | 16 B | 32 B | offset = SigLen |
| IV | 16 B | 16 B | offset = SigLen+EncLen |

- Two sets: client keys (from `ClientSalt`), server keys (from `ServerSalt`). Regenerated on channel
  renewal. Same downstream type as the RSA path → message protection reuses existing code.

## EC application certificate (existing X.509 type, extended validation)

| Aspect | Notes |
|--------|-------|
| public key | `id-ecPublicKey` on P-256 or P-384 |
| thumbprint | SHA-1 of DER (spec-mandated), reused |
| validation | existing chain/trust/validity reused; ADD: reject if curve ≠ negotiated policy |

## State transition — ECC OpenSecureChannel (vs RSA)

```
Client: gen ephemeral (JC,KC); put JC in ClientNonce; ECDSA-sign request with EC app key  ──>
Server: verify ECDSA sig vs client cert; gen ephemeral (JS,KS); put JS in ServerNonce;
        sharedSecret = ECDH(KS, JC); derive client+server SecurityKeys via HKDF; ECDSA-sign response <──
Client: verify ECDSA sig vs server cert; sharedSecret = ECDH(KC, JS); derive identical keys
Both:   symmetric traffic (AES-CBC + HMAC) using derived keys — existing chunk code
Renewal: new ephemerals -> new shared secret -> new keys
```

(Contrast RSA: nonces are random bytes RSA-encrypted to the peer; ECC replaces that with ephemeral
EC public keys + ECDH — no asymmetric encryption.)
