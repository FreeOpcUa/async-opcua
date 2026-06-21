# Data Model: ECC Token EphemeralKey Exchange (Part 6 §6.8.2)

Entities are existing generated types (reused) plus a small amount of per-session server state.

## Wire entities (existing generated types — reused, not modified)

| Entity | Where | Fields used |
|--------|-------|-------------|
| `EphemeralKeyType` (Part 4 §7.15, Table 136) | request/response `AdditionalHeader` value `ECDHKey` | `publicKey: ByteString` (ECC ephemeral public key, curve-encoded), `signature` (created by the issuer over the key so the receiver can authenticate it) |
| `AdditionalParametersType` (Part 6 Table 70) | request/response header `AdditionalHeader` | name-value list carrying `ECDHPolicyUri` (String) and `ECDHKey` (`EphemeralKeyType`, or a StatusCode on error) |

## Server per-session state (new, in-memory)

| Field | Purpose |
|-------|---------|
| issued EphemeralKey (private + public, + the policy it is for) | the most-recently-issued server ephemeral key the client will encrypt against |
| consumed-key marker / set | enforce §6.8.2 anti-replay — an EphemeralKey that was used in a successful ActivateSession MUST NOT be accepted again (bounded per session) |
| last `ECDHPolicyUri` | to apply the §6.8.2 "no policy provided" return rules |

## Client per-session state (new, in-memory)

| Field | Purpose |
|-------|---------|
| most-recent verified server EphemeralKey (public) + its policy | the receiver ephemeral key feature 016 will use to derive the secret key; replaced each time a newer, signature-verified `ECDHKey` arrives |

## Rules

- **Issue (server, FR-001/FR-002):** valid `ECDHPolicyUri` → generate a fresh ephemeral keypair for the
  curve, sign the public key, return `ECDHKey`. Invalid/unsupported → `Bad_SecurityPolicyRejected` in
  place of the key. Absent → no key (today's behavior).
- **Lifecycle (server, FR-004, §6.8.2):** at ActivateSession, return new-vs-retain per the §6.8.2
  rules; a successfully-consumed EphemeralKey is never accepted again (anti-replay).
- **Verify (client, FR-003):** read `ECDHKey`, verify its signature against the server certificate and
  that `publicKey` is a valid curve point; reject otherwise; retain the most recent verified key.
- **Fail-closed (FR-005):** malformed AdditionalHeader / `EphemeralKeyType` bytes are rejected without
  panic.

## State transition (per session)

```
CreateSession(req: ECDHPolicyUri?) → server: valid? generate+sign EphemeralKey EK1 → resp(ECDHKey=EK1)
client: verify EK1 vs server cert → retain EK1
ActivateSession(req: ECDHPolicyUri?, uses EK?) → server: §6.8.2 rules → resp(ECDHKey=EK2 | none)
  on success: mark the consumed EphemeralKey as never-reusable (anti-replay)
client: verify EK2 → retain (most recent wins)
```
(Feature 016 consumes the retained server EphemeralKey + the client's own ephemeral key to build the
`EccEncryptedSecret`.)
