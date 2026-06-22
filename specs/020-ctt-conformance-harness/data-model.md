# Data Model: Conformance Test Harness

## Conformance matrix cell (US1)
- `security_policy`: None | Basic128Rsa15 | Basic256 | Basic256Sha256 | Aes128Sha256RsaOaep |
  Aes256Sha256RsaPss | EccNistP256 | EccNistP384.
- `security_mode`: None (only with policy None) | Sign | SignAndEncrypt.
- `identity_token`: Anonymous | UserName(sample1/password) | X509(client_x509_token).
- `expected`: Accept (all listed services succeed) | Reject(StatusCode) (bad credential / token-policy
  mismatch). RSA cells run against `default_server`; ECC cells against `new_ecc(curve)` (two instances —
  single-cert constraint).

### Operations per Accept cell
connect + `wait_for_connection` (activation) → Read(`Server_ServiceLevel`) → Browse(RootFolder) →
Write(a writable node, or record StatusCode) → CreateSubscription + CreateMonitoredItem + receive ≥1 data
change → disconnect. Every step asserted; any unexpected failure fails the test (no skip).

### Negative cells
- UserName with wrong password → activation `Err` (`Bad_UserAccessDenied`/`Bad_IdentityTokenRejected`).
- Token type / policy mismatch → documented StatusCode.

## Server profile (US2)
- `rsa` (default): existing `sample.server.test.conf` + RSA app cert. Unchanged behavior.
- `ecc` (new): `sample.server.ecc.conf` (ECC_nistP256/P384 Sign+SignAndEncrypt, ANONYMOUS + user + x509)
  + EC app cert (`X509::cert_and_pkey_ecc`, `create_sample_keypair(false)`). Selected via arg/env.

## Known-gap entry (US3)
Tier 3 facet → StatusCode/behavior UACTT sees → why expected:
- NodeManagement (AddNodes/Write-Delete nodes) read-only → `Bad_ServiceUnsupported` (by design).
- Query over CoreNodeManager → unimplemented / `Bad_ViewIdUnknown` for non-default view.
- Discovery LDS (FindServersOnNetwork/RegisterServer2) → `Bad_ServiceUnsupported`.
- Method Call on core methods / Audit events → partial (non-mandatory).
