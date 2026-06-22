# Research: OPC UA Conformance Test Harness (CTT)

Findings from inspecting the existing test harness + demo-server, and the UACTT availability.

## Decision 1 — CI smoke reuses the `Tester` harness (US1)

**Finding**: `async-opcua/tests/utils/tester.rs` already provides everything the smoke needs:
- `default_server()` → a `ServerBuilder` advertising endpoints for **None, Basic128Rsa15, Basic256,
  Basic256Sha256, Aes128Sha256RsaOaep, Aes256Sha256RsaPss** (Sign + SignAndEncrypt each), each with
  `ANONYMOUS + CLIENT_USERPASS_ID + CLIENT_X509_ID` token ids. (This is the RSA matrix.)
- `Tester::new(server, ..)` / `new_ecc(curve)` (the ECC server, EC certs auto-provisioned) /
  `new_ecc_with_channel_lifetime`.
- `connect(policy, mode, identity_token)` → `(Arc<Session>, event loop)`.
- `client_user_token()` (sample1/its password) and `client_x509_token()` (an x509 IdentityToken).
**Decision**: implement the smoke as a new integration module `tests/integration/conformance.rs` that
loops over the matrix using `Tester` (RSA via `default_server`/`Tester::new`, ECC via `new_ecc(P256/P384)`)
and, per valid cell, runs the operations in Decision 2. Reuse `read_service_level`-style helpers from
`ecc.rs`/`core_tests.rs`. **Rationale**: the harness is proven and CI-runnable; no need to spawn the
demo-server binary (that's for the real UACTT).

## Decision 2 — Operations exercised per matrix cell

**Decision**: for each valid (policy, mode, token) cell: connect + `wait_for_connection` (activation);
**Read** (`Server_ServiceLevel`, always present); **Browse** the RootFolder (always present);
**Subscribe** — create a subscription + a monitored item on a server variable and receive at least one
data change; **Write** — write a value to a writable node provided by the test node manager (use the
`setup()`/`TestNodeManager` pattern, or a known writable demo node; if no writable node is available in
the chosen server build, Write is asserted on a node and its StatusCode recorded rather than skipped);
clean **disconnect**. **Rationale**: covers the core CTT service areas (Attribute read/write, View browse,
Subscription) with operations available on any compliant server.

## Decision 3 — Matrix + invalid cells (US1/FR-002)

**Decision**: the matrix is (security policy × mode × token type). Valid cells must succeed. Negative
cells the smoke asserts:
- **Wrong password** under a user-password token → activation fails (`Bad_UserAccessDenied` /
  `Bad_IdentityTokenRejected`).
- A token type not offered by an endpoint, or a `None`-policy user-token over a secured-required context →
  rejected with the documented StatusCode.
No cell is silently skipped — an unexpected failure on a valid cell is a test failure. **Rationale**:
FR-002 (surface broken cells); the project's "fail-closed / surface, don't hide" practice.

## Decision 4 — ECC is a separate server instance (single-cert constraint)

**Decision**: RSA and ECC cells run against **two different server instances** (`Tester::new` with the RSA
`default_server`, and `Tester::new_ecc(curve)` with an EC cert). A single server cannot serve both
(one ApplicationInstance cert; RSA cert can't do ECDSA). The deferred mixed-cert server (012) stays
deferred. **Rationale**: hard protocol/crypto constraint; matches how `ecc.rs` already tests ECC.

## Decision 5 — Demo-server ECC profile (US2)

**Finding**: the demo-server (`samples/demo-server`) is config-driven: `main.rs` loads
`sample.server.test.conf` (RSA endpoints + anon/user/x509 tokens). It uses an RSA sample keypair.
**Decision**: add `samples/demo-server/sample.server.ecc.conf` advertising `ECC_nistP256`/`ECC_nistP384`
(Sign + SignAndEncrypt) with the same token ids, and make `main.rs` select the config via an
arg/env (e.g. `--config <path>` or `OPCUA_DEMO_CONFIG`/profile flag), defaulting to the existing RSA conf
(no behavior change). Provision an **EC** application cert for the ECC profile (mirror the integration
`provision_ecc_certs` approach: `X509::cert_and_pkey_ecc` written to the PKI `own/` dir, `create_sample_keypair(false)`).
Verify the RSA conf already has a `None` endpoint + all three token types on each endpoint (fill gaps if
not — the conf already lists ANONYMOUS + user + x509). **Rationale**: separate profile honors the
single-cert constraint; arg/env keeps the default intact.

## Decision 6 — UACTT run guide + script (US3) — the user can run UACTT on a Windows VM

**Finding (updated)**: the user has a Windows VM and can run the real UACTT if downloadable. The UACTT is
distributed by the OPC Foundation (the **Compliance Test Tool**); a working version is available to
registered users / members via the OPC Foundation site (and the GitHub `OPCFoundation/UA-ComplianceTestTool`
references). So the guide should be **directly actionable**, not hypothetical.
**Decision**: `docs/ctt-conformance.md` includes: (a) where to obtain the UACTT (OPC Foundation download /
membership note) + Windows-VM prerequisites; (b) build/run the demo-server RSA and ECC profiles (exact
commands); (c) cert provisioning + **cross-trust** steps (copy the server cert into the UACTT trusted dir
and the UACTT client cert into the server `pki/trusted/`), using the launch script's printed thumbprints;
(d) UACTT project setup: endpoint URLs per profile, security-policy/mode selection, the user/x509
credentials (sample1 / the x509 cert), and which **test groups/conformance units** apply (Security,
Session/SecureChannel, Attribute Services Read/Write, View/Browse, Subscription/MonitoredItems, plus the
Base/Embedded profile); (e) an **expected-results / known-gaps** table mapping the Tier 3 facets that fail
by design (NodeManagement read-only → `Bad_ServiceUnsupported`; Query over CoreNodeManager →
`Bad_ViewIdUnknown`/unimplemented; Discovery LDS stubs → `Bad_ServiceUnsupported`; Method Call / Audit
events partial). **Launch script** (`samples/demo-server/run-conformance.sh` or `tools/`): boots a chosen
profile (`rsa`|`ecc`) with a clean PKI dir, prints the endpoint URLs + the server cert SHA1/SHA256
thumbprint to trust. **Rationale**: the user will actually run it; make it copy-paste reproducible.

## Decision 7 — Reliability under parallel-load flakiness (FR-003)

**Decision**: the integration suite has known parallel-load timeout flakiness; the conformance smoke (many
sequential connects) is heavier, so run it **single-threaded / isolated** (e.g. assert via one
`#[tokio::test]` that iterates the matrix sequentially, with generous per-connect timeouts), and verify
green in isolation per project practice. **Rationale**: established project handling of the flaky suite.

## Decision 8 — Scope / structure

- US1: `async-opcua/tests/integration/conformance.rs` (Claude — it IS the conformance test) +
  registration in `tests/integration_tests.rs` (or the `integration` mod).
- US2: `samples/demo-server/sample.server.ecc.conf` + `main.rs` config selection + EC cert provisioning
  (codex — sample/production code).
- US3: `docs/ctt-conformance.md` + a launch script (codex/Claude — docs + shell).
- US4: a coverage/limitations section in the smoke module + the guide (Claude).
No new library dependency; the smoke is a test; the script is shell. `clippy --all-targets --all-features`
clean.

## Decision 9 — Verification anchoring

**Decision**: the smoke is anchored to **real client↔server behavior** across the matrix (not loopback) —
it actually connects and runs services; any broken cell fails the test. The known-gaps table is anchored
to `specs/conformance-gap-backlog.md` + the Tier 3 service behaviors. **Rationale**: verification division;
the smoke is the conformance test itself.
