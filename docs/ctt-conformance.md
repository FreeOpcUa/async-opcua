# OPC UA Conformance Testing (UACTT) Guide

This guide explains how to run the **OPC Foundation Compliance Test Tool (UACTT)**
against the async-opcua demo server, and how to read the results.

> **Why this doc exists.** The UACTT is the authoritative OPC UA conformance
> suite, but it is a proprietary **Windows GUI** tool (OPC Foundation membership
> required) and cannot run in this Linux/CI environment. CI instead runs a
> **conformance smoke** — a Linux proxy that drives our server with our client
> across the full security/token matrix
> (`async-opcua/tests/integration/conformance.rs`). That smoke is a
> regression guard, **not** an independent conformance authority. For an
> authoritative pass you run the real UACTT on Windows, as described here.

---

## 1. Obtain the UACTT

- The UACTT is distributed by the **OPC Foundation** to members / registered
  users. See <https://opcfoundation.org/> (Compliance → Compliance Test Tool)
  and the public references at
  <https://github.com/OPCFoundation/UA-ComplianceTestTool>.
- Install it on a **Windows** host or VM. A Linux/macOS host running the
  demo server plus a Windows VM running the UACTT (bridged/host networking so
  the VM can reach the server's endpoint URL) is a perfectly good setup.

## 2. Build & run the demo-server profiles

A server has a **single ApplicationInstance certificate**, and an RSA cert
cannot perform ECDSA, so one server instance cannot serve both RSA and ECC
policies. There are therefore **two profiles**, run one at a time:

| Profile | Config | Port | Policies |
|---------|--------|------|----------|
| `rsa` (default) | `sample.server.test.conf` | 4855 | None, Basic128Rsa15, Basic256, Basic256Sha256, Aes128-Sha256-RsaOaep, Aes256-Sha256-RsaPss (Sign + SignAndEncrypt) |
| `ecc` | `sample.server.ecc.conf` | 4856 | ECC_nistP256, ECC_nistP384 (Sign + SignAndEncrypt) |

Both profiles offer **Anonymous**, **user/password** (`sample1` /
`sample1_password`, and `sample2`), and **x509** identity tokens on every
endpoint.

### Easiest: the launch script

From `samples/demo-server/`:

```bash
./run-conformance.sh rsa          # RSA profile on :4855
./run-conformance.sh ecc          # ECC profile, P-256, on :4856
./run-conformance.sh ecc p384     # ECC profile, P-384
```

The script cleans the profile's PKI directory (so a fresh server cert is
generated), starts the server, and prints the **endpoint URL** plus the
**server certificate SHA1/SHA256 thumbprints** you need to trust in the UACTT.
Press Ctrl-C to stop.

### Manual

```bash
cd samples/demo-server
# RSA (default) — unchanged behavior:
cargo run -p async-opcua-demo-server -- --config sample.server.test.conf
# ECC — provisions an EC application cert into ./pki-ecc before startup:
cargo run -p async-opcua-demo-server -- --config sample.server.ecc.conf --ecc p256
```

> The sample configs use `host: ${computername}`. The endpoint must be
> reachable from the UACTT VM, so set the host to a name/IP the VM can resolve
> (edit the `host:` and `discovery_urls:` entries if `${computername}` does not
> resolve across your network).

## 3. Provision & cross-trust certificates

OPC UA mutually authenticates application instance certificates. Both sides must
trust each other:

1. **Trust the server cert in the UACTT.** Start the chosen profile, copy the
   printed thumbprint, and import `samples/demo-server/pki[-ecc]/own/cert.der`
   into the UACTT's trusted certificate store (UACTT: *Settings → Certificates →
   Trust*). The thumbprints let you confirm you trusted the right cert.
2. **Trust the UACTT client cert in the server.** On first connect the UACTT
   presents its client cert; the demo configs set `trust_client_certs: true`, so
   the server auto-trusts it (the cert lands under `pki[-ecc]/rejected/` →
   move it to `pki[-ecc]/trusted/` if you turn auto-trust off). For a stricter
   run, set `trust_client_certs: false` and manually place the UACTT client cert
   in `pki[-ecc]/trusted/certs/`.

## 4. Configure the UACTT project

1. **Endpoint URL**: `opc.tcp://<host>:4855/` (RSA) or `:4856/` (ECC).
2. **Security**: select each policy/mode the profile advertises (the UACTT can
   iterate them). For ECC, select `ECC_nistP256` / `ECC_nistP384`.
3. **User identity**: Anonymous; UserName `sample1` / `sample1_password`; and
   the x509 user (point the UACTT at the matching user cert).
4. **Applicable test groups / conformance units** for this server's profile
   (Base/Embedded UA Server):
   - **Security** — certificate handling, policy/mode negotiation, rejection of
     bad credentials.
   - **SecureChannel / Session** — OpenSecureChannel, CreateSession,
     ActivateSession, renewal, timeouts.
   - **Attribute Service Set** — Read / Write.
   - **View Service Set** — Browse / BrowseNext / TranslateBrowsePathsToNodeIds.
   - **Subscription / MonitoredItem Service Sets** — CreateSubscription,
     CreateMonitoredItems, Publish, data changes.
   - **Base / Embedded profile** node/address-space checks.

## 5. Expected results / known gaps

Some UACTT conformance units target **optional** facets this server does not
implement (Tier 3 of `specs/conformance-gap-backlog.md`). Failures in these
groups are **expected** and are not base/embedded-profile violations — do not
treat them as defects:

| UACTT area | Expected behavior | StatusCode | Why |
|------------|-------------------|------------|-----|
| **NodeManagement** (AddNodes / AddReferences / DeleteNodes / DeleteReferences) | Not supported | `Bad_ServiceUnsupported` | The CoreNodeManager address space is read-only by design (`clients_can_modify_address_space: false`); writability is an opt-in per node manager. |
| **Query** (QueryFirst / QueryNext) with a non-default `view` | Rejected | `Bad_ViewIdUnknown` | Default-view Query over the in-memory/core address space is implemented; alternate views are not. |
| **Discovery / LDS-ME multicast** (FindServersOnNetwork mDNS records) | Conditional | varies | RegisterServer/RegisterServer2 and pull-based FindServersOnNetwork are implemented. Multicast LDS-ME records require the off-by-default `discovery-mdns` feature and multicast discovery configuration. |
| **Method Call** on core methods; **Audit events** (Part 4 §5.6) | Partial | varies | Non-mandatory; low priority. The demo server defines its own methods (see `methods.rs`) which the UACTT *can* call. |

Everything outside this table (Security, SecureChannel/Session, Read/Write,
Browse, Subscription/MonitoredItem across the RSA and ECC policy/mode/token
matrix) is expected to **pass**. A failure there is a real defect — capture the
UACTT log and open an issue.

## 6. Relationship to the CI smoke

The CI conformance smoke
(`cargo test -p async-opcua --test integration_tests --features ecc conformance
-- --test-threads=1`) exercises the same Security / SecureChannel / Session /
Read / Browse / Subscription surface across the full matrix, in-process, on
every change. It is the day-to-day regression guard. This UACTT run is the
periodic, authoritative cross-check. Together they cover both "did we regress?"
(continuously, on Linux) and "are we conformant per the OPC Foundation?"
(on demand, on Windows).
