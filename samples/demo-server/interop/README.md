# Interop conformance smoke test

A cross-implementation interop test: it boots the async-opcua **demo server** and drives it
with an **independent** OPC UA stack ([node-opcua](https://github.com/node-opcua/node-opcua)).

This is the practical substitute for the official **UACTT** (Unified Architecture Compliance
Test Tool), which is only available to OPC Foundation **corporate** members. Driving the
server with a second, independently-written stack exercises the same interop surface the CTT
targets and catches divergences that same-stack tests cannot.

## Run it

```sh
./run-interop.sh
```

Requires `cargo`, `node` (>= 18) and `npm`. The script:

1. installs `node-opcua` into `node_modules/` (first run only),
2. cleans the PKI directories,
3. builds and starts the demo server on `opc.tcp://127.0.0.1:4855/` using
   [`interop.server.conf`](interop.server.conf) (modern security policies only — no
   `legacy-crypto` feature required),
4. runs [`interop-test.mjs`](interop-test.mjs) against it, and
5. stops the server.

Exit code is the number of failed checks (`0` = all passed).

## What it checks (22 checks)

| Area | Checks |
| --- | --- |
| Discovery | `GetEndpoints` returns endpoints; `None` and `Basic256Sha256/SignAndEncrypt` are advertised |
| Unsecured session | Browse `Objects`, read `Server/CurrentTime`, resolve the `urn:DemoServer` namespace, call the `HelloWorld` method, and receive subscription data-change notifications |
| Secured session | Establish a `Basic256Sha256` `SignAndEncrypt` channel + session and read a value |
| Security matrix | Connect + read across `Basic256Sha256` (Sign and SignAndEncrypt), `Aes128Sha256RsaOaep` and `Aes256Sha256RsaPss` (SignAndEncrypt) |
| Write + Translate | Write to a writable demo variable and read the value back; `TranslateBrowsePathsToNodeIds` resolves `Server/ServerStatus/CurrentTime` to `i=2258` |
| User token | Username/password identity token (`sample1` / `sample1_password`) over a secured channel |

The server auto-trusts client certs (`trust_client_certs: true`) and the node-opcua client
auto-accepts the server cert, so the secured handshake completes unattended. The client
certificate is generated with a matching `applicationUri` so the server's
`Bad_CertificateUriInvalid` check is satisfied.

## Second independent stack: open62541 (C)

Two independently-written stacks agreeing is a strong conformance signal; disagreement is
high-signal. A second stack — **open62541** (C, MPL-2.0) — lives in
[`open62541/`](open62541/) and is driven the same way:

```sh
./open62541/run-open62541.sh   # 14/14 checks
```

It builds open62541 from source (`cmake` + a C compiler — no Windows needed), so it shares
no code with node-opcua. Run both for the strongest signal. To run them together:

```sh
./run-interop.sh && ./open62541/run-open62541.sh
```

For an even stronger (CTT-grade) cross-check, the OPC Foundation **UA-.NETStandard**
reference stack is what the UACTT itself is built on (needs the .NET SDK); **UaExpert**
(free GUI) is handy for manual exploration.

## External implementation smoke: portable profile

The .NET reference-client harness has two profiles:

```sh
./dotnet/run-dotnet.sh
```

runs the full async-opcua demo-server suite. It assumes the demo namespace,
writable demo variables, methods, subscriptions, history, and the demo security
matrix.

```sh
./dotnet/run-dotnet.sh --external opc.tcp://127.0.0.1:4840
./dotnet/run-dotnet.sh --external opc.tcp://127.0.0.1:4840 --security auto
```

runs the portable profile against an already-running server. That profile avoids
demo-specific nodes and checks only standard OPC UA behavior: discovery,
anonymous session activation, standard reads under `ServerStatus`, browsing the
Objects folder, and one unknown-node status path. Use `--security none`, `best`,
or `auto` to choose the endpoint policy; the wrapper defaults to `auto`. The
portable unknown-node check expects `BadNodeIdUnknown`, so a generic Bad status
is not enough.

The Python asyncua harness also has an external portable mode:

```sh
./asyncua/run-asyncua.sh --external opc.tcp://127.0.0.1:4840
```

It runs the same standard-node smoke at anonymous/no-security level. Use it as a
second independent client signal next to the .NET reference stack; use the .NET
`--security best` path when you specifically want to probe a secured endpoint.

In reusable GitHub Actions CI, the external checks are skipped unless a caller
passes an endpoint reachable from the interop job runner:

```yaml
interop:
  uses: ./.github/workflows/ci_interop.yml
  with:
    external_endpoint: opc.tcp://127.0.0.1:4840
```

The caller is responsible for building and launching the external server before
that workflow runs. If the server only listens on `127.0.0.1`, launch it in the
same job and call the wrapper scripts directly; separate GitHub Actions jobs do
not share localhost. The harness does not clone or modify the external
implementation repository.

## Extending it

Add checks to `interop-test.mjs` — e.g. X.509 user tokens, `RegisterServer`, Query, History,
or additional Write/array round-trips. To test the **client** side too, point a node-opcua
*server* at the async-opcua client. node-opcua's API docs: <https://node-opcua.github.io/>.

## Notes

- `node_modules/`, `package-lock.json`, and the generated PKI directories are git-ignored.
- This first found a real interop bug: async-opcua required the `applicationUri` to be the
  *first* certificate subjectAltName, but node-opcua orders DNS/IP before the URI. The
  validator now accepts the URI in any SAN position (Part 6 §6.2.2).
