# open62541 second-stack interop test

Drives the async-opcua demo server with an [open62541](https://www.open62541.org/) (C)
client — a second, **independently-written** OPC UA stack alongside the node-opcua harness
in the parent directory. Two independent stacks passing is a strong conformance signal; a
disagreement between them is high-signal (it points at a real interop divergence).

## Run it

```sh
./run-open62541.sh
```

Requires `cargo`, `cmake`, `gcc`/`make`, `git`, and the OpenSSL development headers
(`libssl-dev`). On the first run it clones open62541 `v1.4.6` and builds it as a single-file
amalgamation with OpenSSL encryption (cached under `src/` and `build/`, both git-ignored),
then compiles [`client.c`](client.c), boots the demo server, and runs the client.

Exit code is the number of failed checks (`0` = all passed). **14/14 checks pass.**

## What it checks

- **Unsecured session:** browse `Objects`, read `Server/CurrentTime`, resolve the
  `urn:DemoServer` namespace, call `HelloWorld`, write to a writable variable and read it
  back, `TranslateBrowsePathsToNodeIds` (`Server/ServerStatus/CurrentTime` → `i=2258`), and
  subscription data-change delivery.
- **Username/password** identity token (`sample1` / `sample1_password`).
- **Secured** `Basic256Sha256` `SignAndEncrypt` session — using a freshly generated client
  certificate (`UA_CreateCertificate`) whose `applicationUri` matches its SAN. The server
  auto-trusts client certs (`trust_client_certs`) and the client accepts the server cert
  (`UA_CertificateVerification_AcceptAll`).

## Why two stacks

node-opcua (JavaScript) and open62541 (C) share no code. Running both against async-opcua
approximates the multi-implementation interop the official UACTT exercises — and it already
paid off: the node-opcua harness found a real `applicationUri` SAN-position bug that a
spec-only audit had dismissed. Extend either client and re-run both to widen coverage.
