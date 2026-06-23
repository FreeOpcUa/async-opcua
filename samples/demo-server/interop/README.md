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

## What it checks

| Area | Checks |
| --- | --- |
| Discovery | `GetEndpoints` returns endpoints; `None` and `Basic256Sha256/SignAndEncrypt` are advertised |
| Unsecured session | Browse `Objects`, read `Server/CurrentTime`, resolve the `urn:DemoServer` namespace, call the `HelloWorld` method, and receive subscription data-change notifications |
| Secured session | Establish a `Basic256Sha256` `SignAndEncrypt` channel + session (auto-trusted both ways) and read a value |

The server auto-trusts client certs (`trust_client_certs: true`) and the node-opcua client
auto-accepts the server cert, so the secured handshake completes unattended. The client
certificate is generated with a matching `applicationUri` so the server's
`Bad_CertificateUriInvalid` check is satisfied.

## Extending it

Add checks to `interop-test.mjs` — e.g. Write services, additional security policies
(`Aes256Sha256RsaPss`), username/password and X.509 user tokens, `TranslateBrowsePathsToNodeIds`,
or `RegisterServer`. To test the **client** side too, point a node-opcua *server* at the
async-opcua client. node-opcua's API docs: <https://node-opcua.github.io/>.

## Notes

- `node_modules/`, `package-lock.json`, and the generated PKI directories are git-ignored.
- This first found a real interop bug: async-opcua required the `applicationUri` to be the
  *first* certificate subjectAltName, but node-opcua orders DNS/IP before the URI. The
  validator now accepts the URI in any SAN position (Part 6 §6.2.2).
