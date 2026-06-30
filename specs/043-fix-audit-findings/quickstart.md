# Quickstart: Audit Findings Remediation

Run the focused command for each task before starting the next one. Use the broader gate before
claiming the feature is complete.

## Session And Identity Checks

```bash
cargo test -p async-opcua-server x509
cargo test -p async-opcua-server --test security_tests
cargo test -p async-opcua --test integration_tests adversarial
cargo test -p async-opcua --test integration_tests session_audit
```

## Certificate And GDS Checks

```bash
cargo test -p async-opcua-crypto cert_chain
cargo test -p async-opcua-server certificate_audit
cargo test -p async-opcua-server --test gds_pull_methods
cargo test -p async-opcua-server --test gds_integration
```

## Transport And Encoding Checks

```bash
cargo test -p async-opcua-core comms
cargo test -p async-opcua-core secure_channel
cargo test -p async-opcua-types encoding
cargo test -p async-opcua-types diagnostic
```

## PubSub And SKS Checks

```bash
cargo test -p async-opcua-pubsub
cargo test -p async-opcua-server --test security_tests get_security_keys
cargo test -p async-opcua --test integration_tests pubsub
```

## XML And History Checks

```bash
cargo test -p async-opcua-xml
cargo test -p async-opcua-history-sqlite
```

## Full Completion Gate

```bash
cargo fmt --check
cargo test --workspace --all-targets --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test -p async-opcua-server certificate_audit
cargo test -p async-opcua --test integration_tests session_audit
cargo build --locked --profile embedded -p async-opcua-minimal-server
cargo build --locked --profile embedded -p async-opcua-foundation-profile-nano-server
cargo build --locked --profile embedded -p async-opcua-foundation-profile-micro-server
cargo build --locked --profile embedded -p async-opcua-foundation-profile-embedded-server
./samples/demo-server/interop/run-interop.sh
./samples/demo-server/interop/open62541/run-open62541.sh
./samples/demo-server/interop/asyncua/run-asyncua.sh
./samples/demo-server/interop/dotnet/run-dotnet.sh
```

## Expected Evidence

- Every remediated finding has a failing-first negative-path test.
- Every negative-path test cites the OPC UA part/section or an explicit audit finding.
- P0/P1 identity, certificate, and credential findings are closed before lower-priority protocol
  robustness work.
- Malformed network, PubSub, XML, history, and encoding inputs fail without panic, unbounded
  allocation, or unintended state update.
- Certificate and GDS replacement failures preserve existing valid trust material.
