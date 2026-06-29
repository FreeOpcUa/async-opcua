# Contract: OPC Foundation Profile Benchmark Builds

## Sample Build Contract

Profile benchmark packages:
- `async-opcua-foundation-profile-nano-server`
- `async-opcua-foundation-profile-micro-server`
- `async-opcua-foundation-profile-embedded-server`

Supported packages:
- `async-opcua-foundation-profile-nano-server`
- `async-opcua-foundation-profile-micro-server`
- `async-opcua-foundation-profile-embedded-server`

Expected build commands:

```sh
cargo build --locked -p async-opcua-foundation-profile-nano-server
cargo build --locked -p async-opcua-foundation-profile-micro-server
cargo build --locked -p async-opcua-foundation-profile-embedded-server
```

Expected test commands:

```sh
cargo test --locked -p async-opcua-foundation-profile-nano-server
cargo test --locked -p async-opcua-foundation-profile-micro-server
cargo test --locked -p async-opcua-foundation-profile-embedded-server
```

Expected behavior:
- The selected benchmark package reports the target URI for its Foundation profile.
- The built server leaves `ServerCapabilities.ServerProfileArray` empty.
- The benchmark dependency tree omits `async-opcua-core-namespace`.

Embedded profile size commands:

```sh
cargo build --locked --profile embedded -p async-opcua-foundation-profile-nano-server
cargo build --locked --profile embedded -p async-opcua-foundation-profile-micro-server
cargo build --locked --profile embedded -p async-opcua-foundation-profile-embedded-server
```

## CI Contract

Reusable workflow: `.github/workflows/ci_footprint.yml`

Expected behavior:
- Builds the existing minimal server footprint sample.
- Builds `nano`, `micro`, and `embedded` profile benchmark variants under the embedded Cargo profile.
- Prints one size line for the minimal sample and one size line for each Foundation profile benchmark variant.
- Fails if any Foundation profile benchmark variant includes the generated core namespace dependency.
