# Contract: OPC Foundation Profile Benchmark Builds

## Sample Build Contract

Profile benchmark package: `async-opcua-foundation-profile-server`

Supported feature selections:
- `nano`
- `micro`
- `embedded`

Invalid feature selections:
- no profile feature
- more than one profile feature

Expected build commands:

```sh
cargo build --locked -p async-opcua-foundation-profile-server --no-default-features --features nano
cargo build --locked -p async-opcua-foundation-profile-server --no-default-features --features micro
cargo build --locked -p async-opcua-foundation-profile-server --no-default-features --features embedded
```

Expected test commands:

```sh
cargo test --locked -p async-opcua-foundation-profile-server --no-default-features --features nano
cargo test --locked -p async-opcua-foundation-profile-server --no-default-features --features micro
cargo test --locked -p async-opcua-foundation-profile-server --no-default-features --features embedded
```

Expected behavior:
- The selected benchmark reports the target URI for its Foundation profile.
- The built server leaves `ServerCapabilities.ServerProfileArray` empty.
- The benchmark dependency tree omits `async-opcua-core-namespace`.

Embedded profile size commands:

```sh
cargo build --locked --profile embedded -p async-opcua-foundation-profile-server --no-default-features --features nano
cargo build --locked --profile embedded -p async-opcua-foundation-profile-server --no-default-features --features micro
cargo build --locked --profile embedded -p async-opcua-foundation-profile-server --no-default-features --features embedded
```

## CI Contract

Reusable workflow: `.github/workflows/ci_footprint.yml`

Expected behavior:
- Builds the existing minimal server footprint sample.
- Builds `nano`, `micro`, and `embedded` profile benchmark variants under the embedded Cargo profile.
- Prints one size line for the minimal sample and one size line for each Foundation profile benchmark variant.
- Fails if any Foundation profile benchmark variant includes the generated core namespace dependency.
