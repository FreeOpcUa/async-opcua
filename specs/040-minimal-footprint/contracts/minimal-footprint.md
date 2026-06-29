# Contract: Minimal Deployment Footprint

## Facade Feature Contract

Cargo dependency shape:

```toml
[dependencies.async-opcua]
version = "0.19"
default-features = false
features = ["base-server"]
```

Behavior:

- `opcua::server` is available.
- The generated core namespace is not enabled by this feature set.
- The existing `features = ["server"]` behavior remains available and continues to include the generated core namespace.

## Local Validation Commands

Build minimal sample:

```sh
cargo build --locked -p async-opcua-minimal-server
cargo build --locked --profile embedded -p async-opcua-minimal-server
```

Verify generated namespace is absent:

```sh
cargo tree --locked -p async-opcua-minimal-server -e normal | rg 'async-opcua-core-namespace' && exit 1 || exit 0
```

Report binary size:

```sh
stat -c '%s %n' target/embedded/async-opcua-minimal-server
```

Expected result:

- Both builds exit with status `0`.
- The generated namespace dependency check exits with status `0` because no match is found.
- The size report prints the executable size in bytes and path.

## CI Contract

Workflow:

```yaml
jobs:
  footprint:
    uses: ./.github/workflows/ci_footprint.yml
```

Behavior:

- Provisions the Rust toolchain.
- Builds `async-opcua-minimal-server` with the embedded profile.
- Fails if generated namespace appears in the sample's normal dependency graph.
- Prints the produced binary size.
- Does not install cargo-bloat or require external services.
