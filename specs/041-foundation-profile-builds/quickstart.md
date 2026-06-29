# Quickstart: OPC Foundation Profile Benchmark Builds

## Build all benchmark variants

```sh
cargo build --locked -p async-opcua-foundation-profile-nano-server
cargo build --locked -p async-opcua-foundation-profile-micro-server
cargo build --locked -p async-opcua-foundation-profile-embedded-server
```

Expected result: all three commands compile.

## Verify target URI selection and conformance-claim behavior

```sh
cargo test --locked -p async-opcua-foundation-profile-nano-server
cargo test --locked -p async-opcua-foundation-profile-micro-server
cargo test --locked -p async-opcua-foundation-profile-embedded-server
```

Expected result: each selected build reports exactly its own target profile URI and does not populate `ServerCapabilities.ServerProfileArray`.

## Confirm generated namespace is absent

```sh
for package in \
  async-opcua-foundation-profile-nano-server \
  async-opcua-foundation-profile-micro-server \
  async-opcua-foundation-profile-embedded-server
do
  if cargo tree --locked -p "$package" -e normal \
    | grep -q 'async-opcua-core-namespace'; then
    echo "unexpected generated namespace dependency in $package"
    exit 1
  fi
done
```

Expected result: all three profile benchmark dependency trees omit the generated core namespace.

## Confirm workspace builds

```sh
cargo build --locked --workspace
cargo build --locked --workspace --all-features
```

Expected result: repository-wide workspace builds include all three benchmark packages.

## Build embedded-profile binaries and report sizes

```sh
for package in \
  async-opcua-foundation-profile-nano-server \
  async-opcua-foundation-profile-micro-server \
  async-opcua-foundation-profile-embedded-server
do
  cargo build --locked --profile embedded -p "$package"
  stat -c "${package}: %s bytes %n" "target/embedded/$package"
done
```

Expected result: each profile benchmark build prints a byte-size line.

## Scope note

These builds are CI-visible profile benchmark builds. They are not official OPC Foundation certification results and they do not advertise `ServerProfileArray` profile conformance. Use OPC Foundation conformance tooling for certification-grade evidence.
