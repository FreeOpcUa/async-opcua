# Quickstart: OPC Foundation Profile Benchmark Builds

## Build all benchmark variants

```sh
cargo build --locked -p async-opcua-foundation-profile-server --no-default-features --features nano
cargo build --locked -p async-opcua-foundation-profile-server --no-default-features --features micro
cargo build --locked -p async-opcua-foundation-profile-server --no-default-features --features embedded
```

Expected result: all three commands compile.

## Verify target URI selection and conformance-claim behavior

```sh
cargo test --locked -p async-opcua-foundation-profile-server --no-default-features --features nano
cargo test --locked -p async-opcua-foundation-profile-server --no-default-features --features micro
cargo test --locked -p async-opcua-foundation-profile-server --no-default-features --features embedded
```

Expected result: each selected build reports exactly its own target profile URI and does not populate `ServerCapabilities.ServerProfileArray`.

## Confirm generated namespace is absent

```sh
for profile in nano micro embedded; do
  if cargo tree --locked -p async-opcua-foundation-profile-server --no-default-features --features "$profile" -e normal \
    | grep -q 'async-opcua-core-namespace'; then
    echo "unexpected generated namespace dependency in $profile benchmark"
    exit 1
  fi
done
```

Expected result: all three profile benchmark dependency trees omit the generated core namespace.

## Confirm invalid selections fail

```sh
if cargo check --locked -p async-opcua-foundation-profile-server --no-default-features; then
  echo "expected no-profile build to fail"
  exit 1
fi

if cargo check --locked -p async-opcua-foundation-profile-server --no-default-features --features nano,micro; then
  echo "expected multi-profile build to fail"
  exit 1
fi
```

Expected result: both invalid selections fail before producing a binary.

## Build embedded-profile binaries and report sizes

```sh
for profile in nano micro embedded; do
  cargo build --locked --profile embedded -p async-opcua-foundation-profile-server --no-default-features --features "$profile"
  stat -c "${profile}: %s bytes %n" target/embedded/async-opcua-foundation-profile-server
done
```

Expected result: each profile benchmark build prints a byte-size line.

## Scope note

These builds are CI-visible profile benchmark builds. They are not official OPC Foundation certification results and they do not advertise `ServerProfileArray` profile conformance. Use OPC Foundation conformance tooling for certification-grade evidence.
