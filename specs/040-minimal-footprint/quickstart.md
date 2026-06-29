# Quickstart: Minimal Deployment Footprint

## Build the minimal server sample

```sh
cargo build --locked -p async-opcua-minimal-server
```

Expected result: the sample compiles while depending on the umbrella crate with the base server path.

## Build with the embedded profile

```sh
cargo build --locked --profile embedded -p async-opcua-minimal-server
```

Expected result: the size-optimized binary is produced at `target/embedded/async-opcua-minimal-server`.

## Confirm generated namespace is absent

```sh
if cargo tree --locked -p async-opcua-minimal-server -e normal | rg 'async-opcua-core-namespace'; then
  echo "unexpected generated namespace dependency"
  exit 1
fi
```

Expected result: no generated namespace dependency is printed.

## Report the local binary size

```sh
stat -c '%s bytes %n' target/embedded/async-opcua-minimal-server
```

Expected result: the command prints the embedded-profile binary size for the minimal sample.

## Compare with the full simple server

```sh
cargo build --locked --profile embedded -p async-opcua-simple-server
stat -c '%s bytes %n' \
  target/embedded/async-opcua-minimal-server \
  target/embedded/async-opcua-simple-server
```

Expected result: the minimal server remains materially smaller because it omits the generated core namespace.

## Check against the audit baseline

The performance audit measured the release-profile simple server at `38,430,784` bytes. A 25% smaller binary must be at most `28,823,088` bytes.

```sh
minimal_size=$(stat -c '%s' target/embedded/async-opcua-minimal-server)
test "$minimal_size" -le 28823088
```

Expected result: the check exits with status `0`.
