# Quickstart: External Implementation Interop Checks

## Validate the default demo-server path

```sh
./samples/demo-server/interop/dotnet/run-dotnet.sh
./samples/demo-server/interop/asyncua/run-asyncua.sh
```

Expected result: both commands start the async-opcua demo server themselves and exit with status `0`.

## Validate portable checks against the local demo server

Start the demo server in one terminal:

```sh
cd samples/demo-server
cargo run -q -p async-opcua-demo-server -- --config interop/interop.server.conf
```

Run portable external checks from the repository root:

```sh
./samples/demo-server/interop/dotnet/run-dotnet.sh --external opc.tcp://127.0.0.1:4855 --security auto
./samples/demo-server/interop/asyncua/run-asyncua.sh --external opc.tcp://127.0.0.1:4855
```

Expected result: both commands connect to the supplied endpoint, do not launch another server, and exit with status `0`.

## Validate an external implementation

Build and launch the external implementation outside this repository, then run:

```sh
OPCUA_EXTERNAL_ENDPOINT=opc.tcp://127.0.0.1:4840
./samples/demo-server/interop/dotnet/run-dotnet.sh --external "$OPCUA_EXTERNAL_ENDPOINT" --security auto
./samples/demo-server/interop/asyncua/run-asyncua.sh --external "$OPCUA_EXTERNAL_ENDPOINT"
```

Expected result: failures identify the specific portable behavior the external server did not satisfy.

## CI usage

Call the reusable workflow with an endpoint that is reachable from the reusable workflow runner:

```yaml
interop:
  uses: ./.github/workflows/ci_interop.yml
  with:
    external_endpoint: opc.tcp://127.0.0.1:4840
```

When `external_endpoint` is omitted or empty, the external job is skipped. If the target server listens only on `127.0.0.1`, launch it in the same job and call the wrapper scripts directly; localhost is not shared between separate GitHub Actions jobs.
