# Contract: External Interop Harness

## Local .NET Reference Client Wrapper

Command:

```sh
samples/demo-server/interop/dotnet/run-dotnet.sh --external <endpoint-url> [--profile portable|async-opcua-demo] [--security none|best|auto]
```

Behavior:

- Does not start the async-opcua demo server when `--external` is present.
- Defaults to `--profile portable` in external mode.
- Uses `--security auto` unless explicitly overridden.
- Returns `0` only when all selected checks pass.
- Returns a non-zero status when any selected check fails.

## Local asyncua Wrapper

Command:

```sh
samples/demo-server/interop/asyncua/run-asyncua.sh --external <endpoint-url>
```

Behavior:

- Does not start the async-opcua demo server when `--external` is present.
- Runs the portable asyncua profile against the supplied endpoint.
- Uses anonymous client behavior.
- Returns `0` only when all selected checks pass.
- Returns a non-zero status when any selected check fails.

## Reusable CI Workflow

Workflow:

```yaml
jobs:
  interop:
    uses: ./.github/workflows/ci_interop.yml
    with:
      external_endpoint: opc.tcp://127.0.0.1:4840
```

Inputs:

- `external_endpoint`: optional OPC UA endpoint URL. Empty by default.

Behavior:

- Always runs the existing demo-server interop job.
- Runs external portable checks only when `external_endpoint` is non-empty.
- Exposes `OPCUA_EXTERNAL_ENDPOINT` to external-check steps.
- Does not clone, modify, or write files into an external implementation repository.
