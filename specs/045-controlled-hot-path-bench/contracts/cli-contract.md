# CLI Contract: Controlled Hot Path Benchmark Harness

## Package

The in-repo command is invoked through Cargo:

```sh
cargo run -p async-opcua-localhost-bench -- <mode> [options]
```

## Modes

### One-shot Run

Starts the benchmark server, waits for readiness, runs one sample, prints one JSON object, and stops the server.

```sh
cargo run -p async-opcua-localhost-bench -- run --op read --port 4840 --warmup 1.0 --measure 5.0
cargo run -p async-opcua-localhost-bench -- run --op write --port 4840 --warmup 1.0 --measure 5.0
```

Required behavior:

- Exit `0` only if setup succeeds and measured failures are zero.
- Exit nonzero for startup failures, connection failures, invalid arguments, or measured service failures.

### Standalone Server

Starts the benchmark server only.

```sh
cargo run -p async-opcua-localhost-bench -- server --port 4840
```

Required behavior:

- Bind to `127.0.0.1:<port>`.
- Expose the benchmark value node at the documented namespace and numeric node id.
- Stop on Ctrl-C or normal process termination.

### Standalone Client

Runs one sample against an existing endpoint.

```sh
cargo run -p async-opcua-localhost-bench -- client --op read --endpoint opc.tcp://127.0.0.1:4840 --namespace 2 --node 1000 --warmup 1.0 --measure 5.0
```

Required behavior:

- Connect to the supplied endpoint.
- Execute the requested service operation against the supplied node.
- Print exactly one JSON sample on success or measured service failure.

## JSON Sample Schema

Every measured sample prints one JSON object with these fields:

```json
{
  "endpoint": "opc.tcp://127.0.0.1:4840",
  "op": "read",
  "node": "ns=2;i=1000",
  "warmup_ok": 100,
  "warmup_bad": 0,
  "ok": 1000,
  "bad": 0,
  "seconds": 5.000000000,
  "ops_per_sec": 200.0,
  "first_bad": "0x00000000"
}
```

Field requirements:

- `endpoint`, `op`, `node`, and `first_bad` are strings.
- `warmup_ok`, `warmup_bad`, `ok`, and `bad` are non-negative integers.
- `seconds` and `ops_per_sec` are numbers.
- `first_bad` is `"0x00000000"` when no operation failed.

## Default Target

- Endpoint: `opc.tcp://127.0.0.1:<port>`
- Namespace index: `2`
- Numeric node id: `1000`
- Attribute: Value
- Value type: Int32
