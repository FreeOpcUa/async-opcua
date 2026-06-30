# async-opcua localhost benchmark

Controlled localhost benchmark harness for async-opcua Read and Write hot paths.

The harness exercises normal OPC UA Attribute Service Set Read/Write behavior against a deterministic writable `Int32` node:

- endpoint: `opc.tcp://127.0.0.1:<port>`
- namespace index: `2`
- numeric node id: `1000`

## One-Shot Samples

```sh
cargo run --release -p async-opcua-localhost-bench -- run --op read --port 4840 --warmup 1.0 --measure 5.0
cargo run --release -p async-opcua-localhost-bench -- run --op write --port 4840 --warmup 1.0 --measure 5.0
```

Each command starts an async-opcua server, waits for readiness, runs one sample, prints one JSON object, and stops the server.

## Standalone Profiling

Run the server in one terminal:

```sh
cargo run --release -p async-opcua-localhost-bench -- server --port 4840
```

Run clients in another terminal:

```sh
cargo run --release -p async-opcua-localhost-bench -- client --op read --endpoint opc.tcp://127.0.0.1:4840 --namespace 2 --node 1000 --warmup 1.0 --measure 5.0
cargo run --release -p async-opcua-localhost-bench -- client --op write --endpoint opc.tcp://127.0.0.1:4840 --namespace 2 --node 1000 --warmup 1.0 --measure 5.0
```

This mode is intended for server-only profiler runs, for example attaching `perf` to the server process while the client drives load.

## JSON Output

The harness prints one JSON object per measured sample:

```json
{"endpoint":"opc.tcp://127.0.0.1:4840","op":"read","node":"ns=2;i=1000","warmup_ok":100,"warmup_bad":0,"ok":1000,"bad":0,"seconds":5.0,"ops_per_sec":200.0,"first_bad":"0x00000000"}
```

The command exits nonzero if setup fails, the endpoint cannot be reached, or any warmup or measured operation fails.

## Artifact Policy

Do not commit generated profiler output. Keep `perf.data*`, flamegraphs, and local run logs out of git.
