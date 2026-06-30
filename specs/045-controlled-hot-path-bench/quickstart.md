# Quickstart: Controlled Hot Path Benchmark Harness

## Short One-Shot Samples

```sh
cargo run -p async-opcua-localhost-bench -- run --op read --port 4840 --warmup 0.5 --measure 2.0
cargo run -p async-opcua-localhost-bench -- run --op write --port 4840 --warmup 0.5 --measure 2.0
```

Expected result: each command prints one JSON object with `bad: 0`, `ok > 0`, and a positive `ops_per_sec`.

## Standalone Server For Profiling

Terminal 1:

```sh
cargo run --release -p async-opcua-localhost-bench -- server --port 4840
```

Terminal 2:

```sh
cargo run --release -p async-opcua-localhost-bench -- client --op read --endpoint opc.tcp://127.0.0.1:4840 --namespace 2 --node 1000 --warmup 1.0 --measure 5.0
cargo run --release -p async-opcua-localhost-bench -- client --op write --endpoint opc.tcp://127.0.0.1:4840 --namespace 2 --node 1000 --warmup 1.0 --measure 5.0
```

Attach `perf` or another profiler to the server process when server-only hotspots are needed.

## Verification Commands

```sh
cargo run -p async-opcua-localhost-bench -- --help
cargo run -p async-opcua-localhost-bench -- run --op read --port 4840 --warmup 0.1 --measure 0.2
cargo run -p async-opcua-localhost-bench -- run --op write --port 4840 --warmup 0.1 --measure 0.2
cargo fmt --check
```

## Artifact Policy

Generated `perf.data`, profiler reports, and run logs are local artifacts. Keep them outside git or under ignored paths. The recent `../scratch/opcua-localhost-bench` data is a comparison baseline, not an input required by this harness.
