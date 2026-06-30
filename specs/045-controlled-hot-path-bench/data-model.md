# Data Model: Controlled Hot Path Benchmark Harness

## BenchmarkOperation

Represents the OPC UA service operation being measured.

- Values: `read`, `write`
- Validation: any other value is rejected before connecting to a server.

## BenchmarkTarget

Represents the endpoint and node selected for a sample.

- `endpoint`: OPC UA endpoint URL.
- `namespace_index`: numeric namespace index used in the request NodeId.
- `node_id`: numeric NodeId identifier.
- `attribute`: Value Attribute for the initial harness.
- Validation: endpoint must be non-empty; namespace index and node id must parse as unsigned integers.

## BenchmarkTiming

Represents the sample timing configuration.

- `warmup_seconds`: duration used for unmeasured warmup operations.
- `measure_seconds`: duration used for measured operations.
- Validation: warmup must be non-negative; measurement must be positive.

## BenchmarkSample

Represents the result of one measured run.

- `endpoint`: endpoint used by the client.
- `op`: operation measured.
- `node`: human-readable node identifier.
- `warmup_ok`: successful warmup service operations.
- `warmup_bad`: failed warmup service operations.
- `ok`: successful measured service operations.
- `bad`: failed measured service operations.
- `seconds`: measured elapsed seconds.
- `ops_per_sec`: `ok / seconds`.
- `first_bad`: first failure status or error marker.

Validation rules:

- Successful command exit requires `bad == 0`, setup success, and connection success.
- `ops_per_sec` is zero only when no operation succeeded or elapsed time is invalid.

## BenchmarkMode

Represents how the harness is run.

- `run`: starts an internal server, waits for readiness, runs one client sample, and shuts down.
- `server`: starts only the benchmark server and waits for shutdown.
- `client`: runs one sample against an already running endpoint.

## BenchmarkServerLifecycle

Represents internal server ownership for one-shot mode.

- States: `not_started`, `starting`, `ready`, `stopping`, `stopped`, `failed`.
- Validation: one-shot mode must not begin measuring before readiness; all terminal paths must request shutdown for internally started servers.
