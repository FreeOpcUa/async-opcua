# Data Model: OPC Foundation Profile Benchmark Builds

## FoundationProfileBenchmark

Represents one selected OPC Foundation server profile benchmark variant.

Fields:
- `name`: Human-readable profile key, one of `nano`, `micro`, `embedded`.
- `target_uri`: OPC Foundation profile URI used to label the benchmark target.
- `surface`: Short statement of the benchmarked service/security surface.
- `limits`: Runtime server limit tier associated with the benchmark build.
- `requires_constant_time_crypto`: Whether the build explicitly enables the default constant-time crypto backend.

Validation rules:
- Each profile benchmark package must represent one profile target.
- Each benchmark must have exactly one target URI.
- Benchmark builds must not advertise the target URI as an OPC Foundation conformance claim.
- Benchmark builds must omit generated core namespace dependencies.

## BenchmarkBuildMatrixEntry

Represents one CI row for building and reporting a benchmark binary.

Fields:
- `profile`: Profile key represented by the package.
- `package`: Workspace package name to build.
- `binary_path`: Expected embedded-profile binary path.
- `size_report`: Human-readable size line emitted in CI logs.

Validation rules:
- The matrix must contain exactly `nano`, `micro`, and `embedded`.
- Each row must build with `--profile embedded`.
- Each row must fail if the normal dependency tree includes `async-opcua-core-namespace`.
- Each row must print a size line that includes the profile key.
