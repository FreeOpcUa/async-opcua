# Data Model: Minimal Deployment Footprint

## FacadeFeatureSet

Represents the public umbrella crate features that decide which modules are exported and which workspace crates are enabled.

Fields:

- `base_server_enabled`: exposes the server SDK without the generated core namespace.
- `server_enabled`: exposes the default server SDK with the generated core namespace.
- `generated_address_space_enabled`: includes the generated OPC UA core namespace.

Validation:

- `base_server_enabled` must make the public server API importable.
- `server_enabled` must continue to imply `generated_address_space_enabled`.
- `base_server_enabled` alone must not imply `generated_address_space_enabled`.

## MinimalServerSample

Represents the sample executable that proves the minimal facade path is usable.

Fields:

- `crate_name`: workspace package name for the sample.
- `facade_features`: umbrella crate features used by the sample.
- `runtime_mode`: single-threaded or otherwise minimal runtime selection.
- `endpoint_behavior`: anonymous local server behavior suitable for build/run smoke tests.

Validation:

- Must depend on the umbrella crate with default features disabled.
- Must compile under release and embedded profiles.
- Must not require generated address-space nodes or local certificate files.

## FootprintBuildCheck

Represents the local and CI validation path for minimal builds.

Fields:

- `build_profile`: release or embedded.
- `package`: sample package being built.
- `dependency_tree_check`: generated namespace absent or present.
- `binary_size_report`: produced executable size in bytes.

Validation:

- Embedded build must succeed in CI.
- Dependency tree check must fail if generated namespace appears on normal dependencies.
- Size report must be informational and not dependent on non-standard tooling.

## FootprintReport

Represents the CI-visible output reviewers use to spot large footprint changes.

Fields:

- `binary_path`: produced executable location.
- `bytes`: exact byte count when available.
- `human_size`: human-readable size when available.
- `profile`: build profile used.

Validation:

- Must be emitted after a successful build.
- Must not hide build failures.
