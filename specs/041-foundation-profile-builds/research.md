# Research: OPC Foundation Profile Benchmark Builds

## Decision: Treat profile builds as benchmark configurations, not conformance claims

**Rationale**: OPC UA Part 7 describes profiles as named aggregations of ConformanceUnits, and profile conformance requires all mandatory ConformanceUnits in the profile to pass their tests. A size benchmark cannot prove that by selecting a package. The benchmark should target a profile-oriented service surface and report size, while leaving `ServerCapabilities.ServerProfileArray` empty unless a later conformance-validating path populates it.

**Alternatives considered**:
- Advertise the selected profile URI from the sample. Rejected because it would overclaim conformance.
- Skip Foundation profile names entirely. Rejected because the user asked for Nano, Micro, and Embedded profile benchmark sizes.

## Decision: Target the 2017 Nano, Micro, and Embedded server profile URI family first

**Rationale**: The repository already uses CTT-oriented language and existing documentation names Nano, Micro, Embedded, and Standard in the classic server profile progression. The first useful CI slice needs stable labels for benchmark rows.

Selected target URIs:
- Nano: `http://opcfoundation.org/UA-Profile/Server/NanoEmbeddedDevice2017`
- Micro: `http://opcfoundation.org/UA-Profile/Server/MicroEmbeddedDevice2017`
- Embedded: `http://opcfoundation.org/UA-Profile/Server/EmbeddedUA2017`

**Alternatives considered**:
- Current/latest OPC Foundation profile database entries. Deferred because profile revisions have changed over time and would require a broader conformance mapping.
- Custom internal names only. Rejected because the benchmark needs to map to the Foundation profile family.

## Decision: Use the smallest existing server feature surface for benchmark rows

**Rationale**: Integrators should be able to compile only the library surface they use. Today the existing coarse boundary is `base-server` versus full `server` with `generated-address-space`. The benchmark rows must use `base-server` and CI must reject accidental generated namespace dependencies. Fine-grained service-set Cargo gates are not present yet and should be planned as a follow-up feature.

**Alternatives considered**:
- Use the full `server` feature for benchmark rows. Rejected because it measures generated namespace size, not profile-oriented library use.
- Require the generated namespace for all profile rows. Rejected because the benchmark goal is footprint measurement, not a conformance claim.

## Decision: Use separate sample packages for profile benchmarks

**Rationale**: Compile-time package selection gives CI exact build commands and prevents a binary from accidentally mixing benchmark tiers. Separate packages also remain compatible with repository-wide `cargo build --workspace --all-features`; mutually exclusive Cargo features do not.

**Alternatives considered**:
- Runtime `--profile` argument. Rejected because one binary could silently drift and CI would not prove distinct package selections.
- Mutually exclusive Cargo features in one sample crate. Rejected because workspace `--all-features` builds enable all features at once.

## Decision: Extend footprint CI with a profile benchmark matrix

**Rationale**: The existing footprint workflow already builds embedded-profile binaries and reports size. Adding a matrix keeps footprint and profile benchmark visibility in one reusable workflow.

**Alternatives considered**:
- A separate CI workflow. Rejected because it would duplicate Rust setup and size-reporting logic.
