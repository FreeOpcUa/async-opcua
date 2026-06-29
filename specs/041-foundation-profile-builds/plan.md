# Implementation Plan: OPC Foundation Profile Benchmark Builds

**Branch**: `041-foundation-profile-builds` | **Date**: 2026-06-29 | **Spec**: [spec.md](./spec.md)
**Input**: Feature specification from `/specs/041-foundation-profile-builds/spec.md`

## Summary

Add CI-visible OPC Foundation Nano, Micro, and Embedded server profile benchmark variants. The implementation keeps these variants as benchmark configurations: each selects one target Foundation profile URI for reporting, uses the smallest existing `base-server` surface, rejects accidental generated namespace dependencies, reports embedded-profile binary sizes, and documents that the builds are not conformance claims.

## Technical Context

**Language/Version**: Rust 2021, latest stable toolchain  
**Primary Dependencies**: Existing `async-opcua` workspace crates, Tokio for the sample runtime  
**Storage**: N/A  
**Testing**: `cargo test`, `cargo build`, `cargo tree`, `cargo fmt`, `cargo clippy`  
**Target Platform**: Linux developer hosts and GitHub Actions Linux runners; embedded Linux as deployment target  
**Project Type**: Rust workspace library plus sample binaries and reusable GitHub Actions workflow  
**Performance Goals**: Profile benchmark binaries build under the existing `embedded` profile and report byte sizes for review visibility  
**Constraints**: Do not require OPC Foundation certification tools in CI; benchmark builds must not advertise Foundation profile conformance; benchmark builds must omit generated core namespace dependencies; keep the existing `samples/minimal-server` footprint guard  
**Scale/Scope**: Three benchmark variants: Nano 2017, Micro 2017, Embedded 2017

## Constitution Check

- **Correctness over completion**: Pass. The plan avoids advertising profile conformance without conformance-unit proof.
- **Do it right once**: Pass. Benchmark builds measure feature footprint and dependency boundaries instead of adding a runtime profile-claim API.
- **Individual task discipline**: Pass. Tasks are single-line, independently verifiable units.
- **Security is paramount**: Pass. Embedded benchmark keeps explicit crypto feature selection; no parser/crypto downgrade or profile overclaim.
- **Leave it better**: Pass. Existing footprint CI grows into a clearer profile benchmark matrix without dropping minimal-footprint coverage.

## Project Structure

### Documentation (this feature)

```text
specs/041-foundation-profile-builds/
├── plan.md
├── research.md
├── data-model.md
├── quickstart.md
├── contracts/
│   └── foundation-profile-builds.md
└── tasks.md
```

### Source Code

```text
samples/foundation-profile-server/
├── Cargo.toml             # mutually exclusive nano/micro/embedded benchmark features
└── src/main.rs            # selected profile benchmark server sample

.github/workflows/
├── ci_footprint.yml       # adds profile benchmark matrix
└── main.yml               # already invokes footprint workflow

docs/setup.md              # benchmark commands and scope
docs/opc_ua_overview.md    # profile/conformance distinction
async-opcua/README.md      # sample listing
```

**Structure Decision**: Extend the existing sample/workflow structure. Keep profile benchmarks separate from `samples/minimal-server` because they encode named Foundation profile benchmark tiers, but use the same `base-server` dependency principle so benchmark rows measure the library surface an integrator actually selects.

## Complexity Tracking

No constitution violations or justified complexity exceptions.

## Phase 0: Research

See [research.md](./research.md).

## Phase 1: Design & Contracts

See [data-model.md](./data-model.md), [contracts/foundation-profile-builds.md](./contracts/foundation-profile-builds.md), and [quickstart.md](./quickstart.md).

## Post-Design Constitution Check

- **Correctness over completion**: Pass. Tests and dependency-tree checks cover selected benchmark targets without turning target URIs into conformance claims.
- **Do it right once**: Pass. Build selection is compile-time exclusive, preventing ambiguous benchmark binaries.
- **Individual task discipline**: Pass. Implementation tasks remain ordered and independently verifiable.
- **Security is paramount**: Pass. No parser/crypto downgrade; Embedded benchmark explicitly opts into the constant-time crypto backend.
- **Leave it better**: Pass. Documentation clarifies benchmark scope, generated namespace boundaries, and certification boundaries.
