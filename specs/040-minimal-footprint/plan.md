# Implementation Plan: Minimal Deployment Footprint

**Branch**: `040-minimal-footprint` | **Date**: 2026-06-29 | **Spec**: [spec.md](./spec.md)  
**Input**: Feature specification from `/specs/040-minimal-footprint/spec.md`

## Summary

Make the documented `base-server` footprint path usable through the public umbrella crate, prove it with a tiny minimal-server sample, and add a CI footprint build that compiles the sample under the existing embedded profile while reporting binary size. The full `server` feature remains unchanged and continues to include the generated OPC UA core namespace.

## Technical Context

**Language/Version**: Rust 1.75+; GitHub Actions YAML for CI  
**Primary Dependencies**: Existing workspace crates; no new runtime dependencies planned  
**Storage**: N/A  
**Testing**: `cargo check/build`, `cargo tree`, `cargo clippy`, embedded-profile build, CI workflow syntax review  
**Target Platform**: Linux developer hosts and GitHub Actions Linux runners; embedded Linux as the deployment target  
**Project Type**: Rust workspace with sample binaries and reusable CI workflows  
**Performance Goals**: Minimal embedded-profile server binary remains materially smaller than the full simple-server baseline; CI reports the size for review visibility  
**Constraints**: Preserve full server generated-namespace behavior; do not weaken security defaults for existing features; avoid new dependencies; keep the footprint path explicit about compliance tradeoffs  
**Scale/Scope**: One umbrella facade feature correction, one minimal sample crate, one CI footprint build path, docs and verification commands

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

- **Correctness over completion**: Pass. The feature is verified by compiling the actual minimal sample and inspecting its dependency graph, not by documentation alone.
- **Do it right once**: Pass. The fix addresses the facade feature boundary directly rather than recommending consumers bypass the umbrella crate.
- **Individual task discipline**: Pass. Tasks are split into one feature-gate correction, one sample, one CI path, documentation, and validation.
- **Security paramount**: Pass. Existing full server and crypto defaults are preserved; the minimal path changes footprint exposure only and documents compliance limitations.
- **Leave it better than you found it**: Pass. The touched docs and CI make the footprint path discoverable and regression-tested.

## Project Structure

### Documentation (this feature)

```text
specs/040-minimal-footprint/
├── spec.md
├── plan.md
├── research.md
├── data-model.md
├── quickstart.md
├── checklists/
│   └── requirements.md
├── contracts/
│   └── minimal-footprint.md
└── tasks.md
```

### Source Code (repository root)

```text
.github/workflows/
├── main.yml
└── ci_footprint.yml

async-opcua/
├── Cargo.toml
└── src/lib.rs

samples/minimal-server/
├── Cargo.toml
└── src/main.rs

docs/
└── setup.md

AGENTS.md
```

**Structure Decision**: Keep the implementation inside the existing workspace and umbrella crate. Add a sample crate under `samples/` so the workspace glob and normal CI can build it. Add a small reusable footprint workflow and call it from `main.yml`, matching the repository's existing CI decomposition.

## Phase 0 Research Summary

Research is captured in [research.md](./research.md). Key decisions:

- Re-export server-facing facade items for `base-server` without changing the semantics of the full `server` feature.
- Use a minimal anonymous server sample that proves the facade path compiles without generated namespace code.
- Add a CI build-and-report guard rather than a hard size threshold in the first increment.
- Keep deeper crypto/auth feature splitting as future work after this small facade/CI slice lands.

## Phase 1 Design Summary

Design artifacts:

- [data-model.md](./data-model.md) defines FacadeFeatureSet, MinimalServerSample, FootprintBuildCheck, and FootprintReport.
- [contracts/minimal-footprint.md](./contracts/minimal-footprint.md) defines local commands and CI behavior.
- [quickstart.md](./quickstart.md) describes local validation and expected outputs.

## Complexity Tracking

No constitution violations to track.
