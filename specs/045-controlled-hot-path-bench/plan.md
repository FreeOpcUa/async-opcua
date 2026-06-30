# Implementation Plan: Controlled Hot Path Benchmark Harness

**Branch**: `245-controlled-hot-path-bench` | **Date**: 2026-06-30 | **Spec**: [spec.md](./spec.md)
**Input**: Feature specification from `/specs/045-controlled-hot-path-bench/spec.md`

## Summary

Add an in-repository localhost benchmark harness that can run controlled OPC UA Read and Write throughput samples against async-opcua. The harness provides one-shot `run` mode for quick local samples plus separate `server` and `client` modes for profiler workflows. It must exercise the normal OPC UA Attribute Service Set Read and Write paths, emit stable JSON sample output, clean up internally started servers, and keep generated perf artifacts out of git.

## Technical Context

**Language/Version**: Rust 1.75+ workspace  
**Primary Dependencies**: Existing workspace crates; `async-opcua` facade crate with client/server features, `tokio`, `async-trait`, `serde`, `serde_json`; no new third-party dependency required  
**Storage**: N/A; generated benchmark/profiler artifacts remain outside committed source  
**Testing**: TDD with a missing package/CLI RED check, then targeted `cargo run` smoke samples; `cargo fmt --check`; package build/test where applicable  
**Target Platform**: Linux developer and CI runners; localhost TCP endpoint  
**Project Type**: Rust workspace library plus internal benchmark CLI tool  
**Performance Goals**: Produce repeatable Read/Write throughput samples and profiler-compatible server process; no hard throughput gate until baseline history exists  
**Constraints**: Must use normal OPC UA service behavior; must not bypass session/transport/server dispatch paths; must fail on measured service errors; must not commit bulky generated perf files  
**Scale/Scope**: One internal benchmark crate with server/client/run modes, stable JSON output, documentation, and short smoke verification

## OPC UA Standard Grounding

The protocol-facing benchmark behavior is constrained by MCP references:

- **OPC-10000-4 4.1**: The Attribute Service Set allows clients to read and write Attributes of Nodes, including Variable values. The harness must measure that public service path, not a private shortcut.
- **OPC-10000-4 5.11.2.1 and 5.11.2.2**: The Read Service reads one or more Attributes of one or more Nodes, with `nodesToRead` identifying requested Nodes and Attributes. Read samples must send real Read requests against the benchmark value node.
- **OPC-10000-4 5.11.4.1 and 5.11.4.2**: The Write Service writes values to one or more Attributes of one or more Nodes and returns after writing or determining the value cannot be written. Write samples must send real Write requests and count non-Good status results as failures.
- **OPC-10000-4 6.5.8**: Servers that support auditing may generate audit entries for Write failures. The benchmark must not bypass the server write service path or audit-relevant behavior.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

- **Correctness Over Completion**: Pass. The harness fails on setup, transport, or service-result errors and reports failure counts explicitly.
- **Do It Right Once**: Pass. The tool is an in-repo controlled harness with documented modes, not an untracked scratch script.
- **Individual Task Discipline**: Pass. Tasks will separate crate setup, server mode, client measurement, run orchestration, documentation, and verification.
- **Security Is Paramount**: Pass. The harness uses localhost SecurityPolicy None only for performance measurement and does not weaken library defaults or production paths.
- **Leave It Better Than You Found It**: Pass. Generated artifacts stay out of source; the active plan pointer is updated so future sessions land in the right context.

## Project Structure

### Documentation (this feature)

```text
specs/045-controlled-hot-path-bench/
|-- spec.md
|-- plan.md
|-- research.md
|-- data-model.md
|-- quickstart.md
|-- contracts/
|   `-- cli-contract.md
|-- checklists/
|   `-- requirements.md
`-- tasks.md
```

### Source Code (repository root)

```text
tools/opcua-localhost-bench/
|-- Cargo.toml
`-- src/
    `-- main.rs

Cargo.toml          # workspace member list
AGENTS.md           # active plan pointer
.gitignore          # generated benchmark/profiler artifact patterns if needed
```

**Structure Decision**: Add a dedicated internal tool under `tools/opcua-localhost-bench` instead of putting benchmark code in `samples/` or a library crate. This keeps benchmark dependencies and command behavior isolated while allowing normal workspace builds and `cargo run -p async-opcua-localhost-bench`.

## Phase 0 Research Summary

Research is captured in [research.md](./research.md). Key decisions:

- Use a controlled Rust workspace tool for the first in-repo harness.
- Provide `run`, `server`, and `client` modes so quick samples and profiler workflows share one implementation.
- Emit one JSON object per measured sample with stable fields and nonzero process exit on measured failures.
- Use a deterministic writable `Int32` value node under a benchmark namespace.
- Do not enforce throughput thresholds in CI until baseline history exists.

## Phase 1 Design Summary

Design artifacts:

- [data-model.md](./data-model.md) defines benchmark configuration, operation, target node, sample, and process lifecycle entities.
- [contracts/cli-contract.md](./contracts/cli-contract.md) defines command shapes and JSON output fields.
- [quickstart.md](./quickstart.md) documents short local samples, standalone server/client profiling, and verification commands.

## Complexity Tracking

| Violation | Why Needed | Simpler Alternative Rejected Because |
|-----------|------------|-------------------------------------|
| None | N/A | N/A |
