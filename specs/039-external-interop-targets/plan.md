# Implementation Plan: External Implementation Interop Checks

**Branch**: `039-external-interop-targets` | **Date**: 2026-06-29 | **Spec**: [spec.md](./spec.md)  
**Input**: Feature specification from `/specs/039-external-interop-targets/spec.md`

## Summary

Make the demo-server interop harness reusable against an already-running external OPC UA server by adding a bounded portable profile, documenting its scope, and wiring an optional reusable CI path. The default async-opcua demo-server interop workflow remains unchanged; external checks run only when an endpoint is supplied.

## Technical Context

**Language/Version**: Rust 1.75+ for the demo server; Bash for wrappers; C#/.NET 8 for the OPC Foundation reference client; Python 3.9+ for asyncua; GitHub Actions YAML for CI  
**Primary Dependencies**: Existing workspace crates, `OPCFoundation.NetStandard.Opc.Ua.Client`, `asyncua==2.0.*`, existing GitHub Actions toolchain setup  
**Storage**: N/A; generated client PKI remains under temp or existing ignored interop directories  
**Testing**: `bash -n`, `dotnet build`, focused interop wrapper runs against the local demo server, and reusable workflow syntax review  
**Target Platform**: Linux CI runners and local Linux developer environments  
**Project Type**: Rust workspace with sample interop harnesses and reusable CI workflows  
**Performance Goals**: External smoke checks should complete in under two minutes after the target endpoint is reachable; normal CI must not wait for external infrastructure when no endpoint is supplied  
**Constraints**: Do not edit the external implementation repository; do not require credentials; use only standard nodes for the portable profile; preserve current demo-server interop behavior by default  
**Scale/Scope**: One external endpoint per workflow invocation; two independent portable client checks in this feature; full demo-server suites remain the richer async-opcua conformance signal

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

- **Correctness over completion**: Pass. The profile is intentionally bounded to portable standard behavior and fails with named checks rather than treating "connected" as sufficient.
- **Do it right once**: Pass. The external path is integrated into the existing wrappers/docs/workflow rather than added as throwaway local commands.
- **Individual task discipline**: Pass. Tasks are split into spec artifacts, one harness change, one workflow change, docs, and validation.
- **Security paramount**: Pass. The portable path requires no stored credentials, reports endpoint-policy selection, and avoids weakening the demo-server security matrix.
- **Leave it better than you found it**: Pass. The touched interop docs explain the difference between portable smoke, full demo conformance, and official certification.

## Project Structure

### Documentation (this feature)

```text
specs/039-external-interop-targets/
├── spec.md
├── plan.md
├── research.md
├── data-model.md
├── quickstart.md
├── checklists/
│   └── requirements.md
├── contracts/
│   └── external-interop.md
└── tasks.md
```

### Source Code (repository root)

```text
.github/workflows/
└── ci_interop.yml

samples/demo-server/interop/
├── README.md
├── asyncua/
│   ├── asyncua-test.py
│   ├── portable-test.py
│   └── run-asyncua.sh
└── dotnet/
    ├── Program.cs
    ├── interop.csproj
    └── run-dotnet.sh

AGENTS.md
```

**Structure Decision**: Extend the existing interop harnesses in place. The asyncua demo-specific script remains the full async-opcua demo-server test; the new portable asyncua script mirrors the portable .NET profile without depending on demo namespace nodes. The reusable CI workflow keeps the full demo-server job and adds a skipped-by-default external job.

## Phase 0 Research Summary

Research is captured in [research.md](./research.md). Key decisions:

- Define the portable profile using standard server nodes and basic service behavior only.
- Keep external live-server checks opt-in through an endpoint input or environment value.
- Use the .NET reference client for endpoint-policy selection and asyncua as a second anonymous portable client.
- Keep external target build orchestration outside async-opcua's repository.

## Phase 1 Design Summary

Design artifacts:

- [data-model.md](./data-model.md) defines ExternalTarget, PortableProfile, ClientImplementation, WorkflowInvocation, and InteropResult.
- [contracts/external-interop.md](./contracts/external-interop.md) defines CLI and workflow contracts.
- [quickstart.md](./quickstart.md) describes local and CI validation paths.

## Complexity Tracking

No constitution violations to track.
