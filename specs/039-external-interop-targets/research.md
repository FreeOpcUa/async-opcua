# Research: External Implementation Interop Checks

## Decision: Portable profile uses standard OPC UA behavior only

**Rationale**: External implementations should not need the async-opcua demo namespace to get a useful smoke result. The portable profile requires endpoint discovery, anonymous session activation, reads of standard ServerStatus nodes, browsing Objects, and an unknown-node status path.

**Alternatives considered**:

- Reuse the full demo-server suite against external servers. Rejected because it requires demo-specific nodes, methods, writable variables, subscriptions, and history.
- Add implementation-specific adapters per target repository. Rejected because it would couple async-opcua to external source trees and violate the no-edit constraint.

## Decision: External checks are opt-in in CI

**Rationale**: Pull request CI for async-opcua must remain deterministic and self-contained. A live external endpoint is inherently environmental, so the reusable workflow accepts an optional endpoint and skips external checks when it is absent.

**Alternatives considered**:

- Always require an external server in PR CI. Rejected because it would make normal async-opcua CI dependent on another project's availability.
- Build known external projects directly inside async-opcua CI. Rejected for this feature because target build orchestration should live outside the reusable harness boundary.

## Decision: .NET covers endpoint-policy selection; asyncua adds a second anonymous portable client

**Rationale**: The OPC Foundation .NET stack already supports certificate-backed endpoint selection and is the strongest available reference client. asyncua is a lightweight independent stack and is useful as a second implementation signal for anonymous portable behavior.

**Alternatives considered**:

- Implement full security-policy selection in both clients. Rejected for this increment because it would add certificate-management complexity without changing the portable profile itself.
- Only provide .NET external checks. Rejected because the user goal is interop signal, and a second client stack catches client/server assumptions that a single client can miss.

## Decision: Do not manage external target repositories

**Rationale**: The harness should be reusable by any project that can expose an OPC UA endpoint. Building and launching the external server belongs to the caller or that project's CI.

**Alternatives considered**:

- Clone/build micro-opcua from this repository. Rejected because it hard-codes one external project and risks writing into that repository.
- Add generated target-specific configuration files. Rejected because the portable profile should need only an endpoint URL.
