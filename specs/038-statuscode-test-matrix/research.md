# Research: StatusCode Conformance Test Matrix

## Decision: Scope Only Implemented Standard Behavior

**Decision**: The matrix includes implemented async-opcua surfaces across OPC UA Parts 2, 3, 4, 5, 6, 8, 9, 11, 12, 13, 14, 18, 80, 81, and 83. It excludes unimplemented standard features and generated-only StatusCode constants.

**Rationale**: The user asked to test what has been implemented. Generating tests for unimplemented surfaces would mix conformance backlog work with test coverage work and would make every task larger than one test.

**Alternatives considered**:

- Cover every `StatusCode::*` symbol in `async-opcua-types`: rejected because generated constants are not behavior paths.
- Cover every production reference occurrence: rejected because many occurrences are internal mapping/retry helpers or environmental failures better covered by one representative path.

## Decision: Use Five Coverage Classifications

**Decision**: Classify each row as `covered`, `tasked`, `environmental`, `generated-only`, or `unimplemented`.

**Rationale**: This avoids duplicate tests and prevents flaky tests for host/network/third-party conditions that cannot be provoked deterministically.

**Alternatives considered**:

- Binary covered/uncovered classification: rejected because it cannot distinguish deterministic gaps from CTT-only or host-environment gaps.

## Decision: One Task Equals One Test Function

**Decision**: Every task in `tasks.md` must name exactly one test function and one file. If a production fix is needed, it stays scoped to making that one test pass.

**Rationale**: Atomic tests make review and CI failures easier to understand. This also matches the user's requirement that each task implement one test.

**Alternatives considered**:

- One task per StatusCode family: rejected because grouped tests hide which exact standard path is covered.
- One task per crate: rejected because each crate spans multiple services and status semantics.

## Decision: Cite Official Sections at Task Level

**Decision**: Every task cites an OPC UA Part and section. MCP-confirmed anchors include:

- OPC-10000-4 7.38.2 Common StatusCodes.
- OPC-10000-4 5.8.2.4 AddNodes StatusCodes.
- OPC-10000-4 5.12.2.4 Call StatusCodes.
- OPC-10000-4 5.5.5.3 RegisterServer Service Results.
- OPC-10000-6 5.4.2.3 JSON Int64/UInt64 integer encoding.
- OPC-10000-6 5.4.2.17 JSON Variant object definition.
- OPC-10000-8 7.2 PercentDeadband.
- OPC-10000-11 6.2.2 Historical Access operation result codes.
- OPC-10000-13 5.3.2 aggregate operation result codes.
- OPC-10000-14 7.2.4.4.2 UADP NetworkMessage layout.
- OPC-10000-14 7.2.4.4.3.2 AES-CTR security nonce behavior.
- OPC-10000-3 5.2.1 and 5.9 RolePermissions/UserRolePermissions/AccessRestrictions attributes.
- OPC-10000-5 6.3.2 ServerCapabilitiesType.
- OPC-10000-9 5.7.2 AcknowledgeableConditionType.
- OPC-10000-81/83 FX/AC nodeset grounding for `EstablishConnections` (FX/AC NodeId i=292), `VerifyAssetCmd`, and `VerifyFunctionalEntityCmd` from the repository's generated FX/AC nodeset artifacts.

**Rationale**: Section-level references let implementers verify expected behavior from the standard, not from local assumptions.

**Alternatives considered**:

- Cite only local audit IDs: rejected because audit IDs are useful provenance but not normative. FX rows use official generated nodeset names/NodeIds because MCP text indexing did not expose section snippets for Parts 80/81/83.

## Decision: Prefer Existing Test Files

**Decision**: Tasks target existing test files unless a new file is clearly more focused.

**Rationale**: Existing fixtures already start servers, create sessions, bind AddressSpaces, and exercise crate internals. Reusing them keeps each test task small.

**Alternatives considered**:

- Create a new status-code mega-suite: rejected because it would centralize unrelated fixtures and make parallel test ownership worse.
