# Data Model: External Implementation Interop Checks

## ExternalTarget

Represents an already-running OPC UA server outside the async-opcua demo-server process.

Fields:

- `endpoint_url`: OPC UA endpoint URL supplied by the caller.
- `availability`: reachable, unreachable, or timed out.
- `advertised_endpoints`: endpoint descriptions returned by discovery.

Validation:

- `endpoint_url` must be present for external mode.
- The target repository is never used as a writable data source.

## PortableProfile

Represents the bounded set of standard checks that external implementations must satisfy.

Fields:

- `discovery_checks`: FindServers and GetEndpoints coverage where supported by the client.
- `session_checks`: anonymous session activation.
- `read_checks`: standard ServerStatus/NamespaceArray reads.
- `browse_checks`: Objects folder browse.
- `error_checks`: unknown-node status result.

Validation:

- The profile must not require demo namespace nodes.
- The profile must not require credentials.

## ClientImplementation

Represents an independent OPC UA client stack used by the harness.

Fields:

- `name`: human-readable client stack label.
- `profile`: demo-server or portable.
- `security_selection`: none, best, auto, or anonymous default depending on client capabilities.
- `result`: aggregate InteropResult.

Validation:

- Demo profile may require async-opcua-specific nodes.
- Portable profile must use only PortableProfile checks.

## WorkflowInvocation

Represents a local or CI run of the interop harness.

Fields:

- `external_endpoint`: optional endpoint supplied by input or environment.
- `mode`: demo-only or demo-plus-external.
- `client_implementations`: ordered list of clients to run.

State transitions:

- No endpoint -> demo-only.
- Endpoint present -> demo checks plus external portable checks.
- External check failure -> failed invocation.

## InteropResult

Represents one named check result and the aggregate result returned by a client harness.

Fields:

- `check_name`: stable description of the behavior under test.
- `status`: pass or fail.
- `detail`: optional diagnostic text.
- `exit_status`: zero when all checks pass, non-zero when any check fails.

Validation:

- Every failed required check must produce a name and diagnostic detail.
- Aggregate exit status must match the failure count.
