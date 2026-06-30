# Data Model: Audit Findings Remediation

## Entity: AuditFinding

Represents a security, conformance, code-review, or negative-path testing gap selected for
remediation.

Fields:

- `id`: Stable finding or task identifier.
- `priority`: P0/P1/P2/P3 ordering used for planning.
- `source`: Audit pass or review that produced the finding.
- `normative_rule`: OPC UA part/section/table or explicit regression expectation.
- `affected_surface`: Session, identity token, certificate, GDS, transport, PubSub, SKS, XML,
  history, or encoding.
- `expected_status`: Public OPC UA status expected for the negative path.
- `side_effect_expectation`: State that must remain unchanged or must be updated atomically.

Validation rules:

- A finding cannot be marked remediated without at least one passing negative-path test.
- A finding cannot be implemented without an OPC UA MCP reference unless it is explicitly a
  code-review-only regression or local invariant.
- P0/P1 findings must be planned before lower-priority findings unless an implementation dependency
  is documented.

## Entity: NormativeSpecRule

Represents the OPC UA rule used to ground a remediation.

Fields:

- `document`: OPC UA document identifier such as `OPC-10000-4`.
- `section`: Section, table, or method clause used as authority.
- `rule_summary`: Short behavior statement used by a test and reviewer.
- `status_codes`: Relevant public status codes, if the rule defines any.
- `state_requirement`: Channel, session, certificate, subscriber, store, or decoder state required
  after success or failure.

Validation rules:

- The rule summary must be derived from the MCP reference before implementation starts.
- Status-code assertions must use the most precise status exposed by the referenced rule.
- If multiple rules conflict, the task must stop for research before code changes.

## Entity: NegativePathTest

Represents the failing-first test that proves a finding.

Fields:

- `name`: Test name or planned test name.
- `layer`: Unit, package integration, workspace integration, or interop.
- `input_shape`: Malformed, unauthorized, mismatched, expired, unsupported, excessive, or corrupt
  input being exercised.
- `expected_status`: Required OPC UA status or local error.
- `state_assertion`: Session, identity, audit, certificate, subscriber, channel, storage, or decoder
  state that must be checked after failure.
- `verification_command`: Fastest targeted command that should pass when the task is complete.

Validation rules:

- The test is written or updated before production behavior changes.
- The test must fail for the current defect unless the task is a not-a-bug proof.
- The test must assert side effects, not just failure severity, for security and stateful protocol
  paths.

## Entity: RemediationTask

Represents one future `/speckit-tasks` item.

Fields:

- `finding`: The single `AuditFinding` or tightly coupled finding group.
- `spec_rule`: The `NormativeSpecRule` grounding the change.
- `test`: The `NegativePathTest` that drives the task.
- `implementation_owner`: Existing module or crate expected to own the behavior.
- `done_command`: Targeted verification command.
- `full_gate`: Broader command set required before feature completion.

Validation rules:

- One remediation task changes one behavior boundary.
- A task may combine assertions only if they share the same owner, status rule, and code path.
- A task is complete only after its `done_command` passes and no broader regression is known.

## Entity: TrustBoundary

Represents the point where untrusted input becomes authority, state, or trust material.

Fields:

- `boundary_type`: Session/channel, identity credential, certificate chain, GDS method, message
  chunk, PubSub subscriber, SKS key set, XML import, history store, or encoding helper.
- `preconditions`: Checks that must succeed before state changes.
- `failure_status`: Status returned when preconditions fail.
- `protected_state`: State that must not change on failure.

Validation rules:

- User authentication, certificate validation, and audit side effects cannot occur before the
  correct session/channel precondition.
- Certificate and key replacement must be all-or-nothing.
- PubSub subscriber state cannot update until a full message is validated.
- Decoders must bound recursion, lengths, and allocation before consuming attacker-controlled data.

## Entity: CertificateMaterial

Represents certificate and key material involved in trust decisions or replacement operations.

Fields:

- `certificate`: Application certificate, user identity certificate, issuer certificate, or rejected
  certificate bytes.
- `private_key`: Existing or replacement private key material.
- `trust_store_location`: Trusted, issuer, rejected, CRL, or generated credential location.
- `validation_status`: Certificate-specific status or success.
- `audit_context`: Certificate bytes and status safe to expose in audit events.

Validation rules:

- Private keys and decrypted credentials must never be logged or emitted in audit events.
- Rejected, expired, revoked, weak, wrong-usage, path-length-invalid, and policy-invalid
  certificates must map to certificate-specific statuses where the spec defines them.
- Failed replacement cannot leave mismatched old/new certificate-key pairs.

## Entity: AuditEvent

Represents a security-relevant OPC UA event produced by a covered failure or suppressed finding.

Fields:

- `event_type`: OPC UA audit event type or subtype.
- `source_name`: Spec-defined event source name.
- `status`: Status associated with the audited operation.
- `certificate`: Subject certificate bytes when the event type exposes certificate context.
- `session_context`: Session, channel, or method context available at emission time.

Validation rules:

- Certificate events must use the certificate audit event shape and source name required by OPC UA.
- Suppressed certificate findings that still allow success must remain auditable.
- Events must not include raw passwords, private keys, decrypted issued tokens, or raw signatures.

## Entity: ProtocolMessage

Represents an input message or encoded value that can be malformed or adversarial.

Fields:

- `surface`: Binary transport, service dispatch, PubSub UADP, SKS, XML, history storage, or
  encoding helper.
- `declared_limits`: Message size, chunk count, sequence number, nonce length, field count,
  recursion depth, or configured storage limit.
- `payload`: Input bytes, typed request, UADP message, XML document, database row, or encoded value.
- `expected_failure`: Status, local error, or graceful connection close behavior.
- `state_after_failure`: Channel, pending chunks, subscriber targets, key set, imported nodes, or
  history rows after rejection.

Validation rules:

- Declared sizes and counts must be validated before allocation or state update.
- Unknown service or future request handling must follow the OPC UA status and channel-liveness
  rule for that surface.
- A failed decode or import cannot silently discard the error.

## State Transitions

```text
Audit finding selected
  -> MCP rule confirmed
       -> Negative-path test written
            -> Test fails for current behavior
                 -> Minimal implementation change
                      -> Targeted command passes
                           -> Finding marked remediated
            -> Test unexpectedly passes
                 -> Reclassify as not-a-bug or refine finding before code changes
  -> MCP rule unclear or conflicts
       -> Stop for research; do not implement
```

```text
Untrusted input received
  -> Precondition fails
       -> Return precise status
       -> Preserve protected state
       -> Emit audit event only when spec requires and context is valid
  -> Preconditions pass
       -> Update state atomically
       -> Continue protocol flow
```
