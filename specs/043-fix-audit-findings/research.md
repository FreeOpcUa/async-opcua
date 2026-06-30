# Research: Audit Findings Remediation

## Decision 1: Generate tasks as atomic, spec-cited remediation units

**Decision**: Each future task will close one finding, or one tightly coupled group of assertions on
the same code path, and will cite the OPC UA MCP section it implements.

**Rationale**: The constitution requires individual task discipline, and the user explicitly asked
for tasks to be atomic, OPC UA grounded, and well ordered. A spec citation on every task prevents
"fix by intuition" and gives reviewers a concrete conformance rule to check.

**Alternatives considered**:

- Group by crate. Rejected because crate-scoped batches hide which finding regressed.
- Group by audit source. Rejected because multiple agents found overlapping rules, and source-based
  grouping would duplicate or reorder the same protocol behavior.

## Decision 2: Sequence identity and session trust boundaries first

**Decision**: Start with ActivateSession and identity-token trust boundaries before certificate/GDS
and protocol-surface work.

**Rationale**: OPC-10000-4 5.7.3 defines ActivateSession behavior and service results, including
re-association with SecureChannels and user identity token handling. OPC-10000-4 6.1.8 defines
CreateSession/ActivateSession signature inputs including the channel thumbprint. OPC-10000-4 7.40
and 7.41 define user identity tokens, token protection, and X.509 token signature requirements.
These are direct authentication and credential-confidentiality surfaces.

**Alternatives considered**:

- Fix broad protocol malformed-input cases first. Rejected because those are important but do not
  protect credential and session authority as directly as session activation.
- Finish all certificate-store changes first. Rejected because the session boundary decides whether
  certificate and user-authentication work should happen at all.

## Decision 3: Preserve precise identity and certificate statuses

**Decision**: Tests must assert the externally visible status that corresponds to the rule being
violated, distinguishing identity-token invalid/rejected, user-signature invalid, user access denied,
and certificate-specific failures.

**Rationale**: OPC-10000-4 5.7.3.3 lists ActivateSession-specific service results, while
OPC-10000-4 7.38.2 defines common status meanings such as valid-but-rejected identity token versus
invalid token. OPC-10000-4 6.1.3 maps certificate validation checks to certificate-specific statuses
and audit event types. Returning a generic status hides remediation guidance and can mask a
different trust-boundary bug.

**Alternatives considered**:

- Accept generic `BadSecurityChecksFailed` for all security failures. Rejected because certificate
  validation and identity-token failures have more precise public contracts in the spec.
- Assert only failure severity. Rejected because it would not protect interop or operator
  diagnostics.

## Decision 4: Treat certificate and GDS work as trust-material transactions

**Decision**: Certificate-validation and GDS certificate-management tasks will prove both the status
result and preservation of trust material when an operation fails.

**Rationale**: OPC-10000-4 6.1.3 defines certificate validation steps and suppressed-error audit
requirements. OPC-10000-5 6.4.15 and the inherited audit certificate event semantics require
certificate audit source naming and certificate context. OPC-10000-12 7.4 requires push management
to use encrypted channels and SecurityAdmin access; OPC-10000-12 7.8.3.2, 7.10.5, and 7.10.10 tie
rejected-list access, certificate update, and signing-request methods to SecurityAdmin and protected
channels.

**Alternatives considered**:

- Validate only returned status codes. Rejected because a failed certificate replacement that
  changes files or registry state is still a security bug.
- Fold all GDS methods into one implementation task. Rejected because authorization, input
  validation, and atomic replacement have different failure modes and test fixtures.

## Decision 5: Treat transport, encoding, and PubSub malformed inputs as state-preservation rules

**Decision**: Malformed binary transport, encoding, XML, history, PubSub, and SKS tasks must assert
bounded failure and no unintended state update.

**Rationale**: OPC-10000-6 6.7.2 through 6.7.7 describe secure-conversation message headers,
abort chunks, sequence verification, and channel-closing behavior on unrecoverable message security
errors. OPC-10000-6 7.1.2 through 7.1.5 describe TCP message headers, max message/chunk limits,
Error messages, and connection-level error handling. OPC-10000-6 5.1.8, 5.1.9, and DiagnosticInfo
sections call out recursion risks that decoders must bound. OPC-10000-14 7.2.4.4.2 defines UADP
NetworkMessage header/security layout; 7.2.4.4.3.2 defines AES-CTR nonce length; 8.3.2 defines SKS
GetSecurityKeys starting-token behavior.

**Alternatives considered**:

- Check only returned errors for malformed messages. Rejected because the audit findings include
  state corruption, subscriber updates, and allocation/resource risks.
- Use only fuzzing. Rejected because fuzzing is useful later but does not prove exact OPC UA
  statuses and side effects.

## Decision 6: Keep implementation inside existing owners

**Decision**: Use the current crate/module boundaries for each fix: server session/auth/GDS for
service behavior, crypto for certificate validation/status mapping, core comms/types for binary
transport and encoding, pubsub for UADP/SKS, XML/history crates for local parsing/storage failures.

**Rationale**: The current workspace already separates ownership by protocol surface. Keeping fixes
within those boundaries avoids broad refactors and makes each task independently reviewable.

**Alternatives considered**:

- Add a central "audit remediation" crate or helper layer. Rejected because it would obscure the
  real trust boundary and create a new abstraction without reducing complexity.
- Rewrite service dispatch or transport before fixing findings. Rejected because the spec requires
  precise behavior on existing surfaces, not architecture churn.

## Decision 7: Verification is layered and task-local

**Decision**: Each task gets one fastest targeted command; feature completion requires the relevant
package suites plus fmt and workspace clippy.

**Rationale**: Atomic tasks need fast feedback, but this feature touches shared authentication,
crypto, transport, PubSub, and encoding contracts. Local verification catches the intended
regression, and full verification catches cross-crate regressions before completion.

**Alternatives considered**:

- Run only the full workspace suite after all fixes. Rejected because failures would be hard to map
  back to one task.
- Run only targeted tests. Rejected because shared protocol code has broad downstream effects.
