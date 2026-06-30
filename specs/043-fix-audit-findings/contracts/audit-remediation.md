# Contract: Audit Findings Remediation

## Normative References

- OPC-10000-4 5.7.3: ActivateSession service behavior and service results.
- OPC-10000-4 6.1.3: certificate validation steps, certificate statuses, and audit reporting.
- OPC-10000-4 6.1.8: CreateSession/ActivateSession signature inputs including channel-bound data.
- OPC-10000-4 7.38.2: common status-code meanings.
- OPC-10000-4 7.40 and 7.41: user identity token and user token policy behavior.
- OPC-10000-5 6.4.15: AuditCertificateInvalidEventType and inherited certificate audit semantics.
- OPC-10000-12 7.4, 7.8.3.2, 7.10.5, 7.10.10: GDS push/pull management, SecurityAdmin, and
  encrypted/authenticated channel requirements.
- OPC-10000-6 5.1.8, 5.1.9, 5.2/5.3 DiagnosticInfo sections: bounded decoder recursion and
  malformed-value handling.
- OPC-10000-6 6.7.2 through 6.7.7: Secure Conversation chunk headers, abort chunks, sequence
  verification, and message-security failure behavior.
- OPC-10000-6 7.1.2 through 7.1.5: OPC UA TCP message limits, Error messages, and connection-level
  error handling.
- OPC-10000-14 7.2.4.4.2, 7.2.4.4.3.2, 8.3.2: UADP NetworkMessage security layout, nonce length,
  and SKS GetSecurityKeys behavior.

## Task Contract

Every generated implementation task must contain:

- A single finding id or a single tightly coupled rule group.
- The OPC UA document and section that grounds the expected behavior.
- The negative-path test to write first.
- The expected public status or local error.
- The state that must remain unchanged or update atomically.
- The likely module owner.
- The targeted command that proves the task is complete.

Tasks must not batch unrelated findings, even if they touch the same file.

## ActivateSession And Identity Contract

### Cross-channel session activation

Given:

- A session was created on one SecureChannel.
- Activation is attempted from a channel that does not satisfy the OPC UA channel-binding
  requirements for that session.

Expected outcome:

- Activation fails before user-token validation, user authentication, identity assignment, or
  certificate audit emission for that token.
- The failure status is the precise secure-channel/session status required by the referenced OPC UA
  rule.
- The previous session identity and monitored-item permissions remain unchanged.

### Protected username and issued tokens

Given:

- The selected endpoint or user token policy requires protected credentials.
- A username/password or issued-token credential is sent without the required token protection.

Expected outcome:

- Activation rejects the token before user authentication.
- The returned status distinguishes malformed/unprotected credentials from valid-but-denied access.
- No plaintext secret is logged, audited, stored, or exposed in diagnostics.

### X.509 user token proof

Given:

- The selected user token policy requires a channel-bound X.509 user-token signature.
- The client sends no signature, a malformed signature, or only a legacy signature form where the
  selected policy requires enhanced channel-bound proof.

Expected outcome:

- Activation fails with the user-token signature status.
- No rejected X.509 user identity or role state remains on the session.
- Valid legacy behavior remains available only where the selected policy permits it.

## Certificate And GDS Contract

### Certificate validation status and audit

Given:

- A presented application or user identity certificate fails a certificate validation step or has a
  suppressed validation finding.

Expected outcome:

- Hard failures return the certificate-specific status required by the OPC UA validation step.
- Suppressed findings remain auditable when the operation otherwise succeeds.
- Certificate audit events use the OPC UA certificate event type/source shape and include
  certificate context when available.
- Application-certificate behavior remains unchanged unless a spec-cited test explicitly changes it.

### GDS authorization

Given:

- A client without SecurityAdmin access calls rejected-list, certificate update, signing-request, or
  completion methods.

Expected outcome:

- The method is rejected before registry, trust-store, certificate, or private-key state changes.
- The returned status matches authorization or security-precondition failure rather than malformed
  input unless the spec requires otherwise.

### Certificate replacement atomicity

Given:

- A certificate replacement operation receives malformed certificate/key material or persistence
  fails partway through.

Expected outcome:

- Existing valid certificate and key material remain paired and usable.
- No partial replacement is published through server configuration or cache state.
- The failure is visible through the returned method status or operation result.

## Transport, Service Dispatch, And Encoding Contract

### Binary transport and service dispatch

Given:

- A message has an impossible declared size, oversized declared size, excessive chunk count,
  unauthenticated abort chunk, invalid sequence number, invalid token id, or unsupported service id.

Expected outcome:

- The receiver fails with the OPC UA transport or service status required by the rule.
- Pending chunks and channel/session state are changed only after required security checks pass.
- The connection or channel remains live only when the referenced OPC UA rule permits continued use.
- No attacker-controlled input causes unbounded allocation or a panic.

### XML, history, and encoding helpers

Given:

- XML import, history storage, or an encoding helper receives malformed, corrupt, recursive,
  oversized, or semantically invalid input.

Expected outcome:

- The failure is returned explicitly.
- The failure does not silently drop an error, commit partial import/storage state, or exceed
  configured limits.
- Existing valid stored data remains readable.

## PubSub And SKS Contract

### UADP subscriber state

Given:

- A UADP NetworkMessage has invalid flags, reserved message type bits, overflowing field counts,
  malformed security header, wrong nonce length, trailing secured payload bytes, or oversized
  secured payload.

Expected outcome:

- The publisher/subscriber rejects the message.
- Subscriber target state is not updated before the whole message is validated.
- Replay/security state is not advanced for a rejected message unless the referenced rule requires
  it.

### SKS key lookup

Given:

- A GetSecurityKeys request supplies an unknown starting token id while older keys are available.

Expected outcome:

- The service returns the available key range required by the OPC UA SKS rule instead of an
  unnecessary not-found failure.
- Current-token requests and exact-token requests remain unchanged.

## Non-Regression Contract

- No accepted remediation may reduce existing conformance coverage.
- No secret material may appear in logs, audit events, panic messages, or committed fixtures.
- No new dependency may touch crypto, parsing, or networking without recorded justification.
- Full completion requires targeted tests, relevant package tests, formatting, and workspace clippy.
