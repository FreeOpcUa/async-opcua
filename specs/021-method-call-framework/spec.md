# Feature Specification: Typed Method-Call Framework

**Feature Branch**: `021-method-call-framework`
**Created**: 2026-06-22
**Status**: Draft
**Input**: Build an ergonomic method-call framework for async-opcua servers (upstream `TODO.md`:
"Write a framework for method calls … let users simply define a rust method that takes in values that
each implement a trait `MethodArg`, with a blanket impl for `TryFromVariant`, and return a tuple of
results.")

## Context *(mandatory)*

OPC UA servers expose callable **Methods**. Today a server author registers a method by writing a
low-level callback that receives the raw argument list and must, by hand: check the number of
arguments, convert each positional argument from its dynamic value into the Rust type it expects,
choose the correct error status when a conversion or count check fails, and assemble the list of output
values. This is verbose and easy to get wrong (off-by-one on argument position, wrong status code on
mismatch, forgotten arity check).

The server's Call service plumbing already exists and works end-to-end. This feature adds a **typed,
opt-in convenience layer on top of the existing method-registration path** so an author can instead
write a normal Rust function whose parameters are ordinary typed values and whose return is a tuple of
typed outputs, with the argument decoding, arity/type validation, correct status-code selection, and
output marshaling handled for them. It does **not** change the OPC UA wire protocol, the Call service,
or the existing low-level registration API; both styles coexist.

This also advances the conformance backlog's Tier 3 "Method Call" facet by making it *easy* to return
the spec-correct Call status codes.

## User Scenarios & Testing *(mandatory)*

### User Story 1 — Typed method registration (Priority: P1) 🎯 MVP

As a server author, I want to register an OPC UA method by writing a plain Rust function with typed
parameters and a typed tuple return, so that argument decoding, count/type validation, error-status
selection, and output marshaling are handled for me instead of by hand.

**Why this priority**: It is the entire point of the feature and the MVP — it delivers the ergonomic
win and is independently usable on its own.

**Independent Test**: Register a typed method (e.g. one taking a text value and a number, returning a
text value) through the typed adapter; invoke it with valid arguments and confirm the correct typed
output; invoke it with the wrong number of arguments and with a wrong-typed argument and confirm the
spec-correct rejection status (and per-argument result where applicable). All via the existing
registration path, with no change to existing low-level callbacks.

**Acceptance Scenarios**:

1. **Given** a typed method that takes typed inputs and returns a typed tuple, **When** it is called
   with arguments that match in count and type, **Then** the inputs are decoded to the declared Rust
   types, the user function runs, and its tuple result is marshaled back to the correct output values.
2. **Given** the same typed method, **When** it is called with too few or too many arguments, **Then**
   the call is rejected with the argument-count status code defined by the Call service (no panic, no
   generic error).
3. **Given** the same typed method, **When** an argument cannot be decoded to its declared type, **Then**
   the call is rejected with the invalid-argument status and a per-argument result identifying which
   argument failed.
4. **Given** typed methods with zero inputs and zero outputs, with a single output, and with multiple
   outputs, **When** each is called validly, **Then** outputs are marshaled correctly for every arity.
5. **Given** a user function that returns an error (either a status code directly or the crate's error
   type), **When** it is called, **Then** that error is surfaced as the method-call status without
   panicking.

---

### User Story 2 — Demo-server adoption & before/after (Priority: P2)

As a developer learning the SDK, I want the sample server to demonstrate the typed framework alongside
a retained low-level method, so I can see the ergonomic improvement and confirm both styles still work.

**Why this priority**: Demonstrates the value and guards against regressing the existing low-level path;
depends on US1.

**Independent Test**: The sample server registers at least one single-input/single-output method and
one multi-argument method via the typed framework, plus retains at least one raw low-level method; the
server builds and all three are callable with correct results.

**Acceptance Scenarios**:

1. **Given** the sample server, **When** it is built, **Then** it registers representative methods via
   the typed framework and at least one via the existing low-level callback, with no regression.
2. **Given** a method rewritten with the typed framework, **When** compared to its previous low-level
   form, **Then** it expresses the same behavior with markedly less boilerplate (no manual indexing,
   type-matching, or output-vector assembly).

---

### User Story 3 — Context-aware typed methods (Priority: P3, optional)

As a server author, I want an optional typed variant that also gives my function access to the
method-call context (e.g. the calling session / invocation context), so context-dependent methods get
the same ergonomic benefits — **only if it falls out naturally from the trait design**.

**Why this priority**: Nice-to-have; the existing low-level context-aware registration already covers
the need, so this is deferred unless cheap.

**Independent Test**: A typed method that also receives the call context can read context information
and still benefits from typed arguments/outputs and validation.

**Acceptance Scenarios**:

1. **Given** a context-aware typed method, **When** it is called, **Then** it receives both the typed
   arguments and the call context, with the same validation and marshaling guarantees as US1.

---

### Edge Cases

- **Argument count mismatch** (too few / too many) → the count-specific Call status code; never a panic.
- **Per-argument decode failure** → invalid-argument status plus a per-argument result vector marking
  the offending argument(s).
- **User function returns an error** → surfaced as the call status (supports both a status code and the
  crate error type), no panic.
- **Zero-argument / zero-output** methods and **multi-output** methods must all marshal correctly.
- **Existing low-level callbacks** must remain valid and behave identically (no breaking change).
- The new code must compile warning-free under **every supported feature configuration** (not only the
  all-features build), since the CI gate exercises the no-default-features / json-off legs under
  `-D warnings`.

## Requirements *(mandatory)*

- **FR-001**: The framework MUST let an author register a method as a normal Rust function/closure whose
  parameters are typed values (each accepted via a conversion trait with a blanket implementation for
  any type already convertible from a dynamic value) and whose return is `Result<Outputs, E>`, where
  `Outputs` is a tuple of typed outputs (each convertible into a dynamic value) supporting arities from
  zero up to at least six, plus the single-value case.
- **FR-002**: The framework MUST decode each positional argument into its declared type, run the user
  function, and marshal the returned tuple back into the output value list — registered through the
  **existing** method-registration path with no downstream change.
- **FR-003**: On wrong argument count, the framework MUST reject the call with the Call-service-defined
  count status code (too few vs too many distinguished where the service defines distinct codes), with
  no panic.
- **FR-004**: On per-argument decode failure, the framework MUST reject the call with the operation-
  level invalid-argument status (`BadInvalidArgument`) and identify the failing argument index via a
  log/diagnostic. NOTE: the wire per-argument `inputArgumentResults` vector is **not** populated — the
  existing method-callback path carries only a single status code, and populating a per-argument vector
  would require a richer callback type, which is deferred to preserve the additive/no-breakage
  constraint (FR-006). The operation-level status is the client-visible, conformance-significant result.
- **FR-005**: The framework MUST accept user error returns as both a status code directly and the
  crate's error type, surfacing them as the call status without panicking.
- **FR-006**: The framework MUST be **additive and opt-in**: the existing low-level callback type and
  registration API are unchanged, and existing low-level callbacks keep working identically (no public
  API breakage).
- **FR-007**: The framework MUST introduce **no new runtime dependency** and MUST compile warning-free
  under `-D warnings` in **all** supported feature configurations (default, all-features, and
  no-default-features / json-off / xml-only legs).
- **FR-008**: The sample server MUST demonstrate the typed framework on a single-in/single-out method
  and a multi-argument method while retaining at least one low-level method, with no regression.
- **FR-009** *(optional, US3)*: The framework SHOULD offer a context-aware typed variant mirroring the
  existing context-aware low-level registration, if it integrates cleanly with the trait design.

### Key Entities *(include if feature involves data)*

- **Typed argument**: a Rust type usable as a method parameter because it can be produced from a single
  dynamic argument value.
- **Typed output set**: a tuple (arity 0..=N, plus the single-value case) of types each convertible to a
  dynamic value, marshaled positionally to the method's outputs.
- **Typed method adapter**: the wrapper that turns a typed user function into the existing low-level
  callback, performing arity check → per-argument decode → invoke → output marshal, with correct status
  selection.

## Success Criteria *(mandatory)*

- **SC-001**: An author can register a working method with typed inputs and a typed tuple output without
  writing any manual argument indexing, type matching, or output-vector assembly.
- **SC-002**: Invalid calls (wrong count, wrong type, user error) yield the spec-correct Call status
  codes (and per-argument results for decode failures) with no panic, verified by tests anchored to the
  Call-service status-code semantics.
- **SC-003**: A typed method registered through the framework is callable end-to-end via the server's
  Call service and returns the correct outputs.
- **SC-004**: The existing low-level method-callback API and all existing methods continue to work
  unchanged (no breaking change), and the sample server demonstrates both styles.
- **SC-005**: The workspace builds and lints clean (`clippy --all-targets --all-features` plus the
  no-default-features / json-off legs under `-D warnings`); existing unit and integration suites pass;
  no new runtime dependency is added.

## Assumptions

- The typed layer wraps the **existing** method-callback registration (and its context-aware variant);
  the Call service, request/result wire types, and the low-level callback signature are unchanged.
- Tuple-arity support up to ~6 outputs is sufficient; higher arities can be added later by extending the
  generating macro.
- Argument/output conversions reuse the existing dynamic-value conversion traits already in the
  codebase (the blanket-impl foundation referenced by the TODO), adding no new dependency.
- **Verification division** (established practice): the trait/adapter production code and the sample-
  server rewrite may be implemented by the code-generation assistant; all tests are authored and run
  independently, anchored to OPC UA Part 4 Call-service status-code semantics and real value
  round-trips (not author-loopback), including an end-to-end Call through the server.
- **Out of scope / deferred**: changing the Call service or wire types; the broader Tier 3 Method/Audit
  conformance facet beyond returning correct Call status codes; other open `TODO.md` items (SDK
  tooling, persistent-store example server, "bad ideas" servers).
