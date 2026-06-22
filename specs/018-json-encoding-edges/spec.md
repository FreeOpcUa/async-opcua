# Feature Specification: JSON Encoding Conformance Edges (Part 6 §5.4)

**Feature Branch**: `018-json-encoding-edges`
**Created**: 2026-06-22
**Status**: Draft
**Input**: Fix the JSON encoding conformance edges (Tier 2 #5 in `specs/conformance-gap-backlog.md`),
OPC UA Part 6 §5.4 (reversible JSON encoding). Three self-contained sub-issues in `async-opcua-types`,
behind the existing `json` feature.

## Context *(mandatory)*

The OPC UA JSON encoding (Part 6 §5.4) is used for PubSub JSON messages and JSON-based tooling. Three
edge gaps remain (conformance backlog Tier 2 #5), in `async-opcua-types`:

1. **Silent drop (fail-closed gap)** — an `ExtensionObject` carried in a JSON document with an
   **XML-encoded body** (`UaEncoding = 2`) is **silently turned into a null object** when the crate is
   built with the `xml` feature **off**: the decoder logs a warning and returns `Ok(null)` instead of an
   error. A remote peer can therefore hide an XML-bodied object that the receiver mistakes for an
   absent/empty value. This must **fail closed** (return a decoding error).
2. **DataValue picoseconds** — `DataValue` carries `SourcePicoseconds` / `ServerPicoseconds`; the backlog
   reports they are not round-tripped through the JSON encoding. This must be verified and, if broken,
   fixed so they round-trip per §5.4.
3. **XmlElement in Variant** — the JSON round-trip of a `Variant` holding an `XmlElement` is untested
   (a `todo!()` placeholder in the test suite). The behavior must be verified and locked with a real test
   (and fixed if the round-trip is actually broken).

These are independent and low-risk; #1 is the meaningful conformance/security fix.

## User Scenarios & Testing *(mandatory)*

### User Story 1 — Fail closed on an XML-bodied ExtensionObject in JSON when XML is unavailable (Priority: P1) 🎯 MVP

As a server decoding an untrusted JSON message, when it contains an `ExtensionObject` whose body is
XML-encoded but the build does not include XML support, I want decoding to **fail with an error** rather
than silently yield a null object, so a peer cannot smuggle a body the receiver treats as absent.

**Why this priority**: It is the fail-closed/conformance fix (Constitution IV) and the only one with a
security dimension — a silent null is a parser-trust gap.

**Independent Test**: Build with `json` on and `xml` off; decode a JSON `ExtensionObject` with
`UaEncoding = 2` (XML body) and assert the result is a decoding **error**, not `Ok(null)`; no panic on
malformed input.

**Acceptance Scenarios**:

1. **Given** a JSON `ExtensionObject` with an XML-encoded body and a build without XML support, **When**
   decoded, **Then** it returns a decoding error (e.g. `Bad_DecodingError`), not a null object.
2. **Given** the same input on a build **with** XML support, **When** decoded, **Then** the body is
   parsed exactly as today (unchanged behavior).
3. **Given** malformed / truncated JSON extension-object bytes, **When** decoded, **Then** an error is
   returned and the decoder never panics.

---

### User Story 2 — DataValue picoseconds round-trip through JSON (Priority: P2)

As a client/server exchanging `DataValue`s as JSON, I want `SourcePicoseconds` and `ServerPicoseconds`
preserved across a JSON encode→decode round-trip (when their corresponding timestamps are present), so
sub-tick precision is not lost.

**Why this priority**: A correctness/conformance gap, but JSON is opt-in and picoseconds are rarely used,
so lower impact than US1.

**Independent Test**: JSON-encode a `DataValue` with source/server timestamps and non-zero
`SourcePicoseconds`/`ServerPicoseconds`, decode it back, and assert all four fields are preserved; the
JSON field names match Part 6 §5.4 (`SourcePicoseconds` / `ServerPicoseconds`).

**Acceptance Scenarios**:

1. **Given** a `DataValue` with timestamps + non-zero picoseconds, **When** JSON-encoded and decoded,
   **Then** the picoseconds are preserved (round-trip equal).
2. **Given** a `DataValue` with no timestamps, **When** encoded, **Then** picoseconds are omitted/ignored
   exactly as the binary encoding does (picoseconds are meaningless without a timestamp).

---

### User Story 3 — XmlElement-in-Variant JSON round-trip locked by a test (Priority: P3)

As a maintainer, I want the JSON round-trip of a `Variant` holding an `XmlElement` covered by a real test
(replacing the `todo!()` placeholder), so the behavior is verified and protected against regression.

**Why this priority**: Mostly a test-coverage gap; the production encode/decode appears to exist.

**Independent Test**: JSON-encode a `Variant::XmlElement(..)`, decode it back, assert equality; the
`todo!()` is gone.

**Acceptance Scenarios**:

1. **Given** a `Variant` holding an `XmlElement`, **When** JSON-encoded and decoded, **Then** the value
   round-trips equal.
2. **Given** the test suite, **When** run, **Then** no `todo!()` remains in the Variant JSON per-type test.

---

### User Story 4 — Backward compatibility (Priority: P2)

As a maintainer, I want every other JSON encode/decode behavior unchanged — the only behavioral change is
that the previously-silent xml-off XML-ExtensionObject-in-JSON path now returns an error instead of null.

**Independent Test**: The existing JSON + serde test suites pass unchanged; the `xml`-enabled
ExtensionObject path, binary/XML encodings, and all other JSON types are byte-identical.

**Acceptance Scenarios**:

1. **Given** the existing JSON and serde round-trip suites, **When** run (xml on and xml off), **Then**
   they pass; only the xml-off XML-bodied-ExtensionObject case changes (null → error).

### Edge Cases

- Malformed / truncated JSON extension object → error, never panic (both xml on and off).
- An ExtensionObject with `UaEncoding = 2` and an empty XML body (xml on) keeps its current behavior.
- A `DataValue` with picoseconds but a missing timestamp → picoseconds omitted (consistent with binary).
- A `Variant::XmlElement` holding an empty/with-content XML fragment round-trips.

## Requirements *(mandatory)*

- **FR-001**: Decoding a JSON `ExtensionObject` whose body is XML-encoded (`UaEncoding = 2`) MUST return a
  decoding error when the crate is built without XML support — it MUST NOT silently return a null object.
- **FR-002**: With XML support compiled in, the XML-bodied ExtensionObject JSON path MUST behave exactly
  as today (parse the XML body); no change.
- **FR-003**: `DataValue` JSON encode/decode MUST round-trip `SourcePicoseconds` and `ServerPicoseconds`
  (when the corresponding timestamp is present), using the Part 6 §5.4 field names.
- **FR-004**: The JSON round-trip of a `Variant` holding an `XmlElement` MUST be covered by a real test
  (no `todo!()`), and MUST round-trip equal (fixing the encode/decode if it is actually broken).
- **FR-005**: All JSON encode/decode paths MUST remain **panic-free** and **fail closed** on
  attacker-controlled / malformed input.
- **FR-006**: No new dependency; changes confined to `async-opcua-types` behind the existing `json`
  feature; the `xml`-enabled behavior, the binary/XML encodings, and all other JSON types unchanged;
  existing JSON + serde suites pass with `xml` on and `xml` off.

### Key Entities *(include if feature involves data)*

- **`ExtensionObject` (JSON)**: `{ UaTypeId, UaEncoding, UaBody }`; `UaEncoding = 2` = XML body. The
  decode path resolves the body by encoding; the xml-off XML branch is the fail-closed gap.
- **`DataValue` (JSON)**: `{ Value, Status, SourceTimestamp, SourcePicoseconds, ServerTimestamp,
  ServerPicoseconds }` per §5.4 — the picoseconds fields are the round-trip subject.
- **`Variant::XmlElement`**: a Variant whose scalar type is XmlElement; the JSON round-trip subject of US3.

## Success Criteria *(mandatory)*

- **SC-001**: On a `json`-on / `xml`-off build, decoding a JSON ExtensionObject with an XML body returns
  an error (not a null), verified by an explicit test asserting `Err`; no input panics.
- **SC-002**: A `DataValue` with timestamps + non-zero picoseconds round-trips through JSON with all four
  timestamp/picoseconds fields preserved.
- **SC-003**: The `Variant::XmlElement` JSON round-trip test passes and the `todo!()` is removed.
- **SC-004**: The full JSON + serde suites pass with `xml` on AND `xml` off; `cargo clippy --all-targets
  --all-features` is clean with no new dependency; the only behavioral change is the xml-off
  XML-ExtensionObject-in-JSON path (null → error).

## Assumptions

- **Empirical verification first**: US2 (picoseconds) and US3 (XmlElement) backlog claims are verified
  against the actual code/tests before any fix — if a round-trip already works, the deliverable is the
  missing test plus recording the claim as stale (this project has had stale backlog claims before).
- **Field names / semantics** from Part 6 §5.4 are confirmed in `~/opcua-specs` at planning
  (`SourcePicoseconds` / `ServerPicoseconds`; the ExtensionObject JSON `UaEncoding` values).
- **Out of scope / deferred**: broader reversible-vs-non-reversible JSON work beyond these three edges;
  the XML encoding itself; any change to the binary encoding.
- **Verification division**: codex implements production code only; **Claude authors and runs all tests**
  independently — §5.4-anchored round-trip vectors (XmlElement, DataValue picoseconds), the fail-closed
  `Err` assertion for the xml-off XML-ExtensionObject-in-JSON case, and malformed-input negative/no-panic
  assertions — anchored to the spec, not codex loopback.
- **Spec source**: Part 6 §5.4 text in `~/opcua-specs` (PDFs not committed).
