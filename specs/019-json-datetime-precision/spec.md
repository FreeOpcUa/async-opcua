# Feature Specification: JSON DateTime Full-Precision Encoding (Part 6 §5.4.2.6)

**Feature Branch**: `019-json-datetime-precision`
**Created**: 2026-06-22
**Status**: Draft
**Input**: Conformance backlog Tier 2 **#5b** (discovered during feature 018): the JSON `DateTime`
encoding truncates sub-millisecond precision, losing it across a round-trip.

## Context *(mandatory)*

An OPC UA `DateTime` is a count of 100-nanosecond ticks (7 fractional-second digits of precision). The
JSON encoder (`async-opcua-types/src/date_time.rs`, `JsonEncodable for DateTime`) formats via
`to_rfc3339()` which uses `chrono::SecondsFormat::Millis` — **3** fractional digits. So a timestamp like
`…:33.975046100Z` is emitted as `…:33.975Z`, and the sub-millisecond part is **lost on a JSON
encode→decode round-trip** (confirmed in feature 018: a DataValue's SourceTimestamp ticks were not
preserved).

Part 6 **§5.4.2.6** is explicit: "DateTime values shall be formatted as specified by ISO 8601-1 … ISO
8601-1 DateTime values may specify an arbitrary number of decimal places … **Encoders shall support as
many decimal places required to represent the full range of the DateTime type** on their platform." So
truncating to milliseconds is non-conformant.

This feature makes the **JSON DateTime encoder emit full precision** (lossless), so a JSON round-trip
preserves the exact tick value. Scope is the JSON path only (5b); the shared `to_rfc3339()` (used by the
XML encoding and `Display`) is left unchanged — XML DateTime precision is a separate, not-yet-scoped
concern.

## User Scenarios & Testing *(mandatory)*

### User Story 1 — JSON DateTime round-trips at full precision (Priority: P1) 🎯 MVP

As a client/server exchanging timestamps as JSON, I want a `DateTime` encoded to JSON and decoded back to
equal the original exactly (to the 100-ns tick), so sub-millisecond precision is not silently lost.

**Why this priority**: It is the conformance defect (§5.4.2.6); the entire feature.

**Independent Test**: A `DateTime` with sub-millisecond precision (e.g. `…975046100Z`) JSON-encoded then
decoded equals the original exactly; the emitted JSON string carries enough fractional digits to
represent the value.

**Acceptance Scenarios**:

1. **Given** a `DateTime` with 100-ns-tick precision (non-zero sub-millisecond part), **When** JSON-encoded
   and decoded, **Then** the decoded value equals the original exactly (tick-for-tick).
2. **Given** a whole-second `DateTime`, **When** JSON-encoded, **Then** it is emitted as a valid ISO 8601
   string (minimal fractional digits) and round-trips equal.
3. **Given** a millisecond-precision `DateTime`, **When** JSON-encoded and decoded, **Then** it round-trips
   equal.

---

### User Story 2 — Backward compatibility (Priority: P2)

As a maintainer, I want only the JSON DateTime *output format* to change (to carry full precision); JSON
decode already accepts any precision, and the XML / `Display` / binary encodings are unchanged.

**Independent Test**: JSON decode of an existing millisecond-format string still works; the XML and
`Display` outputs (which use `to_rfc3339()`) are unchanged; the binary encoding (tick-based) is unchanged.

**Acceptance Scenarios**:

1. **Given** a JSON DateTime string with 0/3-digit fractional seconds, **When** decoded, **Then** it parses
   as before (decoder already supports arbitrary precision).
2. **Given** the XML and binary encodings, **When** exercised, **Then** their output is byte-identical to
   today (only the JSON encoder format changes).

### Edge Cases

- A `DateTime` whose sub-second part is zero → emitted with minimal (or no) fractional digits, round-trips.
- Min/max DateTime sentinels (`0001-01-01T00:00:00Z` / `9999-…59Z`) — keep the §5.4.2.6 sentinel handling
  in `to_rfc3339`/parse (do not regress).
- Malformed JSON DateTime string → decode returns an error, never panics (existing behavior).

## Requirements *(mandatory)*

- **FR-001**: The JSON `DateTime` encoder MUST emit enough fractional-second digits to represent the full
  100-ns-tick precision of the value (no truncation to milliseconds), per Part 6 §5.4.2.6.
- **FR-002**: A `DateTime` JSON encode→decode round-trip MUST preserve the exact value (tick-for-tick) for
  any representable DateTime, including sub-millisecond precision.
- **FR-003**: The emitted string MUST be valid ISO 8601-1 (UTC, `Z`); whole-second values use minimal
  fractional digits.
- **FR-004**: JSON DateTime **decode** is unchanged (it already accepts arbitrary fractional precision);
  the shared `to_rfc3339()` used by the **XML** encoding and `Display`, and the **binary** encoding, are
  unchanged.
- **FR-005**: Decode remains panic-free / fail-closed on malformed input; no new dependency; change
  confined to `async-opcua-types` (`json` feature).

### Key Entities *(include if feature involves data)*

- **`DateTime`**: 100-ns-tick UTC timestamp; JSON form is an ISO 8601 string. The JSON encoder's
  fractional-digit count is the subject.

## Success Criteria *(mandatory)*

- **SC-001**: A `DateTime` with non-zero sub-millisecond precision round-trips through JSON exactly
  (tick-for-tick) — verified by a test that fails on the current millisecond-truncating encoder.
- **SC-002**: Whole-second and millisecond DateTimes round-trip through JSON exactly; the emitted JSON is
  valid ISO 8601.
- **SC-003**: XML and binary encodings + `Display` are unchanged (existing XML/date_time tests pass
  untouched); JSON decode of legacy millisecond strings still works.
- **SC-004**: `cargo clippy --all-targets --all-features` clean; no new dependency; existing JSON + serde
  suites pass (with the one updated assertion for the now-full-precision JSON output).

## Assumptions

- **Format choice**: a minimal-but-lossless fractional representation (chrono `SecondsFormat::AutoSi` or
  equivalent) — whole seconds emit no/3 digits, sub-second emits up to 9, all lossless for 100-ns ticks.
  Confirmed at implementation.
- **Scope**: JSON encoder only. XML DateTime precision (same root, shared `to_rfc3339`) is **out of scope**
  / a separate potential item.
- **One existing assertion updates**: the JSON Variant-DateTime test that hard-codes `"…00.000Z"` updates
  to the new full-precision/minimal output (it asserts the format, not a conformance requirement).
- **Verification division**: codex makes the encoder change; **Claude authors/runs the tests** — sub-ms
  round-trip (must fail pre-fix), whole-second/ms round-trips, decode-of-legacy-ms, and an
  XML/binary-unchanged check — anchored to §5.4.2.6.
- **Spec source**: Part 6 §5.4.2.6 in `~/opcua-specs`.
