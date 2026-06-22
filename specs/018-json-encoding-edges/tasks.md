---
description: "Task list for feature 018 — JSON encoding conformance edges (Part 6 §5.4)"
---

# Tasks: JSON Encoding Conformance Edges (Part 6 §5.4)

**Input**: design docs in `/specs/018-json-encoding-edges/` (spec, plan, research, data-model,
contracts/api-surface, quickstart). Tier 2 #5 of the conformance backlog.

**Tests**: INCLUDED (conformance + attacker-facing decode; Constitution I/IV).
**Verification division**: codex makes the one production change (no self-authored tests); **Claude authors
and runs all tests** independently, anchored to **Part 6 §5.4** field names + round-trip vectors and the
fail-closed `Err` assertion — NOT codex loopback. **One commit per user story.**
Gate: `cargo fmt --all --check && cargo clippy --all-targets --all-features --locked -- -D warnings &&
cargo test -p async-opcua-types --all-features && cargo test -p async-opcua-types --no-default-features
--features json` (the last runs the xml-off fail-closed path).

**Pinned facts (research.md):** Empirical probing found **US2 + US3 are STALE backlog claims — both
already round-trip**: DataValue JSON preserves `SourcePicoseconds`/`ServerPicoseconds` (derived
JsonEncodable/Decodable, §5.4 names); `Variant::XmlElement` ↔ `{"Type":16,"Body":"<xml>"}` round-trips
equal. The only real fix is **US1**: `extension_object.rs` `JsonDecodable`, the `encoding == 2` (XML body)
branch under `#[cfg(not(feature = "xml"))]` returns `Ok(ExtensionObject::null())` (silent drop) → must
`Err(Error::decoding(...))` (fail closed). The `#[cfg(feature = "xml")]` branch is unchanged. `json`/`xml`
are independent features; the xml-off path builds with `--no-default-features --features json`. XmlElement
is `crate::XmlElement` (newtype over UAString, `XmlElement::from(&str)`); the existing test
`serialize_variant_xmlelement` is a commented-out `/* todo!() */` block.

## Format: `[ID] [P?] [Story] Description`

---

## Phase 1: Setup

- [X] T001 Baseline gate (both configs: `--all-features` and `--no-default-features --features json`);
  re-confirm the §5.4 field names + the `extension_object.rs` `encoding == 2` / `not(feature = "xml")`
  branch and the commented-out `serialize_variant_xmlelement` test in `tests/json.rs`. No code change.

## Phase 2: User Story 1 — Fail closed on XML-ExtensionObject-in-JSON when xml is off (P1) 🎯 MVP

**Goal**: decoding a JSON ExtensionObject with an XML body returns an error (not a silent null) on a build
without XML support.

- [X] T002 [US1] Claude-authored failing test in `async-opcua-types/src/tests/json.rs`: on a
  `json`-on / `xml`-off build, `ExtensionObject::decode` of a JSON object with `UaEncoding: 2` and an XML
  string `UaBody` returns `Err` (assert `is_err()`), NOT `Ok(null)`. Gate the test (or the assertion) on
  `#[cfg(not(feature = "xml"))]`. Also add a malformed/truncated extension-object JSON → `Err`/no-panic
  case that runs in both configs.
- [X] T003 [US1] Implement in `async-opcua-types/src/extension_object.rs`: in `impl JsonDecodable for
  ExtensionObject`, the `encoding == 2` branch's `#[cfg(not(feature = "xml"))]` arm — replace
  `Ok(ExtensionObject::null())` with `Err(Error::decoding("Cannot decode an XML-encoded ExtensionObject
  body from JSON without the `xml` feature"))`. Leave the `#[cfg(feature = "xml")]` arm unchanged. (codex; depends T002)
- [X] T004 [US1] Gate (incl. the `--no-default-features --features json` run); verify T002 passes; **commit US1**
  (`fix(018 US1): fail closed on XML-ExtensionObject-in-JSON when xml feature off`).

## Phase 3: User Story 2 — DataValue picoseconds JSON round-trip (P2)

**Goal**: lock the (already-working) picoseconds round-trip with a test; record the backlog claim as stale.

- [X] T005 [US2] Claude-authored test in `tests/json.rs`: a `DataValue` with source+server timestamps and
  non-zero `source_picoseconds`/`server_picoseconds` round-trips through `to_string`/`from_str` preserving
  all four fields; assert the emitted JSON uses the §5.4 names `SourcePicoseconds`/`ServerPicoseconds`;
  add a no-timestamp DataValue case (picoseconds omitted). No production change (stale claim).
- [X] T006 [US2] Gate; verify T005 passes; **commit US2** (`test(018 US2): lock DataValue picoseconds JSON round-trip (backlog claim was stale)`).

## Phase 4: User Story 3 — Variant XmlElement JSON round-trip (P3)

**Goal**: replace the commented-out `todo!()` with a real test; record the backlog claim as stale.

- [X] T007 [US3] Claude-authored test in `tests/json.rs`: replace the commented-out
  `serialize_variant_xmlelement` `/* todo!() */` block with
  `test_ser_de_variant(Variant::from(XmlElement::from("<a>1</a>")), json!({"Type": 16, "Body": "<a>1</a>"}))`
  plus a null/empty XmlElement case (`{"Type": 16, "Body": null}`). No production change (stale claim).
- [X] T008 [US3] Gate; verify T007 passes; **commit US3** (`test(018 US3): lock Variant XmlElement JSON round-trip, remove todo!() (backlog claim was stale)`).

## Phase 5: User Story 4 — Backward compatibility (P2)

- [X] T009 [P] [US4] Confirm (Claude) the full JSON + serde suites pass with `xml` on AND off, and that
  the only behavioral change is the xml-off XML-ExtensionObject-in-JSON path (null → error): run
  `cargo test -p async-opcua-types --all-features` and `--no-default-features --features json`; no new
  failures. (No new test file needed beyond the existing suites + US1–US3 additions.)
- [X] T010 [US4] Gate both configs; **commit US4** if any back-compat note/test is added (else fold into final gate).

## Phase 6: Polish

- [X] T011 Update `specs/conformance-gap-backlog.md` Tier 2 #5: mark done; note US2/US3 were stale (already
  round-tripped) and US1 was the real fail-closed fix.
- [X] T012 Final gate: fmt + clippy --all-targets --all-features + `cargo test -p async-opcua-types
  --all-features` + `--no-default-features --features json`; confirm only the xml-off ExtensionObject path
  changed.

---

## Dependencies & Execution Order

- **Setup (T001)** → **US1 (T002→T003)** the real fix → **US2 (T005)** + **US3 (T007)** independent
  test-only stories (parallelizable) → **US4 (T009)** back-compat → **Polish**. One task per codex dispatch
  (codex: only T003; all other tasks are Claude tests/docs). Tests precede implementation in US1.

## Implementation Strategy

**MVP = US1** (the fail-closed fix — the only real defect). US2/US3 lock the two already-working paths the
backlog wrongly flagged (test-only). US4 guards back-compat. Minimal, low-risk; the value is the
fail-closed fix + closing three under-tested JSON paths.

## Notes

- codex makes only the one production change (T003); Claude authors/runs all tests, anchored to §5.4.
- One commit per story; the `xml`-enabled path + binary/XML + all other JSON types unchanged; no new dep;
  no panic on malformed JSON.
- Deferred (recorded): broader reversible-vs-non-reversible JSON work; the XML encoding itself.
