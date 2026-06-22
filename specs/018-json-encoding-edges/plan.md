# Implementation Plan: JSON Encoding Conformance Edges (Part 6 §5.4)

**Branch**: `018-json-encoding-edges` | **Date**: 2026-06-22 | **Spec**: [spec.md](./spec.md)
**Input**: Feature specification from `/specs/018-json-encoding-edges/spec.md`

## Summary

Three JSON-encoding conformance edges (Tier 2 #5). Empirical probing during planning found **two are
stale backlog claims** (the round-trips already work — DataValue picoseconds, Variant XmlElement) and
**one is a real fail-closed fix**: an XML-bodied `ExtensionObject` in a JSON document is silently turned
into `null` when the crate is built without `xml` support — it must return a decoding **error** instead.
So this feature is: one ~1-line production change (US1) plus three locking tests (US1/US2/US3) and a
backlog-staleness note. All in `async-opcua-types` behind the `json` feature.

## Technical Context

**Language/Version**: Rust (workspace edition 2021), `async-opcua-types` v0.19.
**Primary Dependencies**: none new — existing `struson` (json), derived `JsonEncodable`/`JsonDecodable`.
**Storage**: N/A.
**Testing**: `cargo test -p async-opcua-types` — Claude-authored, anchored to §5.4 field names + round-trip
vectors; the US1 fail-closed assertion runs on a `json`-on / `xml`-off build.
**Target Platform**: all async-opcua targets.
**Project Type**: library (protocol stack).
**Performance Goals**: N/A.
**Constraints**: JSON decode is attacker-facing — panic-free, fail-closed; no new dep; `xml`-enabled
behavior + binary/XML encodings + all other JSON types unchanged; `clippy --all-targets --all-features`
clean; existing JSON + serde suites pass with `xml` on and off.
**Scale/Scope**: 1 production line (`extension_object.rs`) + ~3 tests in `tests/json.rs`.

## Constitution Check

- **I. Correctness Over Completion**: claims verified empirically before acting — US2/US3 confirmed stale
  (round-trips work), only US1 is a real defect (see research.md). ✅
- **IV. Security Is Paramount**: US1 is a fail-closed fix — a silently-dropped XML body (treated as null)
  becomes a decoding error; JSON decode stays panic-free on malformed input. ✅
- **II/III. Do It Right Once / Task Discipline**: minimal change (1 line) + locking tests; one commit per
  story. ✅
- **V. Leave It Better**: removes a silent-drop and the `todo!()` placeholder; locks two under-tested
  paths. ✅
- **Verification division**: codex makes the production change; Claude authors/runs all tests (incl. the
  xml-off `Err` assertion + malformed-input no-panic), anchored to §5.4. ✅

**Gate: PASS** — no violations; no Complexity Tracking entries.

## Project Structure

### Documentation (this feature)

```
specs/018-json-encoding-edges/
├── spec.md
├── plan.md            # this file
├── research.md        # empirical findings: US2/US3 stale, US1 real fail-closed fix
├── data-model.md      # JSON shapes (ExtensionObject / DataValue / Variant XmlElement)
├── quickstart.md      # verification commands (incl. json-on/xml-off run)
├── contracts/
│   └── api-surface.md  # the one production change + test surface
└── checklists/
    └── requirements.md
```

### Source Code (repository root)

```
async-opcua-types/src/
├── extension_object.rs   # US1: JsonDecodable, encoding==2 / not(feature="xml") branch:
│                         #      Ok(ExtensionObject::null()) -> Err(Error::decoding(...))
└── tests/
    └── json.rs           # US1 fail-closed test (xml off) + malformed no-panic;
                          # US2 DataValue picoseconds round-trip; US3 Variant XmlElement
                          # round-trip (replace the commented-out todo!())
```

**Structure decision**: one production line in `extension_object.rs`; everything else is tests in
`tests/json.rs`. No new module/dep/feature.

## Complexity Tracking

No constitution violations; no entries.
