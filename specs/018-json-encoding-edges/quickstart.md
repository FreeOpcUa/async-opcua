# Quickstart / Verification: JSON Encoding Conformance Edges (Part 6 §5.4)

All commands from the workspace root. Tests authored + run by Claude (verification division), anchored to
§5.4 field names + round-trip vectors — not loopback.

## Baseline gate (before any change)

```bash
cargo fmt --all --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test -p async-opcua-types --all-features
```

## US1 — fail-closed XML-ExtensionObject-in-JSON when `xml` is off (the real fix)

```bash
# xml OFF (json on) — the fail-closed path; the new test must see Err, not Ok(null):
cargo test -p async-opcua-types --no-default-features --features json
# xml ON — the XML body is parsed as before (unchanged):
cargo test -p async-opcua-types --all-features
```
- A JSON ExtensionObject with `UaEncoding: 2` (XML body) decodes to an **error** (xml off), not null.
- Malformed/truncated extension-object JSON → error, never panic (both configs).

## US2 — DataValue picoseconds JSON round-trip (stale claim → locked by test)

- A `DataValue` with timestamps + `SourcePicoseconds`/`ServerPicoseconds` round-trips through JSON with all
  four fields preserved; field names are `SourcePicoseconds` / `ServerPicoseconds`.

## US3 — Variant XmlElement JSON round-trip (stale claim → locked by test)

- `Variant::from(XmlElement::from("<a>1</a>"))` ↔ `{"Type":16,"Body":"<a>1</a>"}`; the commented-out
  `todo!()` is replaced with a real test (content + empty/null cases).

## US4 — backward compatibility

- Full JSON + serde suites pass with `xml` on AND off; only the xml-off XML-ExtensionObject-in-JSON case
  changes (null → error).

## Final gate

```bash
cargo fmt --all --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test -p async-opcua-types --all-features
cargo test -p async-opcua-types --no-default-features --features json   # xml-off path
```
One commit per user story; the one production change to codex; tests authored + run by Claude.
