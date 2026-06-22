# Research: JSON Encoding Conformance Edges (Part 6 §5.4)

Findings from empirically probing the actual code (throwaway round-trip tests, since reverted) +
inspecting the JSON encode/decode paths in `async-opcua-types`. **Two of the three backlog sub-issues are
STALE** (the round-trips already work); only one is a real code fix.

## Decision 1 — US1 (real fix): XML-bodied ExtensionObject in JSON must fail closed when `xml` is off

**Finding (confirmed)**: `impl JsonDecodable for ExtensionObject` in
`async-opcua-types/src/extension_object.rs`, the `encoding == 2` (XML body) branch, has:
```rust
#[cfg(not(feature = "xml"))]
{
    tracing::warn!("XML feature is not enabled, deserializing XML payloads in JSON extension objects is not supported");
    Ok(ExtensionObject::null())   // <-- silent drop
}
```
This silently turns an XML-bodied ExtensionObject into `null` on a build without XML support — a peer can
hide a body the receiver treats as absent.
**Decision**: replace the `Ok(ExtensionObject::null())` with `Err(Error::decoding(...))` (a
`Bad_DecodingError`-class error) so it **fails closed** (Constitution IV). Keep the
`#[cfg(feature = "xml")]` branch (which parses the XML) unchanged. Single-line behavioral change on the
previously-silent path only. **Rationale**: §5.4 (an encoding the receiver can't process is a decoding
error, not a success) + Constitution IV (never silently weaken/drop).

## Decision 2 — US2 (STALE claim → test only): DataValue picoseconds DO round-trip in JSON

**Finding (probe)**: a `DataValue { value, status, source_timestamp, source_picoseconds: Some(123),
server_timestamp, server_picoseconds: Some(456) }` JSON-encodes to:
```json
{"Value":{"Type":5,"Body":100},"SourceTimestamp":"…","SourcePicoseconds":123,"ServerTimestamp":"…","ServerPicoseconds":456}
```
and decodes back to `source_picoseconds = Some(123)`, `server_picoseconds = Some(456)`. The derived
`JsonEncodable`/`JsonDecodable` (data_value.rs ~line 44) already emits/reads the §5.4 field names
`SourcePicoseconds` / `ServerPicoseconds`.
**Decision**: the backlog claim ("picoseconds not round-tripped") is **STALE** — no code change. Deliverable
= an explicit regression test locking the round-trip (and the field names), and record the claim as stale.
**Rationale**: §5.4 DataValue JSON object includes SourcePicoseconds/ServerPicoseconds; the derive already
maps them.

## Decision 3 — US3 (STALE claim → test only): Variant XmlElement DOES round-trip in JSON

**Finding (probe)**: `Variant::from(XmlElement::from("<a>1</a>"))` JSON-encodes to `{"Type":16,"Body":
"<a>1</a>"}` and decodes back equal (`EQ=true`). The production encode (`variant/json.rs:39`) and decode
(`variant/json.rs:165` `dec_body::<XmlElement>`) already work. The test in `tests/json.rs` is a
**commented-out** `/* … todo!() */` block (`serialize_variant_xmlelement`), so it is not even an active
test.
**Decision**: the claim is **STALE** (round-trip works) — no production change. Deliverable = replace the
commented-out `todo!()` with a real `test_ser_de_variant(Variant::from(XmlElement::from("<a>1</a>")),
json!({"Type": 16, "Body": "<a>1</a>"}))` test (and an empty/null XmlElement case). `XmlElement` is a
newtype over `UAString` (`XmlElement::from(&str)`; re-exported as `crate::XmlElement`).

## Decision 4 — Test configuration for US1 (xml off)

**Decision**: the fail-closed path only exists under `#[cfg(not(feature = "xml"))]`, so the US1 test must
run on a `json`-on / `xml`-off build. `async-opcua-types` features: `json` and `xml` are independent, so
`--features json --no-default-features` (or an equivalent that turns `xml` off) compiles the fail-closed
branch. The gate includes both a `--all-features` run (xml on: branch unchanged) and a `json`-on/`xml`-off
run (the new `Err`). Confirm the exact feature flags at implementation by reading the crate's
`[features]`.
**Rationale**: the behavior under test is feature-gated.

## Decision 5 — Scope / structure

**Decision**: US1 = one ~1-line production change in `extension_object.rs`. US2/US3 = test-only additions
in `async-opcua-types/src/tests/json.rs` (+ possibly `tests/serde.rs` already covers picoseconds for
serde; the new test is for the OPC UA JSON path). No new deps; no new modules; behind `json`. The
`xml`-enabled path, binary/XML encodings, and all other JSON types are unchanged.

## Decision 6 — Test anchoring & negatives (verification division)

**Decision**: Claude-authored tests anchored to §5.4 field names + round-trip vectors:
- US1: a JSON ExtensionObject with `UaEncoding: 2` + an XML string body → assert `decode` returns `Err`
  (xml off), and (xml on) the existing parse behavior; plus malformed/truncated extension-object JSON →
  `Err`, never panic.
- US2: DataValue picoseconds round-trip (+ a no-timestamp case → picoseconds omitted, matching binary).
- US3: Variant XmlElement round-trip (content + empty/null), `todo!()` removed.
**Rationale**: the project's verification division; prior fuzz/test work caught real bugs.

## Net effect

- **Real code change**: 1 (US1 fail-closed, ~1 line + an error message).
- **Test-only (stale claims)**: 2 (US2, US3) — add the missing tests, record both as stale in the backlog.
- This is a small feature; the value is the fail-closed fix + locking three under-tested JSON paths.
