# API Surface: JSON Encoding Conformance Edges

No public signature changes. One behavioral change (US1) + locking tests (US1/US2/US3). All in
`async-opcua-types` behind the `json` feature.

## Production change (US1) — `async-opcua-types/src/extension_object.rs`

In `impl JsonDecodable for ExtensionObject`, the `encoding == 2` (XML body) branch:
```rust
// before:
#[cfg(not(feature = "xml"))]
{
    tracing::warn!("XML feature is not enabled, …");
    Ok(ExtensionObject::null())
}
// after:
#[cfg(not(feature = "xml"))]
{
    Err(Error::decoding(
        "Cannot decode an XML-encoded ExtensionObject body from JSON without the `xml` feature",
    ))
}
```
- The `#[cfg(feature = "xml")]` branch (parses the XML body) is unchanged.
- `Error::decoding(...)` is already used throughout this impl (e.g. the surrounding encoding checks).

## Test surface (Claude) — `async-opcua-types/src/tests/json.rs`

- **US1**: a JSON ExtensionObject `{"UaTypeId":…, "UaEncoding":2, "UaBody":"<xml/>"}` →
  `ExtensionObject::decode` returns `Err` on a `json`-on / `xml`-off build (the test or its module is
  `#[cfg(not(feature = "xml"))]`-gated, or the assertion is conditional). Plus a malformed/truncated
  extension-object JSON → `Err`, never panic (runs in both configs).
- **US2**: a `DataValue` with timestamps + non-zero `source_picoseconds`/`server_picoseconds` round-trips
  through `to_string`/`from_str` preserving all four fields; a no-timestamp DataValue omits picoseconds.
- **US3**: replace the commented-out `serialize_variant_xmlelement` `todo!()` with
  `test_ser_de_variant(Variant::from(XmlElement::from("<a>1</a>")), json!({"Type": 16, "Body": "<a>1</a>"}))`
  + an empty/null XmlElement case.

## Invariants

- `xml`-enabled ExtensionObject JSON path, binary/XML encodings, and all other JSON types unchanged.
- No new dependency; `clippy --all-targets --all-features` clean; JSON + serde suites pass with `xml`
  on AND off.
- The only behavioral change is the previously-silent xml-off XML-ExtensionObject-in-JSON path (null →
  error).
