# Data Model: JSON Encoding Conformance Edges

No new types. The relevant JSON shapes (Part 6 §5.4):

## ExtensionObject (JSON) — US1

```json
{ "UaTypeId": <NodeId>, "UaEncoding": <0|1|2>, "UaBody": <body> }
```
- `UaEncoding`: 0/absent = JSON body; 1 = binary (base64) body; **2 = XML body** (string).
- Decode resolves the body by encoding. The **`encoding == 2` + `not(feature = "xml")`** branch currently
  returns `Ok(ExtensionObject::null())` (silent drop) → **change to `Err(Error::decoding(...))`** (fail
  closed). The `feature = "xml"` branch (parses the XML) is unchanged.
- Validation: malformed/truncated extension-object JSON → `Err`, never panic (existing behavior, asserted).

## DataValue (JSON) — US2 (already correct; lock with a test)

```json
{ "Value": <Variant>, "Status": <u32>, "SourceTimestamp": <DateTime>,
  "SourcePicoseconds": <u16>, "ServerTimestamp": <DateTime>, "ServerPicoseconds": <u16> }
```
- Derived `JsonEncodable`/`JsonDecodable` already emits/reads `SourcePicoseconds` / `ServerPicoseconds`
  (verified). Picoseconds are meaningful only with the corresponding timestamp present (matches binary).
- Round-trip invariant: encode→decode preserves all four timestamp/picoseconds fields.

## Variant XmlElement (JSON) — US3 (already correct; lock with a test)

```json
{ "Type": 16, "Body": "<xml-string>" }
```
- `Variant::XmlElement` (newtype over `UAString`, `crate::XmlElement`, `XmlElement::from(&str)`) encodes
  as a JSON string body with `Type: 16`; decode (`dec_body::<XmlElement>`) recovers it. Round-trips equal
  (verified). Null/empty XmlElement → `Body: null`.

## StatusCode / error contract

- US1: the new fail-closed path returns a decoding error (`Error::decoding(...)`, `Bad_DecodingError`
  class), surfaced as `Err` from `JsonDecodable::decode`.
- All JSON decode paths remain panic-free + fail-closed on malformed input.
