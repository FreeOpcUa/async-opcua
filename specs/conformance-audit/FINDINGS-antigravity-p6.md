# OPC UA Part 6 Mappings Conformance Audit Findings

This document summarizes the OPC UA spec-conformance audit of the `async-opcua` Rust repository against **OPC UA Part 6 "Mappings" v1.05.07**. 

---

## Numbered Summary of Candidate Divergences

We identified **16 candidate divergences** where the codebase implementation deviates from the authoritative OPC UA Part 6 specification:

1. **String pre-allocation DoS** ([string.rs:131](file:///home/quackdcs/async-opcua/async-opcua-types/src/string.rs#L131)): `UAString::decode` pre-allocates buffer memory based on the attacker-controlled `len` field before checking if there are enough bytes left in the stream. This enables a crafted length field to trigger large memory allocations, potentially leading to Out-Of-Memory (OOM) Denial of Service (DoS). (In contrast, `ByteString::decode` bounds allocations using `stream.take().read_to_end()`).
2. **Non-conformant Boolean decoding** ([basic_types.rs:46](file:///home/quackdcs/async-opcua/async-opcua-types/src/basic_types.rs#L46)): `SimpleBinaryDecodable for bool` decodes `read_u8(stream)? == 1`. The spec states "decoders shall treat any non-zero value as true". Hence, any non-zero value other than 1 (e.g. 2, 255) will incorrectly decode as `false` instead of `true`.
3. **Rejection of Variant reserved type IDs 26-31** ([type_id.rs:260](file:///home/quackdcs/async-opcua/async-opcua-types/src/variant/type_id.rs#L260), [mod.rs:659](file:///home/quackdcs/async-opcua/async-opcua-types/src/variant/mod.rs#L659)): The spec states: "Decoders shall accept these IDs, assume the Value contains a ByteString or an array of ByteStrings and pass both onto the application. Encoders shall not use these IDs."
   The implementation of `VariantScalarTypeId::from_encoding_mask` rejects these IDs by returning `None`, leading to a decoding error for arrays. For scalars, `decode_variant_value` returns `Variant::Empty` instead of a `ByteString`.
4. **DataValue picoseconds not clamped** ([data_value.rs:227](file:///home/quackdcs/async-opcua/async-opcua-types/src/data_value.rs#L227)): The spec states: "The Picoseconds fields shall contain values less than 10 000. The decoder shall treat values greater than or equal to 10 000 as the value ‘9999’."
   The implementation reads `source_picoseconds` and `server_picoseconds` directly as `u16` but does not clamp values `>= 10000` to `9999`.
5. **Incorrect JSON field names for Variant** ([json.rs:79](file:///home/quackdcs/async-opcua/async-opcua-types/src/variant/json.rs#L79)): The spec (Table 41) states the Variant JSON fields are `UaType` and `Value` (along with `Dimensions`). The implementation uses `"Type"` and `"Body"` instead.
6. **Object representation for JSON NodeIds** ([node_id/json.rs:34](file:///home/quackdcs/async-opcua/async-opcua-types/src/node_id/json.rs#L34), [expanded_node_id.rs:82](file:///home/quackdcs/async-opcua/async-opcua-types/src/expanded_node_id.rs#L82)): The spec requires that NodeId and ExpandedNodeId be encoded as JSON strings using the string syntax defined in 5.1.12 (e.g. `i=13`, `ns=2;s=my_string`). The implementation serializes them as JSON objects containing fields like `"Id"`, `"IdType"`, `"Namespace"`, etc.
7. **JSON number representation for 64-bit integers** ([json.rs:235](file:///home/quackdcs/async-opcua/async-opcua-types/src/json.rs#L235)): The spec requires `Int64` and `UInt64` values to be encoded as decimal strings. The implementation serializes and deserializes them directly as JSON numbers.
8. **JSON nesting inside UaBody for ExtensionObjects** ([extension_object.rs:283](file:///home/quackdcs/async-opcua/async-opcua-types/src/extension_object.rs#L283)): The spec defines that for JSON-encoded structures, the structure fields should be serialized directly inside the ExtensionObject's JSON object (i.e. at the top level of the object) with `UaTypeId` inserted into that same object. `UaEncoding` and `UaBody` are *only* used for UA Binary or UA XML encoded structures. The implementation always serializes the structure nested inside a `"UaBody"` key (e.g. `{ "UaTypeId": ..., "UaBody": { ... } }`), even when utilizing JSON encoding.
9. **No JSON duplicate field name rejection** ([node_id/json.rs:91](file:///home/quackdcs/async-opcua/async-opcua-types/src/node_id/json.rs#L91)): The spec states: "Decoders shall report decoding errors to the application if a JSON object has multiple fields with the same name." The JSON decoders loop through fields (e.g. `while stream.has_next()?`) and silently overwrite values without checking for duplicates.
10. **No JSON array-length bounding** ([json.rs:122](file:///home/quackdcs/async-opcua/async-opcua-types/src/json.rs#L122)): The JSON decoder for `Vec<T>` decodes arrays dynamically via a `while stream.has_next()?` loop without verifying that the count does not exceed `max_array_length`, presenting an unbounded memory pre-allocation DoS vulnerability.
11. **Negotiation limit of 1 chunk when 0 (unlimited) is requested** ([tcp.rs:116](file:///home/quackdcs/async-opcua/async-opcua-server/src/transport/tcp.rs#L116)): The spec states: "A value of zero indicates that the Client/Server has no limit." However, `effective_max_chunk_count` resolves `(0, 0)` as `1` (which is unit-tested). This results in a limit of exactly 1 chunk when both are 0, rather than treating it as unlimited.
12. **Strict UACP buffer size requirements** ([tcp_types.rs:341](file:///home/quackdcs/async-opcua/async-opcua-core/src/comms/tcp_types.rs#L341)): The spec states: "Shall be at least 1024 bytes if the sender intends to use an ECC SecurityPolicy. Shall be at least 8192 bytes otherwise." The implementation unconditionally requires buffer sizes to be `>= 8192` bytes, rejecting valid ECC buffer sizes of 1024–8191.
13. **No size limit check on Error Message reason** ([tcp_types.rs:445](file:///home/quackdcs/async-opcua/async-opcua-core/src/comms/tcp_types.rs#L445)): The spec states: "This string shall not be more than 4096 bytes. A Client shall ignore strings that are longer than this." `ErrorMessage::decode` does not validate this limit.
14. **No length checks on ReverseHello fields** ([tcp_types.rs:502](file:///home/quackdcs/async-opcua/async-opcua-core/src/comms/tcp_types.rs#L502)): The spec states that for `ReverseHello` the `ServerUri` and `EndpointUrl` shall be less than 4096 bytes. The implementation performs no validation on these lengths during decoding.
15. **No validation of SecurityPolicyUri length** ([security_header.rs:142](file:///home/quackdcs/async-opcua/async-opcua-core/src/comms/security_header.rs#L142)): The spec states that `SecurityPolicyUriLength` shall not exceed 255 bytes. The implementation decodes the field using `UAString::decode` and does not check this limit.
16. **No cryptographic verification of abort chunks** ([tcp.rs:473](file:///home/quackdcs/async-opcua/async-opcua-server/src/transport/tcp.rs#L473)): The spec states that an abort chunk is signed and encrypted if the channel security is enabled. The server processes `FinalError` chunks and clears its pending chunks buffer immediately *before* executing the cryptographic signature and decryption checks (`verify_and_remove_security_server`), allowing unauthenticated spoofing to disrupt message assembly.

---

## Detailed Findings Table

### 1. Binary Decode Robustness / Bounds

| Rule | Spec §/line | Impl file:line | Status | Notes |
| :--- | :--- | :--- | :--- | :--- |
| String pre-allocation bounding | §5.2.2.4 / 1595–1606 | [string.rs:131](file:///home/quackdcs/async-opcua/async-opcua-types/src/string.rs#L131) | **CANDIDATE DIVERGENCE** | `UAString::decode` performs eager allocation of a buffer of size `len` using `vec![0u8; len]` before verifying if the stream contains that many bytes, creating an OOM vector. |
| ByteString decoding bounds | §5.2.2.7 / 1669–1674 | [byte_string.rs:168](file:///home/quackdcs/async-opcua/async-opcua-types/src/byte_string.rs#L168) | **HONORED** | Limits length to `max_byte_string_length` and uses `stream.take().read_to_end()` to safely bound memory allocation to actual bytes received. |
| Array pre-allocation bounding | §5.2.5 / 2092–2100 | [encoding.rs:620](file:///home/quackdcs/async-opcua/async-opcua-types/src/encoding.rs#L620) | **HONORED** | Limits length to `max_array_length` before processing elements. |
| Nesting / Recursion depth bounding | §5.2.2.12 / 1867–1870 | [diagnostic_info.rs:233](file:///home/quackdcs/async-opcua/async-opcua-types/src/diagnostic_info.rs#L233) | **HONORED** | Uses `depth_lock()` which limits nesting to `MAX_DECODING_DEPTH` (default 10) for Variant, ExtensionObject, and DiagnosticInfo. |
| ExtensionObject body size validation | §5.2.2.15 / 1932–1953 | [extension_object.rs:21](file:///home/quackdcs/async-opcua/async-opcua-types/src/extension_object.rs#L21) | **HONORED** | Uses `validate_body_size` to reject sizes larger than `max_message_size` before decoding. |

### 2. Binary Encode/Decode Correctness for Built-in Types

| Rule | Spec §/line | Impl file:line | Status | Notes |
| :--- | :--- | :--- | :--- | :--- |
| Boolean decoding (non-zero as true) | §5.2.2.1 / 1539–1545 | [basic_types.rs:46](file:///home/quackdcs/async-opcua/async-opcua-types/src/basic_types.rs#L46) | **CANDIDATE DIVERGENCE** | Strictly decodes `read_u8(stream)? == 1` instead of treating all non-zero values as true. |
| Variant array and matrix dimensions | §5.2.2.16 / 2035–2037 | [variant/mod.rs:456](file:///home/quackdcs/async-opcua/async-opcua-types/src/variant/mod.rs#L456) | **HONORED** | Raises `Bad_DecodingError` if array dimensions are inconsistent with `ArrayLength`. |
| Variant reserved type IDs 26-31 | §5.2.2.16 / 2005–2008 | [type_id.rs:260](file:///home/quackdcs/async-opcua/async-opcua-types/src/variant/type_id.rs#L260) | **CANDIDATE DIVERGENCE** | Returns `None` (unrecognized encoding mask) for arrays, or parses as `Variant::Empty` for scalars, instead of treating them as `ByteString`. |
| DataValue picoseconds clamp | §5.2.2.17 / 2079–2080 | [data_value.rs:227](file:///home/quackdcs/async-opcua/async-opcua-types/src/data_value.rs#L227) | **CANDIDATE DIVERGENCE** | Does not clamp picoseconds values `>= 10000` to `9999`. |
| DiagnosticInfo recursion level | §5.2.2.12 / 1867–1870 | [diagnostic_info.rs:233](file:///home/quackdcs/async-opcua/async-opcua-types/src/diagnostic_info.rs#L233) | **HONORED** | Limits recursion depth to 10 via `depth_lock()`, conforming to the spec suggestion of between 4 and 10 levels. |
| 4 NodeId formats support | §5.2.2.9 / 1716–1720 | [node_id/mod.rs:134](file:///home/quackdcs/async-opcua/async-opcua-types/src/node_id/mod.rs#L134) | **HONORED** | Correctly supports decoding Two Byte, Four Byte, Numeric, String, Guid, and ByteString representations. |
| Int64/UInt64 binary correctness | §5.2.2.2 / 1546–1548 | [basic_types.rs:21](file:///home/quackdcs/async-opcua/async-opcua-types/src/basic_types.rs#L21) | **HONORED** | Correctly encoded/decoded as little-endian 64-bit values. |

### 3. JSON Encoding/Decoding Correctness

| Rule | Spec §/line | Impl file:line | Status | Notes |
| :--- | :--- | :--- | :--- | :--- |
| Variant JSON field names and structure | §5.4.2.17 / 3243–3256 | [variant/json.rs:79](file:///home/quackdcs/async-opcua/async-opcua-types/src/variant/json.rs#L79) | **CANDIDATE DIVERGENCE** | Uses `"Type"` and `"Body"` in JSON serialization instead of `"UaType"` and `"Value"`. |
| NodeId/ExpandedNodeId STRING form | §5.4.2.10 / 3087–3090 | [node_id/json.rs:34](file:///home/quackdcs/async-opcua/async-opcua-types/src/node_id/json.rs#L34) | **CANDIDATE DIVERGENCE** | Encodes NodeId and ExpandedNodeId as JSON objects rather than JSON strings per 5.1.12. |
| Int64/UInt64 JSON decimal strings | §5.4.2.3 / 3035–3037 | [json.rs:235](file:///home/quackdcs/async-opcua/async-opcua-types/src/json.rs#L235) | **CANDIDATE DIVERGENCE** | Encodes 64-bit integers as JSON numbers instead of JSON strings. |
| ExtensionObject JSON format | §5.4.2.16 / 3202–3211 | [extension_object.rs:283](file:///home/quackdcs/async-opcua/async-opcua-types/src/extension_object.rs#L283) | **CANDIDATE DIVERGENCE** | Always nests JSON structure fields inside a `"UaBody"` key instead of placing them directly at the top level of the JSON object. |
| Duplicate JSON field name rejection | §5.4.2.16 / 3213–3214 | [node_id/json.rs:91](file:///home/quackdcs/async-opcua/async-opcua-types/src/node_id/json.rs#L91) | **CANDIDATE DIVERGENCE** | JSON object decoders silently overwrite values on duplicate names instead of raising decoding errors. |
| JSON array-length bounding (DoS) | §5.4.5 / 3324–3325 | [json.rs:122](file:///home/quackdcs/async-opcua/async-opcua-types/src/json.rs#L122) | **CANDIDATE DIVERGENCE** | Reads arrays dynamically in a loop without checking if the length exceeds `max_array_length`. |

### 4. Transport Protocol Conformance

| Rule | Spec §/line | Impl file:line | Status | Notes |
| :--- | :--- | :--- | :--- | :--- |
| Hello limit size negotiation (0 = unlimited) | §7.1.2.3 / 5273–5279 | [tcp.rs:116](file:///home/quackdcs/async-opcua/async-opcua-server/src/transport/tcp.rs#L116) | **CANDIDATE DIVERGENCE** | `effective_max_chunk_count` resolves `(0, 0)` as `1` instead of treating it as unlimited. |
| Buffer sizes (ECC 1024 vs 8192) | §7.1.2.3 / 5262–5267 | [tcp_types.rs:341](file:///home/quackdcs/async-opcua/async-opcua-core/src/comms/tcp_types.rs#L341) | **CANDIDATE DIVERGENCE** | Hello validation unconditionally rejects buffer sizes < 8192 bytes, ignoring the 1024-byte minimum allowed when utilizing ECC. |
| Error Message reason size check | §7.1.2.5 / 5341–5343 | [tcp_types.rs:445](file:///home/quackdcs/async-opcua/async-opcua-core/src/comms/tcp_types.rs#L445) | **CANDIDATE DIVERGENCE** | `ErrorMessage::decode` does not check or restrict the error reason string length to <= 4096 bytes. |
| ReverseHello string limits | §7.1.2.6 / 5356–5360 | [tcp_types.rs:502](file:///home/quackdcs/async-opcua/async-opcua-core/src/comms/tcp_types.rs#L502) | **CANDIDATE DIVERGENCE** | Does not validate that incoming `ReverseHelloMessage` server/endpoint URIs are <= 4096 bytes. |
| SecurityPolicyUri length validation | §6.7.2.3 / Table 58 | [security_header.rs:142](file:///home/quackdcs/async-opcua/async-opcua-core/src/comms/security_header.rs#L142) | **CANDIDATE DIVERGENCE** | Does not validate that asymmetric security header's `SecurityPolicyUri` length is <= 255. |
| Chunker sequence numbers wrap-around | §6.7.2.4 / 4332–4340 | [sequence_number.rs:89](file:///home/quackdcs/async-opcua/async-opcua-core/src/comms/sequence_number.rs#L89) | **HONORED** | Correctly validates legacy and standard sequence number wrap-around limits. |
| Abort chunk signature verification | §6.7.3 / 4412–4437 | [tcp.rs:473](file:///home/quackdcs/async-opcua/async-opcua-server/src/transport/tcp.rs#L473) | **CANDIDATE DIVERGENCE** | Clears the pending buffer for `FinalError` chunks *before* verification, bypassing signature and decryption verification checks under active security. |
