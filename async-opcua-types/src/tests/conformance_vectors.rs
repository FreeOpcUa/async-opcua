//! Cross-stack encoding conformance: decode the OPC Foundation reference stack's own golden binary
//! vectors with async-opcua and confirm they re-encode byte-for-byte identically.
//!
//! The vectors under `vectors/opcfoundation/builtin_binary/` are the libFuzzer seed corpus from the
//! OPC UA .NET Standard reference stack (`Fuzzing/Opc.Ua.Encoders.Fuzz.Corpus/Testcases.BuiltInTypes/
//! Binary/`), where each file is a bare OPC UA Binary encoding of one Built-in type (Part 6 §5.2).
//! Decoding the reference encoder's output and re-encoding to the exact same bytes is a strong,
//! independent check that our Binary codec agrees with the reference implementation. Vendored MIT;
//! see `vectors/opcfoundation/PROVENANCE.md`.

use crate::{
    BinaryDecodable, BinaryEncodable, ContextOwned, DataValue, DiagnosticInfo, ExpandedNodeId,
    ExtensionObject, LocalizedText, NodeId, QualifiedName, Variant,
};

/// Decode `bytes` as `T`, require the whole input to be consumed, then re-encode and require the
/// output to be byte-identical to the reference vector.
fn assert_vector_roundtrips<T: BinaryDecodable + BinaryEncodable>(name: &str, bytes: &[u8]) {
    let ctx_owned = ContextOwned::default();
    let ctx = ctx_owned.context();

    let mut stream = bytes;
    let decoded =
        T::decode(&mut stream, &ctx).unwrap_or_else(|e| panic!("{name}: decode failed: {e}"));
    assert!(
        stream.is_empty(),
        "{name}: {} trailing byte(s) left after decoding the reference vector",
        stream.len()
    );

    let reencoded = decoded.encode_to_vec(&ctx);
    assert_eq!(
        reencoded, bytes,
        "{name}: re-encoded bytes differ from the OPC Foundation reference vector\n  ref = {bytes:02x?}\n  ours= {reencoded:02x?}"
    );
}

macro_rules! vector_test {
    ($fn_name:ident, $ty:ty, $file:literal) => {
        #[test]
        fn $fn_name() {
            assert_vector_roundtrips::<$ty>(
                $file,
                include_bytes!(concat!(
                    "vectors/opcfoundation/builtin_binary/",
                    $file,
                    ".bin"
                )),
            );
        }
    };
}

vector_test!(opcf_binary_nodeid, NodeId, "nodeid");
vector_test!(opcf_binary_expandednodeid, ExpandedNodeId, "expandednodeid");
vector_test!(opcf_binary_qualifiedname, QualifiedName, "qualifiedname");
vector_test!(opcf_binary_localizedtext, LocalizedText, "localizedtext");
vector_test!(opcf_binary_variant, Variant, "variant");
vector_test!(opcf_binary_datavalue, DataValue, "datavalue");
vector_test!(opcf_binary_diagnosticinfo, DiagnosticInfo, "diagnosticinfo");
vector_test!(
    opcf_binary_extensionobject,
    ExtensionObject,
    "extensionobject"
);

// --- String-parser conformance ---------------------------------------------------------------
//
// The OPC Foundation reference stack's parser fuzz corpus (`Testcases.Parsers/`) seeds each parser
// with a canonical, valid string. async-opcua must parse the exact same syntax (Part 6 §5.3.1.x for
// NodeId/ExpandedNodeId; Part 4 §7.27 for NumericRange). These are the canonical valid forms, so
// parsing MUST succeed and (where a Display inverse exists) round-trip. Strings inlined verbatim from
// the corpus (commit 147c287, BOM stripped — it is a file-encoding artifact, not part of the value).

use crate::{Guid, NumericRange};
use std::str::FromStr;

#[test]
fn opcf_parse_nodeid() {
    // nodeid_numeric / nodeid_string / nodeid_guid
    assert_eq!(NodeId::from_str("i=85").unwrap(), NodeId::new(0u16, 85u32));
    assert_eq!(
        NodeId::from_str("ns=2;s=Demo.Node").unwrap(),
        NodeId::new(2u16, "Demo.Node")
    );
    let guid = NodeId::from_str("ns=2;g=00000000-0000-0000-0000-000000000001").unwrap();
    assert_eq!(guid.namespace, 2);
    // Display must round-trip back to the same NodeId.
    assert_eq!(NodeId::from_str(&guid.to_string()).unwrap(), guid);
}

#[test]
fn opcf_parse_expanded_nodeid() {
    // expandednodeid_string / expandednodeid_uri — both canonical valid forms must parse.
    let by_uri = ExpandedNodeId::from_str("nsu=urn:example:namespace;s=Demo").unwrap();
    assert_eq!(by_uri.namespace_uri.as_ref(), "urn:example:namespace");
    let with_server =
        ExpandedNodeId::from_str("svr=1;nsu=http://opcfoundation.org/UA/;i=85").unwrap();
    assert_eq!(with_server.server_index, 1);
}

#[test]
fn opcf_parse_numeric_range() {
    // numericrange_single ("0") / numericrange_matrix ("0:10,1:2")
    NumericRange::from_str("0").expect("single index range must parse");
    let matrix = NumericRange::from_str("0:10,1:2").expect("multi-dimension range must parse");
    // Display must round-trip back to an equal range.
    assert_eq!(NumericRange::from_str(&matrix.to_string()).unwrap(), matrix);
}

#[test]
fn opcf_parse_guid() {
    // uuid
    let g = Guid::from_str("00000000-0000-0000-0000-000000000001").unwrap();
    assert_eq!(Guid::from_str(&g.to_string()).unwrap(), g);
}
