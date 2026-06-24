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
