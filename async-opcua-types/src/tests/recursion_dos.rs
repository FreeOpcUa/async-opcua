//! Regression tests for finding C1: unbounded-recursion stack overflows on the binary
//! decode path. A single crafted message must be rejected by the decoding-depth guard
//! (`DecodingOptions::depth_lock`) instead of recursing until the stack overflows.
//!
//! `constants::MAX_DECODING_DEPTH` is 10, so payloads nested well beyond that must error.

use std::io::Cursor;

use crate::{BinaryDecodable, BinaryEncodable, ContextOwned, DataValue, DiagnosticInfo, Variant};

/// `DiagnosticInfo::decode` recurses on the `HAS_INNER_DIAGNOSTIC_INFO` (0x40) branch.
/// A run of 0x40 bytes forces one recursion level each; the depth guard must stop it.
#[test]
fn diagnostic_info_deep_nesting_is_bounded() {
    let payload = vec![0x40u8; 64]; // far beyond MAX_DECODING_DEPTH (10)
    let ctx_f = ContextOwned::default();
    let ctx = ctx_f.context();
    let mut stream = Cursor::new(payload);
    let res = DiagnosticInfo::decode(&mut stream, &ctx);
    assert!(
        res.is_err(),
        "deeply nested DiagnosticInfo must hit the decoding-depth limit, got {res:?}"
    );
}

/// The `DataValue` <-> `Variant` cycle (`DataValue` holds a `Variant`, the `Variant`
/// `DataValue` branch decodes a `DataValue`) must be bounded by the depth guard.
#[test]
fn data_value_variant_cycle_is_bounded() {
    let ctx_f = ContextOwned::default();
    let ctx = ctx_f.context();

    // Build a DataValue nested via Variant::DataValue well beyond MAX_DECODING_DEPTH.
    // Construction is iterative; encode recurses only ~32 deep, which is safe.
    let mut dv = DataValue::null();
    for _ in 0..32 {
        dv = DataValue::value_only(Variant::DataValue(Box::new(dv)));
    }
    let mut buf = Vec::new();
    dv.encode(&mut buf, &ctx).expect("encode of bounded-depth value");

    let mut stream = Cursor::new(buf);
    let res = DataValue::decode(&mut stream, &ctx);
    assert!(
        res.is_err(),
        "deeply nested DataValue/Variant cycle must hit the decoding-depth limit, got {res:?}"
    );
}
