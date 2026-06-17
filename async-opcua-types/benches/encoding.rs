//! Binary encode/decode benchmarks (feature 009 / FR-030 / PERF-P12).
//!
//! Covers the hot paths exercised by the transmit/receive code: a small request
//! message, a large primitive array `DataValue` (the PERF-P5/P10 fan-out path), and
//! a big `ByteString` (the `Bytes`-backed zero-copy decode path, PERF-P5).
#![allow(missing_docs)] // bench harness (criterion_main!) generates undocumented items

use std::io::Cursor;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use opcua_types::{
    BinaryDecodable, BinaryEncodable, ByteString, Context, ContextOwned, DataValue,
    DecodingOptions, NamespaceMap, NodeId, ReadRequest, ReadValueId, RequestHeader,
    TimestampsToReturn, Variant,
};

/// A permissive decode context — real servers raise array/byte-string limits well
/// above the conservative defaults, so the large fixtures below decode successfully.
fn permissive_context() -> ContextOwned {
    let mut options = DecodingOptions::default();
    options.max_array_length = 1_000_000;
    options.max_byte_string_length = 8 * 1024 * 1024;
    options.max_string_length = 8 * 1024 * 1024;
    ContextOwned::new_default(NamespaceMap::new(), options)
}

fn small_read_request() -> ReadRequest {
    ReadRequest {
        request_header: RequestHeader::dummy(),
        max_age: 0.0,
        timestamps_to_return: TimestampsToReturn::Both,
        nodes_to_read: Some(vec![ReadValueId {
            node_id: NodeId::new(1, 1),
            attribute_id: 13,
            ..Default::default()
        }]),
    }
}

fn large_array_data_value() -> DataValue {
    // 10k-element Int32 array — representative of a large variable read / notification.
    DataValue::value_only(Variant::from((0i32..10_000).collect::<Vec<i32>>()))
}

fn big_byte_string() -> DataValue {
    // 1 MiB ByteString — exercises the Bytes-backed zero-copy decode path.
    DataValue::value_only(Variant::from(ByteString::from(vec![0xABu8; 1024 * 1024])))
}

fn encode_to_vec<T: BinaryEncodable>(value: &T, ctx: &Context<'_>) -> Vec<u8> {
    let mut buf = Cursor::new(vec![0u8; value.byte_len(ctx)]);
    value.encode(&mut buf, ctx).expect("encode");
    buf.into_inner()
}

fn bench_encoding(c: &mut Criterion) {
    let ctx_f = permissive_context();
    let ctx = ctx_f.context();

    let request = small_read_request();
    let array = large_array_data_value();
    let bytes = big_byte_string();

    let request_bin = encode_to_vec(&request, &ctx);
    let array_bin = encode_to_vec(&array, &ctx);
    let bytes_bin = encode_to_vec(&bytes, &ctx);

    let mut enc = c.benchmark_group("encode");
    enc.bench_function(BenchmarkId::from_parameter("small_read_request"), |b| {
        b.iter(|| std::hint::black_box(encode_to_vec(&request, &ctx)))
    });
    enc.bench_function(BenchmarkId::from_parameter("large_array_data_value"), |b| {
        b.iter(|| std::hint::black_box(encode_to_vec(&array, &ctx)))
    });
    enc.bench_function(BenchmarkId::from_parameter("big_byte_string_1mib"), |b| {
        b.iter(|| std::hint::black_box(encode_to_vec(&bytes, &ctx)))
    });
    enc.finish();

    let mut dec = c.benchmark_group("decode");
    dec.bench_function(BenchmarkId::from_parameter("small_read_request"), |b| {
        b.iter(|| {
            let mut cur = Cursor::new(request_bin.as_slice());
            std::hint::black_box(ReadRequest::decode(&mut cur, &ctx).expect("decode request"))
        })
    });
    dec.bench_function(BenchmarkId::from_parameter("large_array_data_value"), |b| {
        b.iter(|| {
            let mut cur = Cursor::new(array_bin.as_slice());
            std::hint::black_box(DataValue::decode(&mut cur, &ctx).expect("decode array"))
        })
    });
    dec.bench_function(BenchmarkId::from_parameter("big_byte_string_1mib"), |b| {
        b.iter(|| {
            let mut cur = Cursor::new(bytes_bin.as_slice());
            std::hint::black_box(DataValue::decode(&mut cur, &ctx).expect("decode bytes"))
        })
    });
    dec.finish();
}

criterion_group!(benches, bench_encoding);
criterion_main!(benches);
