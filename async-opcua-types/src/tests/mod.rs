mod date_time;
mod encoding;
mod fallback;
#[cfg(feature = "json")]
mod json;
mod node_id;
mod variant;
#[cfg(feature = "xml")]
mod xml;

use std::cmp::PartialEq;
use std::fmt::Debug;
use std::io::Cursor;

use crate::{
    argument::Argument, status_code::StatusCode, BinaryDecodable, BinaryEncodable, ContextOwned,
};

fn serialize_test_and_return<T>(value: T) -> T
where
    T: BinaryEncodable + BinaryDecodable + Debug + PartialEq + Clone,
{
    serialize_test_and_return_expected(value.clone(), value)
}

fn serialize_as_stream<T>(value: T) -> Cursor<Vec<u8>>
where
    T: BinaryEncodable + Debug,
{
    let ctx_f = ContextOwned::default();
    let ctx = ctx_f.context();
    // Ask the struct for its byte length
    let byte_len = value.byte_len(&ctx);
    let mut stream = Cursor::new(vec![0u8; byte_len]);

    // Encode to stream
    let start_pos = stream.position();
    value.encode(&mut stream, &ctx).expect("Encoding failed");
    let end_pos = stream.position();

    // Test that the position matches the byte_len
    assert_eq!((end_pos - start_pos) as usize, byte_len);

    let actual = stream.into_inner();
    println!("value = {value:?}");
    println!("encoded bytes = {actual:?}");
    Cursor::new(actual)
}

fn serialize_test_and_return_expected<T>(value: T, expected_value: T) -> T
where
    T: BinaryEncodable + BinaryDecodable + Debug + PartialEq,
{
    let mut stream = serialize_as_stream(value);

    let ctx_f = ContextOwned::default();
    let ctx = ctx_f.context();
    let new_value: T = T::decode(&mut stream, &ctx).unwrap();
    println!("new value = {new_value:?}");
    assert_eq!(expected_value, new_value);
    new_value
}

fn serialize_test<T>(value: T)
where
    T: BinaryEncodable + BinaryDecodable + Debug + PartialEq + Clone,
{
    let _ = serialize_test_and_return(value);
}

fn serialize_test_expected<T>(value: T, expected_value: T)
where
    T: BinaryEncodable + BinaryDecodable + Debug + PartialEq,
{
    let _ = serialize_test_and_return_expected(value, expected_value);
}

fn serialize_and_compare<T>(value: T, expected: &[u8])
where
    T: BinaryEncodable + Debug + PartialEq,
{
    let ctx_f = ContextOwned::default();
    let ctx = ctx_f.context();
    // Ask the struct for its byte length
    let byte_len = value.byte_len(&ctx);
    let mut stream = Cursor::new(vec![0; byte_len]);

    value.encode(&mut stream, &ctx).expect("Encoding failed");

    let actual = stream.into_inner();

    println!("actual {actual:?}");
    println!("expected {expected:?}");

    for i in 0..expected.len() {
        assert_eq!(actual[i], expected[i])
    }
}
