//! Enabled with the "json" feature.
//!
//! Core utilities for JSON encoding and decoding from OPC-UA JSON.

use std::io::{Cursor, Read, Write};

pub use crate::Context;
use struson::writer::JsonNumberError;
pub use struson::{
    json_path,
    reader::{JsonReader, JsonStreamReader, ValueType},
    writer::{JsonStreamWriter, JsonWriter},
};

use crate::{EncodingResult, Error, UaNullable};

/// Trait for OPC-UA json encoding.
pub trait JsonEncodable: UaNullable {
    #[allow(unused)]
    /// Write the type to the provided JSON writer.
    fn encode(
        &self,
        stream: &mut JsonStreamWriter<&mut dyn Write>,
        ctx: &crate::Context<'_>,
    ) -> EncodingResult<()>;
}

impl From<struson::reader::ReaderError> for Error {
    fn from(value: struson::reader::ReaderError) -> Self {
        Self::decoding(value)
    }
}

impl From<JsonNumberError> for Error {
    fn from(value: JsonNumberError) -> Self {
        Self::encoding(value)
    }
}

impl From<struson::reader::TransferError> for Error {
    fn from(value: struson::reader::TransferError) -> Self {
        Self::decoding(value)
    }
}

/// Trait for decoding a type from a JSON stream.
pub trait JsonDecodable: Sized {
    #[allow(unused)]
    /// Decode Self from a JSON stream.
    fn decode(
        stream: &mut JsonStreamReader<&mut dyn Read>,
        ctx: &Context<'_>,
    ) -> EncodingResult<Self>;
}

impl<T> JsonEncodable for Option<T>
where
    T: JsonEncodable,
{
    fn encode(
        &self,
        stream: &mut JsonStreamWriter<&mut dyn Write>,
        ctx: &crate::Context<'_>,
    ) -> EncodingResult<()> {
        match self {
            Some(s) => s.encode(stream, ctx),
            None => Ok(stream.null_value()?),
        }
    }
}

impl<T> JsonDecodable for Option<T>
where
    T: JsonDecodable,
{
    fn decode(
        stream: &mut JsonStreamReader<&mut dyn Read>,
        ctx: &Context<'_>,
    ) -> EncodingResult<Self> {
        match stream.peek()? {
            ValueType::Null => {
                stream.next_null()?;
                Ok(None)
            }
            _ => Ok(Some(T::decode(stream, ctx)?)),
        }
    }
}

impl<T> JsonEncodable for Vec<T>
where
    T: JsonEncodable,
{
    fn encode(
        &self,
        stream: &mut JsonStreamWriter<&mut dyn Write>,
        ctx: &crate::Context<'_>,
    ) -> EncodingResult<()> {
        stream.begin_array()?;
        for elem in self {
            elem.encode(stream, ctx)?;
        }
        stream.end_array()?;
        Ok(())
    }
}

impl<T> JsonDecodable for Vec<T>
where
    T: JsonDecodable,
{
    fn decode(
        stream: &mut JsonStreamReader<&mut dyn Read>,
        ctx: &Context<'_>,
    ) -> EncodingResult<Self> {
        if stream.peek()? == ValueType::Null {
            stream.next_null()?;
            return Ok(Vec::new());
        }

        let mut res = Vec::new();
        stream.begin_array()?;
        while stream.has_next()? {
            res.push(T::decode(stream, ctx)?);
        }
        stream.end_array()?;

        Ok(res)
    }
}

impl<T> JsonEncodable for Box<T>
where
    T: JsonEncodable,
{
    fn encode(
        &self,
        stream: &mut JsonStreamWriter<&mut dyn Write>,
        ctx: &crate::Context<'_>,
    ) -> EncodingResult<()> {
        T::encode(self, stream, ctx)
    }
}

impl<T> JsonDecodable for Box<T>
where
    T: JsonDecodable,
{
    fn decode(
        stream: &mut JsonStreamReader<&mut dyn Read>,
        ctx: &Context<'_>,
    ) -> EncodingResult<Self> {
        Ok(Box::new(T::decode(stream, ctx)?))
    }
}

const VALUE_INFINITY: &str = "Infinity";
const VALUE_NEG_INFINITY: &str = "-Infinity";
const VALUE_NAN: &str = "NaN";

macro_rules! json_enc_float {
    ($t:ty) => {
        impl JsonEncodable for $t {
            fn encode(
                &self,
                stream: &mut JsonStreamWriter<&mut dyn Write>,
                _ctx: &crate::Context<'_>,
            ) -> EncodingResult<()> {
                if self.is_infinite() {
                    if self.is_sign_positive() {
                        stream.string_value(VALUE_INFINITY)?;
                    } else {
                        stream.string_value(VALUE_NEG_INFINITY)?;
                    }
                } else if self.is_nan() {
                    stream.string_value(VALUE_NAN)?;
                } else {
                    stream.fp_number_value(*self)?;
                }

                Ok(())
            }
        }

        impl JsonDecodable for $t {
            fn decode(
                stream: &mut JsonStreamReader<&mut dyn Read>,
                _ctx: &Context<'_>,
            ) -> EncodingResult<Self> {
                if stream.peek()? == ValueType::String {
                    let v = stream.next_str()?;
                    match v {
                        VALUE_INFINITY => Ok(Self::INFINITY),
                        VALUE_NEG_INFINITY => Ok(Self::NEG_INFINITY),
                        VALUE_NAN => Ok(Self::NAN),
                        // Not technically spec, but to optimize interoperability, try to
                        // parse the number as a float
                        r => Ok(r.parse()?),
                    }
                } else {
                    Ok(stream.next_number()??)
                }
            }
        }
    };
}

macro_rules! json_enc_number {
    ($t:ty) => {
        impl JsonEncodable for $t {
            fn encode(
                &self,
                stream: &mut JsonStreamWriter<&mut dyn Write>,
                _ctx: &crate::Context<'_>,
            ) -> EncodingResult<()> {
                stream.number_value(*self)?;
                Ok(())
            }
        }

        impl JsonDecodable for $t {
            fn decode(
                stream: &mut JsonStreamReader<&mut dyn Read>,
                _ctx: &Context<'_>,
            ) -> EncodingResult<Self> {
                Ok(stream.next_number()??)
            }
        }
    };
}

json_enc_number!(u8);
json_enc_number!(u16);
json_enc_number!(u32);
json_enc_number!(u64);
json_enc_number!(i8);
json_enc_number!(i16);
json_enc_number!(i32);
json_enc_number!(i64);
json_enc_float!(f32);
json_enc_float!(f64);

impl JsonEncodable for String {
    fn encode(
        &self,
        stream: &mut JsonStreamWriter<&mut dyn Write>,
        _ctx: &crate::Context<'_>,
    ) -> EncodingResult<()> {
        stream.string_value(self.as_str())?;
        Ok(())
    }
}

impl JsonDecodable for String {
    fn decode(
        stream: &mut JsonStreamReader<&mut dyn Read>,
        _ctx: &Context<'_>,
    ) -> EncodingResult<Self> {
        Ok(stream.next_string()?)
    }
}

impl JsonEncodable for bool {
    fn encode(
        &self,
        stream: &mut JsonStreamWriter<&mut dyn Write>,
        _ctx: &crate::Context<'_>,
    ) -> EncodingResult<()> {
        stream.bool_value(*self)?;
        Ok(())
    }
}

impl JsonDecodable for bool {
    fn decode(
        stream: &mut JsonStreamReader<&mut dyn Read>,
        _ctx: &Context<'_>,
    ) -> EncodingResult<Self> {
        Ok(stream.next_bool()?)
    }
}

/// Utility method used in unions to consume a JSON value from the stream,
/// and return it as a vector that can be parsed later.
pub fn consume_raw_value(
    r: &mut JsonStreamReader<&mut dyn std::io::Read>,
) -> EncodingResult<Vec<u8>> {
    let mut res = Vec::new();
    let cursor = Cursor::new(&mut res);
    let mut writer = JsonStreamWriter::new(cursor);
    r.transfer_to(&mut writer)?;
    writer.finish_document()?;
    Ok(res)
}
