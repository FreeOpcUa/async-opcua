// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2024 Adam Lock

//! Contains the `BinaryEncodable` trait and helpers for reading and writing of scalar values and
//! other primitives.

use std::{
    error::Error as StdError,
    fmt::{Debug, Display},
    io::{Cursor, Read, Result, Write},
    sync::atomic::{AtomicU64, Ordering},
};

use byteorder::{ByteOrder, LittleEndian, WriteBytesExt};
use chrono::Duration;
use log::error;

use crate::{constants, status_code::StatusCode, Context, QualifiedName};

#[derive(Debug, Clone, Default)]
/// Parsed data encoding.
pub enum DataEncoding {
    #[default]
    /// Binary data decoding.
    Binary,
    /// XML data encoding.
    XML,
    /// JSON data encoding.
    JSON,
    /// Some other data encoding.
    Other(QualifiedName),
}

impl DataEncoding {
    /// Parse data encoding from the browse name in a service call.
    pub fn from_browse_name(name: QualifiedName) -> std::result::Result<Self, StatusCode> {
        match name.name.as_ref() {
            "Default Binary" | "" => Ok(Self::Binary),
            "Default XML" => Ok(Self::XML),
            "Default JSON" => Ok(Self::JSON),
            _ if name.namespace_index != 0 => Ok(Self::Other(name)),
            _ => Err(StatusCode::BadDataEncodingInvalid),
        }
    }
}

/// Result of an encoding or decoding operation.
pub type EncodingResult<T> = std::result::Result<T, Error>;

#[derive(Debug)]
/// General OPC-UA error.
///
/// Contains context about the request this error occured as part of, if that is possible to retrieve,
/// as well as details about the error that caused this, and a status code.
pub struct Error {
    status: StatusCode,
    request_id: Option<u32>,
    request_handle: Option<u32>,
    context: Box<dyn StdError + Send + Sync>,
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.status(), self.context)
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(&*self.context)
    }
}

impl Error {
    /// Create a new error with the specified `status` code and
    /// `context` as a dynamic error source.
    pub fn new(status: StatusCode, context: impl Into<Box<dyn StdError + Send + Sync>>) -> Self {
        Self {
            status,
            request_handle: None,
            request_id: None,
            context: context.into(),
        }
    }

    /// Create a new error with status code `BadDecodingError` and
    /// `context` as a dynamic error source.
    pub fn decoding(context: impl Into<Box<dyn StdError + Send + Sync>>) -> Self {
        Self {
            status: StatusCode::BadDecodingError,
            request_handle: None,
            request_id: None,
            context: context.into(),
        }
    }

    /// Create a new error with status code `BadEncodingError` and
    /// `context` as a dynamic error source.
    pub fn encoding(context: impl Into<Box<dyn StdError + Send + Sync>>) -> Self {
        Self {
            status: StatusCode::BadEncodingError,
            request_handle: None,
            request_id: None,
            context: context.into(),
        }
    }

    /// Add request ID and request handle to this error.
    pub fn with_context(mut self, request_id: Option<u32>, request_handle: Option<u32>) -> Self {
        self.request_id = request_id;
        self.request_handle = request_handle;
        self
    }

    /// Add request ID to this error.
    pub fn with_request_id(mut self, id: u32) -> Self {
        self.request_id = Some(id);
        self
    }

    /// Add request handle to this error.
    pub fn with_request_handle(mut self, handle: u32) -> Self {
        self.request_handle = Some(handle);
        self
    }

    /// Utility for setting request handle when it is _maybe_ initialized.
    pub fn maybe_with_request_handle(mut self, handle: Option<u32>) -> Self {
        if let Some(handle) = handle {
            self.request_handle = Some(handle);
        }
        self
    }

    /// Get the inner status code of this error.
    pub fn status(&self) -> StatusCode {
        self.status
    }

    /// Get the full context of this error, if both fields are present.
    pub fn full_context(&self) -> Option<(u32, u32)> {
        if let (Some(id), Some(handle)) = (self.request_id, self.request_handle) {
            Some((id, handle))
        } else {
            None
        }
    }
}

impl From<Error> for StatusCode {
    fn from(value: Error) -> Self {
        error!("{}", value);
        value.status()
    }
}

impl From<Error> for std::io::Error {
    fn from(value: Error) -> Self {
        value.status().into()
    }
}

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Self::decoding(value)
    }
}

/// Depth lock holds a reference on the depth gauge. The drop ensures impl that the reference is
/// decremented even if there is a panic unwind.
#[derive(Debug)]
pub struct DepthLock<'a> {
    depth_gauge: &'a DepthGauge,
}

impl Drop for DepthLock<'_> {
    fn drop(&mut self) {
        // This will overflow back if the gauge is somehow at 0. That really should not be possible, if it is only ever
        // incremented from `obtain`
        self.depth_gauge
            .current_depth
            .fetch_sub(1, Ordering::Release);
    }
}

impl<'a> DepthLock<'a> {
    fn new(depth_gauge: &'a DepthGauge) -> (Self, u64) {
        let current = depth_gauge.current_depth.fetch_add(1, Ordering::Acquire);

        (Self { depth_gauge }, current)
    }

    /// The depth lock tests if the depth can increment and then obtains a lock on it.
    /// The lock will decrement the depth when it drops to ensure proper behaviour during unwinding.
    pub fn obtain(depth_gauge: &'a DepthGauge) -> core::result::Result<DepthLock<'a>, Error> {
        let max_depth = depth_gauge.max_depth;
        let (gauge, val) = Self::new(depth_gauge);

        if val >= max_depth {
            Err(Error::decoding(
                "Decoding in stream aborted due maximum recursion depth being reached",
            ))
        } else {
            Ok(gauge)
        }
    }
}

/// Depth gauge is used on potentially recursive structures like Variant & ExtensionObject during
/// decoding to limit the depth the decoder will go before giving up.
#[derive(Debug)]
pub struct DepthGauge {
    /// Maximum decoding depth for recursive elements. Triggers when current depth equals max depth.
    pub(self) max_depth: u64,
    /// Current decoding depth for recursive elements.
    pub(self) current_depth: AtomicU64,
}

// TODO: In general keeping DepthGauge as part of DecodingOptions is suboptimal,
// since this pattern is unintuitive. It should be separated out.
impl Clone for DepthGauge {
    fn clone(&self) -> Self {
        Self {
            max_depth: self.max_depth,
            current_depth: AtomicU64::new(0),
        }
    }
}

impl Default for DepthGauge {
    fn default() -> Self {
        Self::new(constants::MAX_DECODING_DEPTH)
    }
}

impl DepthGauge {
    /// Create a new depth gauge with specified max depth.
    pub fn new(max_depth: u64) -> Self {
        Self {
            max_depth,
            current_depth: AtomicU64::new(0),
        }
    }

    /// Create a minimal depth gauge with max depth of 1.
    pub fn minimal() -> Self {
        Self {
            max_depth: 1,
            ..Default::default()
        }
    }

    /// Get the max depth of the gauge.
    pub fn max_depth(&self) -> u64 {
        self.max_depth
    }
}

#[derive(Clone, Debug)]
/// General decoding options.
pub struct DecodingOptions {
    /// Time offset between the client and the server, only used by the client when it's configured
    /// to ignore time skew.
    pub client_offset: Duration,
    /// Maximum size of a message in bytes. 0 means no limit.
    pub max_message_size: usize,
    /// Maximum number of chunks. 0 means no limit.
    pub max_chunk_count: usize,
    /// Maximum length in bytes (not chars!) of a string. 0 actually means 0, i.e. no string permitted
    pub max_string_length: usize,
    /// Maximum length in bytes of a byte string. 0 actually means 0, i.e. no byte string permitted
    pub max_byte_string_length: usize,
    /// Maximum number of array elements. 0 actually means 0, i.e. no array permitted
    pub max_array_length: usize,
    /// Decoding depth gauge is used to check for recursion
    pub decoding_depth_gauge: DepthGauge,
}

impl Default for DecodingOptions {
    fn default() -> Self {
        DecodingOptions {
            client_offset: Duration::zero(),
            max_message_size: constants::MAX_MESSAGE_SIZE,
            max_chunk_count: constants::MAX_CHUNK_COUNT,
            max_string_length: constants::MAX_STRING_LENGTH,
            max_byte_string_length: constants::MAX_BYTE_STRING_LENGTH,
            max_array_length: constants::MAX_ARRAY_LENGTH,
            decoding_depth_gauge: DepthGauge::default(),
        }
    }
}

impl DecodingOptions {
    /// This can be useful for decoding extension objects where the payload is not expected to contain
    /// a large value.
    pub fn minimal() -> Self {
        DecodingOptions {
            max_string_length: 8192,
            max_byte_string_length: 8192,
            max_array_length: 8192,
            decoding_depth_gauge: DepthGauge::minimal(),
            ..Default::default()
        }
    }

    /// For test only. Having a separate function makes it easier to control calls to DecodingOptions::default().
    pub fn test() -> Self {
        Self::default()
    }

    /// Get a lease on depth, this will fail if max depth is exceeded.
    /// Once the lease is dropped, current depth is decremented.
    pub fn depth_lock(&self) -> core::result::Result<DepthLock<'_>, Error> {
        DepthLock::obtain(&self.decoding_depth_gauge)
    }
}

/// Trait implemented by OPC-UA types, indicating whether
/// they are null or not, for use in encoding.
pub trait UaNullable {
    /// Return true if this value is null, meaning it can be left out when
    /// being encoded in JSON and XML encodings.
    fn is_ua_null(&self) -> bool {
        false
    }
}

impl<T> UaNullable for Option<T>
where
    T: UaNullable,
{
    fn is_ua_null(&self) -> bool {
        match self {
            Some(s) => s.is_ua_null(),
            None => true,
        }
    }
}

impl<T> UaNullable for Vec<T> where T: UaNullable {}
impl<T> UaNullable for Box<T>
where
    T: UaNullable,
{
    fn is_ua_null(&self) -> bool {
        self.as_ref().is_ua_null()
    }
}

macro_rules! is_null_const {
    ($t:ty, $c:expr) => {
        impl UaNullable for $t {
            fn is_ua_null(&self) -> bool {
                *self == $c
            }
        }
    };
}

is_null_const!(bool, false);
is_null_const!(u8, 0);
is_null_const!(u16, 0);
is_null_const!(u32, 0);
is_null_const!(u64, 0);
is_null_const!(i8, 0);
is_null_const!(i16, 0);
is_null_const!(i32, 0);
is_null_const!(i64, 0);
is_null_const!(f32, 0.0);
is_null_const!(f64, 0.0);

impl UaNullable for String {}
impl UaNullable for str {}

/// OPC UA Binary Encoding interface. Anything that encodes to binary must implement this. It provides
/// functions to calculate the size in bytes of the struct (for allocating memory), encoding to a stream
/// and decoding from a stream.
///
/// # Implementing
///
/// The majority of implementers should just use the `derive(BinaryEncodable)` macro,
/// if you need to implement this yourself for some reason, the following _must_ be satisfied:
///
///  - `byte_len` must return a length exactly equal to what `encode` will write, or `encode`
///    must be guaranteed to fail. Since `byte_len` is infallible, you are allowed to
///    return some invalid value there, then fail later when calling `encode`. This should be avoided.
///  - `encode` must use `write_all` on the stream, not just `write`, to ensure that all the data
///    is written, even if the stream is interrupted. Prefer calling `encode` on inner types
///    instead.
pub trait BinaryEncodable {
    /// Returns the exact byte length of the structure as it would be if `encode` were called.
    /// This may be called prior to writing to ensure the correct amount of space is available.
    #[allow(unused)]
    fn byte_len(&self, ctx: &crate::Context<'_>) -> usize;
    /// Encodes the instance to the write stream.
    fn encode<S: Write + ?Sized>(&self, stream: &mut S, ctx: &Context<'_>) -> EncodingResult<()>;

    /// Convenience method for encoding a message straight into an array of bytes. It is preferable to reuse buffers than
    /// to call this so it should be reserved for tests and trivial code.
    fn encode_to_vec(&self, ctx: &Context<'_>) -> Vec<u8> {
        let mut buffer = Cursor::new(Vec::with_capacity(self.byte_len(ctx)));
        let _ = self.encode(&mut buffer, ctx);
        buffer.into_inner()
    }
}

/// Trait for decoding a type from OPC UA binary.
pub trait BinaryDecodable: Sized {
    /// Decodes an instance from the read stream. The decoding options contains restrictions set by
    /// the server / client on the length of strings, arrays etc. If these limits are exceeded the
    /// implementation should return with a `BadDecodingError` as soon as possible.
    fn decode<S: Read + ?Sized>(stream: &mut S, ctx: &Context<'_>) -> EncodingResult<Self>;
}

/// Trait for encoding a type that cannot contain any custom types
/// to OPC UA binary. Used in some core modules to encode raw binary messages.
pub trait SimpleBinaryEncodable {
    #[allow(unused)]
    // Returns the exact byte length of the structure as it would be if `encode` were called.
    /// This may be called prior to writing to ensure the correct amount of space is available.
    fn byte_len(&self) -> usize;

    /// Encodes the instance to the write stream.
    fn encode<S: Write + ?Sized>(&self, stream: &mut S) -> EncodingResult<()>;

    /// Convenience method for encoding a message straight into an array of bytes. It is preferable to reuse buffers than
    /// to call this so it should be reserved for tests and trivial code.
    fn encode_to_vec(&self) -> Vec<u8> {
        let mut buffer = Cursor::new(Vec::with_capacity(self.byte_len()));
        let _ = self.encode(&mut buffer);
        buffer.into_inner()
    }
}

impl<T> BinaryEncodable for T
where
    T: SimpleBinaryEncodable,
{
    fn byte_len(&self, _ctx: &crate::Context<'_>) -> usize {
        SimpleBinaryEncodable::byte_len(self)
    }

    fn encode<S: Write + ?Sized>(&self, stream: &mut S, _ctx: &Context<'_>) -> EncodingResult<()> {
        SimpleBinaryEncodable::encode(self, stream)
    }
}

/// Trait for decoding a type that cannot contain any custom types
/// from OPC UA binary. Used in some core modules to decode raw binary messages.
pub trait SimpleBinaryDecodable: Sized {
    /// Decode Self from the byte stream.
    fn decode<S: Read + ?Sized>(
        stream: &mut S,
        decoding_options: &DecodingOptions,
    ) -> EncodingResult<Self>;
}

impl<T> BinaryDecodable for T
where
    T: SimpleBinaryDecodable,
{
    fn decode<S: Read + ?Sized>(stream: &mut S, ctx: &Context<'_>) -> EncodingResult<Self> {
        SimpleBinaryDecodable::decode(stream, ctx.options())
    }
}

/// Converts an IO encoding error (and logs when in error) into an EncodingResult
pub fn process_encode_io_result(result: Result<()>) -> EncodingResult<()> {
    result.map_err(Error::encoding)
}

/// Converts an IO encoding error (and logs when in error) into an EncodingResult
pub fn process_decode_io_result<T>(result: Result<T>) -> EncodingResult<T>
where
    T: Debug,
{
    result.map_err(Error::decoding)
}

impl<T> BinaryEncodable for Option<Vec<T>>
where
    T: BinaryEncodable,
{
    fn byte_len(&self, ctx: &crate::Context<'_>) -> usize {
        let mut size = 4;
        if let Some(ref values) = self {
            size += values.iter().map(|v| v.byte_len(ctx)).sum::<usize>();
        }
        size
    }

    fn encode<S: Write + ?Sized>(&self, stream: &mut S, ctx: &Context<'_>) -> EncodingResult<()> {
        if let Some(ref values) = self {
            write_i32(stream, values.len() as i32)?;
            for value in values.iter() {
                value.encode(stream, ctx)?;
            }
        } else {
            write_i32(stream, -1)?;
        }
        Ok(())
    }
}

impl<T> BinaryDecodable for Option<Vec<T>>
where
    T: BinaryDecodable,
{
    fn decode<S: Read + ?Sized>(
        stream: &mut S,
        ctx: &Context<'_>,
    ) -> EncodingResult<Option<Vec<T>>> {
        let len = read_i32(stream)?;
        if len == -1 {
            Ok(None)
        } else if len < -1 {
            Err(Error::decoding(
                "Array length is negative value and invalid",
            ))
        } else if len as usize > ctx.options().max_array_length {
            Err(Error::decoding(format!(
                "Array length {} exceeds decoding limit {}",
                len,
                ctx.options().max_array_length
            )))
        } else {
            let mut values: Vec<T> = Vec::with_capacity(len as usize);
            for _ in 0..len {
                values.push(T::decode(stream, ctx)?);
            }
            Ok(Some(values))
        }
    }
}

/// Calculates the length in bytes of an array of encoded type
pub fn byte_len_array<T: BinaryEncodable>(values: &Option<Vec<T>>, ctx: &Context<'_>) -> usize {
    let mut size = 4;
    if let Some(ref values) = values {
        size += values.iter().map(|v| v.byte_len(ctx)).sum::<usize>();
    }
    size
}

/// Writes a series of identical bytes to the stream
pub fn write_bytes<W: Write + ?Sized>(
    stream: &mut W,
    value: u8,
    count: usize,
) -> EncodingResult<usize> {
    for _ in 0..count {
        stream.write_u8(value).map_err(Error::encoding)?;
    }
    Ok(count)
}

/// Writes an unsigned byte to the stream
pub fn write_u8<T, W: Write + ?Sized>(stream: &mut W, value: T) -> EncodingResult<()>
where
    T: Into<u8>,
{
    let buf: [u8; 1] = [value.into()];
    process_encode_io_result(stream.write_all(&buf))
}

/// Writes a signed 16-bit value to the stream
pub fn write_i16<T, W: Write + ?Sized>(stream: &mut W, value: T) -> EncodingResult<()>
where
    T: Into<i16>,
{
    let mut buf = [0u8; 2];
    LittleEndian::write_i16(&mut buf, value.into());
    process_encode_io_result(stream.write_all(&buf))
}

/// Writes an unsigned 16-bit value to the stream
pub fn write_u16<T, W: Write + ?Sized>(stream: &mut W, value: T) -> EncodingResult<()>
where
    T: Into<u16>,
{
    let mut buf = [0u8; 2];
    LittleEndian::write_u16(&mut buf, value.into());
    process_encode_io_result(stream.write_all(&buf))
}

/// Writes a signed 32-bit value to the stream
pub fn write_i32<T, W: Write + ?Sized>(stream: &mut W, value: T) -> EncodingResult<()>
where
    T: Into<i32>,
{
    let mut buf = [0u8; 4];
    LittleEndian::write_i32(&mut buf, value.into());
    process_encode_io_result(stream.write_all(&buf))
}

/// Writes an unsigned 32-bit value to the stream
pub fn write_u32<T, W: Write + ?Sized>(stream: &mut W, value: T) -> EncodingResult<()>
where
    T: Into<u32>,
{
    let mut buf = [0u8; 4];
    LittleEndian::write_u32(&mut buf, value.into());
    process_encode_io_result(stream.write_all(&buf))
}

/// Writes a signed 64-bit value to the stream
pub fn write_i64<T, W: Write + ?Sized>(stream: &mut W, value: T) -> EncodingResult<()>
where
    T: Into<i64>,
{
    let mut buf = [0u8; 8];
    LittleEndian::write_i64(&mut buf, value.into());
    process_encode_io_result(stream.write_all(&buf))
}

/// Writes an unsigned 64-bit value to the stream
pub fn write_u64<T, W: Write + ?Sized>(stream: &mut W, value: T) -> EncodingResult<()>
where
    T: Into<u64>,
{
    let mut buf = [0u8; 8];
    LittleEndian::write_u64(&mut buf, value.into());
    process_encode_io_result(stream.write_all(&buf))
}

/// Writes a 32-bit precision value to the stream
pub fn write_f32<T, W: Write + ?Sized>(stream: &mut W, value: T) -> EncodingResult<()>
where
    T: Into<f32>,
{
    let mut buf = [0u8; 4];
    LittleEndian::write_f32(&mut buf, value.into());
    process_encode_io_result(stream.write_all(&buf))
}

/// Writes a 64-bit precision value to the stream
pub fn write_f64<T, W: Write + ?Sized>(stream: &mut W, value: T) -> EncodingResult<()>
where
    T: Into<f64>,
{
    let mut buf = [0u8; 8];
    LittleEndian::write_f64(&mut buf, value.into());
    process_encode_io_result(stream.write_all(&buf))
}

/// Reads an array of bytes from the stream
pub fn read_bytes<R: Read + ?Sized>(stream: &mut R, buf: &mut [u8]) -> EncodingResult<usize> {
    let result = stream.read_exact(buf);
    process_decode_io_result(result)?;
    Ok(buf.len())
}

/// Read an unsigned byte from the stream
pub fn read_u8<R: Read + ?Sized>(stream: &mut R) -> EncodingResult<u8> {
    let mut buf = [0u8];
    let result = stream.read_exact(&mut buf);
    process_decode_io_result(result)?;
    Ok(buf[0])
}

/// Read an signed 16-bit value from the stream
pub fn read_i16<R: Read + ?Sized>(stream: &mut R) -> EncodingResult<i16> {
    let mut buf = [0u8; 2];
    let result = stream.read_exact(&mut buf);
    process_decode_io_result(result)?;
    Ok(LittleEndian::read_i16(&buf))
}

/// Read an unsigned 16-bit value from the stream
pub fn read_u16<R: Read + ?Sized>(stream: &mut R) -> EncodingResult<u16> {
    let mut buf = [0u8; 2];
    let result = stream.read_exact(&mut buf);
    process_decode_io_result(result)?;
    Ok(LittleEndian::read_u16(&buf))
}

/// Read a signed 32-bit value from the stream
pub fn read_i32<R: Read + ?Sized>(stream: &mut R) -> EncodingResult<i32> {
    let mut buf = [0u8; 4];
    let result = stream.read_exact(&mut buf);
    process_decode_io_result(result)?;
    Ok(LittleEndian::read_i32(&buf))
}

/// Read an unsigned 32-bit value from the stream
pub fn read_u32<R: Read + ?Sized>(stream: &mut R) -> EncodingResult<u32> {
    let mut buf = [0u8; 4];
    let result = stream.read_exact(&mut buf);
    process_decode_io_result(result)?;
    Ok(LittleEndian::read_u32(&buf))
}

/// Read a signed 64-bit value from the stream
pub fn read_i64<R: Read + ?Sized>(stream: &mut R) -> EncodingResult<i64> {
    let mut buf = [0u8; 8];
    let result = stream.read_exact(&mut buf);
    process_decode_io_result(result)?;
    Ok(LittleEndian::read_i64(&buf))
}

/// Read an unsigned 64-bit value from the stream
pub fn read_u64<R: Read + ?Sized>(stream: &mut R) -> EncodingResult<u64> {
    let mut buf = [0u8; 8];
    let result = stream.read_exact(&mut buf);
    process_decode_io_result(result)?;
    Ok(LittleEndian::read_u64(&buf))
}

/// Read a 32-bit precision value from the stream
pub fn read_f32<R: Read + ?Sized>(stream: &mut R) -> EncodingResult<f32> {
    let mut buf = [0u8; 4];
    let result = stream.read_exact(&mut buf);
    process_decode_io_result(result)?;
    Ok(LittleEndian::read_f32(&buf))
}

/// Read a 64-bit precision from the stream
pub fn read_f64<R: Read + ?Sized>(stream: &mut R) -> EncodingResult<f64> {
    let mut buf = [0u8; 8];
    let result = stream.read_exact(&mut buf);
    process_decode_io_result(result)?;
    Ok(LittleEndian::read_f64(&buf))
}

/// Skip `bytes` bytes in the stream.
pub fn skip_bytes<R: Read + ?Sized>(stream: &mut R, bytes: u64) -> EncodingResult<()> {
    std::io::copy(&mut stream.take(bytes), &mut std::io::sink())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::{constants, DepthGauge, DepthLock};
    use crate::StatusCode;

    #[test]
    fn depth_gauge() {
        let dg = Arc::new(DepthGauge::default());

        let max_depth = dg.max_depth();
        assert_eq!(max_depth, constants::MAX_DECODING_DEPTH);

        // Iterate the depth
        {
            let mut v = Vec::new();
            for _ in 0..max_depth {
                v.push(DepthLock::obtain(&dg).unwrap());
            }

            // Depth should now be MAX_DECODING_DEPTH
            {
                assert_eq!(
                    dg.current_depth.load(std::sync::atomic::Ordering::Relaxed),
                    max_depth
                );
            }

            // Next obtain should fail
            assert_eq!(
                DepthLock::obtain(&dg).unwrap_err().status,
                StatusCode::BadDecodingError
            );

            // DepthLocks drop here
        }

        // Depth should be zero
        {
            assert_eq!(
                dg.current_depth.load(std::sync::atomic::Ordering::Relaxed),
                0
            );
        }
    }
}
