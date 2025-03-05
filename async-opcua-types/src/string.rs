// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2024 Adam Lock

//! Contains the implementation of `UAString`.

use std::{
    fmt,
    io::{Read, Write},
};

use crate::{
    encoding::{process_decode_io_result, process_encode_io_result, write_i32, EncodingResult},
    read_i32, DecodingOptions, Error, OutOfRange, SimpleBinaryDecodable, SimpleBinaryEncodable,
    UaNullable,
};

/// To avoid naming conflict hell, the OPC UA String type is typed `UAString` so it does not collide
/// with the Rust `String`.
///
/// A string contains UTF-8 encoded characters or a null value. A null value is distinct from
/// being an empty string so internally, the code maintains that distinction by holding the value
/// as an `Option<String>`.
#[derive(Eq, PartialEq, Debug, Clone, Hash)]
pub struct UAString {
    value: Option<String>,
}

impl fmt::Display for UAString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(ref value) = self.value {
            write!(f, "{}", value)
        } else {
            write!(f, "[null]")
        }
    }
}

impl UaNullable for UAString {
    fn is_ua_null(&self) -> bool {
        self.is_null()
    }
}

#[cfg(feature = "json")]
mod json {
    use std::io::{Read, Write};
    use struson::{
        reader::{JsonReader, JsonStreamReader, ValueType},
        writer::{JsonStreamWriter, JsonWriter},
    };

    use crate::json::{Context, JsonDecodable, JsonEncodable};

    use super::{EncodingResult, UAString};

    impl JsonEncodable for UAString {
        fn encode(
            &self,
            stream: &mut JsonStreamWriter<&mut dyn Write>,
            _ctx: &Context<'_>,
        ) -> EncodingResult<()> {
            if let Some(s) = self.value() {
                stream.string_value(s)?;
            } else {
                stream.null_value()?;
            }

            Ok(())
        }
    }

    impl JsonDecodable for UAString {
        fn decode(
            stream: &mut JsonStreamReader<&mut dyn Read>,
            _ctx: &Context<'_>,
        ) -> EncodingResult<Self> {
            match stream.peek()? {
                ValueType::String => Ok(stream.next_string()?.into()),
                _ => {
                    stream.next_null()?;
                    Ok(UAString::null())
                }
            }
        }
    }
}

impl SimpleBinaryEncodable for UAString {
    fn byte_len(&self) -> usize {
        // Length plus the actual string length in bytes for a non-null string.
        4 + match &self.value {
            Some(s) => s.len(),
            None => 0,
        }
    }

    fn encode<S: Write + ?Sized>(&self, stream: &mut S) -> EncodingResult<()> {
        // Strings are encoded as UTF8 chars preceded by an Int32 length. A -1 indicates a null string
        match &self.value {
            Some(s) => {
                write_i32(stream, s.len() as i32)?;
                let buf = s.as_bytes();
                process_encode_io_result(stream.write_all(buf))
            }
            None => write_i32(stream, -1),
        }
    }
}

impl SimpleBinaryDecodable for UAString {
    fn decode<S: Read + ?Sized>(
        stream: &mut S,
        decoding_options: &DecodingOptions,
    ) -> EncodingResult<Self> {
        let len = read_i32(stream)?;
        // Null string?
        if len == -1 {
            Ok(UAString::null())
        } else if len < -1 {
            Err(Error::decoding(format!(
                "String buf length is a negative number {}",
                len
            )))
        } else if len as usize > decoding_options.max_string_length {
            Err(Error::decoding(format!(
                "String buf length {} exceeds decoding limit {}",
                len, decoding_options.max_string_length
            )))
        } else {
            // Create a buffer filled with zeroes and read the string over the top
            let mut buf = vec![0u8; len as usize];
            process_decode_io_result(stream.read_exact(&mut buf))?;
            let value = String::from_utf8(buf).map_err(|err| {
                Error::decoding(format!("Decoded string was not valid UTF-8 - {}", err))
            })?;
            Ok(UAString::from(value))
        }
    }
}

#[cfg(feature = "xml")]
mod xml {
    use crate::xml::*;
    use std::io::{Read, Write};

    use super::UAString;

    impl XmlType for UAString {
        const TAG: &'static str = "String";
    }

    impl XmlEncodable for UAString {
        fn encode(
            &self,
            writer: &mut XmlStreamWriter<&mut dyn Write>,
            _ctx: &Context<'_>,
        ) -> Result<(), Error> {
            if let Some(s) = self.value() {
                writer.write_text(s)?;
            }

            Ok(())
        }
    }

    impl XmlDecodable for UAString {
        fn decode(
            read: &mut XmlStreamReader<&mut dyn Read>,
            _context: &Context<'_>,
        ) -> Result<Self, Error> {
            Ok(read.consume_as_text()?.into())
        }
    }
}

impl From<UAString> for String {
    fn from(value: UAString) -> Self {
        value.as_ref().to_string()
    }
}

impl AsRef<str> for UAString {
    fn as_ref(&self) -> &str {
        if self.is_null() {
            ""
        } else {
            self.value.as_ref().unwrap()
        }
    }
}

impl<'a> From<&'a str> for UAString {
    fn from(value: &'a str) -> Self {
        Self::from(value.to_string())
    }
}

impl From<&String> for UAString {
    fn from(value: &String) -> Self {
        UAString {
            value: Some(value.clone()),
        }
    }
}

impl From<String> for UAString {
    fn from(value: String) -> Self {
        UAString { value: Some(value) }
    }
}

impl From<Option<String>> for UAString {
    fn from(value: Option<String>) -> Self {
        UAString { value }
    }
}

impl Default for UAString {
    fn default() -> Self {
        UAString::null()
    }
}

impl PartialEq<str> for UAString {
    fn eq(&self, other: &str) -> bool {
        match self.value {
            None => false,
            Some(ref v) => v.eq(other),
        }
    }
}

impl UAString {
    /// Get the inner raw value.
    pub fn value(&self) -> &Option<String> {
        &self.value
    }

    /// Set the inner value.
    pub fn set_value(&mut self, value: Option<String>) {
        self.value = value;
    }

    /// Returns true if the string is null or empty, false otherwise
    pub fn is_empty(&self) -> bool {
        self.value.is_none() || self.value.as_ref().is_some_and(|v| v.is_empty())
    }

    /// Returns the length of the string in bytes or -1 for null.
    pub fn len(&self) -> isize {
        if self.value.is_none() {
            -1
        } else {
            self.value.as_ref().unwrap().len() as isize
        }
    }

    /// Create a null string (not the same as an empty string).
    pub fn null() -> UAString {
        UAString { value: None }
    }

    /// Test if the string is null.
    pub fn is_null(&self) -> bool {
        self.value.is_none()
    }

    /// This function is meant for use with NumericRange. It creates a substring from this string
    /// from min up to and inclusive of max. Note that min must have an index within the string
    /// but max is allowed to be beyond the end in which case the remainder of the string is
    /// returned (see docs for NumericRange).
    pub fn substring(&self, min: usize, max: usize) -> Result<UAString, OutOfRange> {
        if let Some(ref v) = self.value() {
            if min >= v.len() {
                Err(OutOfRange)
            } else {
                let max = if max >= v.len() { v.len() - 1 } else { max };
                Ok(UAString::from(&v[min..=max]))
            }
        } else {
            Err(OutOfRange)
        }
    }
}

#[test]
fn string_null() {
    let s = UAString::null();
    assert!(s.is_null());
    assert!(s.is_empty());
    assert_eq!(s.len(), -1);
}

#[test]
fn string_empty() {
    let s = UAString::from("");
    assert!(!s.is_null());
    assert!(s.is_empty());
    assert_eq!(s.len(), 0);
}

#[test]
fn string_value() {
    let v = "Mary had a little lamb";
    let s = UAString::from(v);
    assert!(!s.is_null());
    assert!(!s.is_empty());
    assert_eq!(s.as_ref(), v);
}

#[test]
#[allow(clippy::comparison_to_empty)]
fn string_eq() {
    let s = UAString::null();
    assert!(!s.eq(""));

    let s = UAString::from("");
    assert!(s.eq(""));

    let s = UAString::from("Sunshine");
    assert!(s.ne("Moonshine"));
    assert!(s.eq("Sunshine"));
    assert!(!s.eq("Sunshine "));
}

#[test]
fn string_substring() {
    let a = "Mary had a little lamb";
    let v = UAString::from(a);
    let v2 = v.substring(0, 4).unwrap();
    let a2 = v2.as_ref();
    assert_eq!(a2, "Mary ");

    let v2 = v.substring(2, 2).unwrap();
    let a2 = v2.as_ref();
    assert_eq!(a2, "r");

    let v2 = v.substring(0, 2000).unwrap();
    assert_eq!(v, v2);
    assert_eq!(v2.as_ref(), a);

    assert!(v.substring(22, 10000).is_err());

    assert!(UAString::null().substring(0, 0).is_err());
}
