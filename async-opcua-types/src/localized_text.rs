// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2024 Adam Lock

//! Contains the definition of `LocalizedText`.
use std::{
    fmt,
    io::{Read, Write},
};

use crate::{
    encoding::{BinaryDecodable, BinaryEncodable, EncodingResult},
    string::*,
};

#[allow(unused)]
mod opcua {
    pub use crate as types;
}
/// A human readable text with an optional locale identifier.
#[derive(PartialEq, Default, Debug, Clone, crate::UaNullable)]
#[cfg_attr(
    feature = "json",
    derive(opcua_macros::JsonEncodable, opcua_macros::JsonDecodable)
)]
#[cfg_attr(
    feature = "xml",
    derive(crate::XmlEncodable, crate::XmlDecodable, crate::XmlType)
)]
pub struct LocalizedText {
    /// The locale. Omitted from stream if null or empty
    pub locale: UAString,
    /// The text in the specified locale. Omitted from stream if null or empty.
    pub text: UAString,
}

impl<'a> From<&'a str> for LocalizedText {
    fn from(value: &'a str) -> Self {
        Self {
            locale: UAString::null(),
            text: UAString::from(value),
        }
    }
}

impl From<&String> for LocalizedText {
    fn from(value: &String) -> Self {
        Self {
            locale: UAString::null(),
            text: UAString::from(value),
        }
    }
}

impl From<String> for LocalizedText {
    fn from(value: String) -> Self {
        Self {
            locale: UAString::null(),
            text: UAString::from(value),
        }
    }
}

impl fmt::Display for LocalizedText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.text)
    }
}

impl BinaryEncodable for LocalizedText {
    fn byte_len(&self, ctx: &opcua::types::Context<'_>) -> usize {
        let mut size = 1;
        if !self.locale.is_empty() {
            size += self.locale.byte_len(ctx);
        }
        if !self.text.is_empty() {
            size += self.text.byte_len(ctx);
        }
        size
    }

    fn encode<S: Write + ?Sized>(
        &self,
        stream: &mut S,
        ctx: &crate::Context<'_>,
    ) -> EncodingResult<()> {
        // A bit mask that indicates which fields are present in the stream.
        // The mask has the following bits:
        // 0x01    Locale
        // 0x02    Text
        let mut encoding_mask: u8 = 0;
        if !self.locale.is_empty() {
            encoding_mask |= 0x1;
        }
        if !self.text.is_empty() {
            encoding_mask |= 0x2;
        }
        encoding_mask.encode(stream, ctx)?;
        if !self.locale.is_empty() {
            self.locale.encode(stream, ctx)?;
        }
        if !self.text.is_empty() {
            self.text.encode(stream, ctx)?;
        }
        Ok(())
    }
}

impl BinaryDecodable for LocalizedText {
    fn decode<S: Read + ?Sized>(stream: &mut S, ctx: &crate::Context<'_>) -> EncodingResult<Self> {
        let encoding_mask = u8::decode(stream, ctx)?;
        let locale = if encoding_mask & 0x1 != 0 {
            UAString::decode(stream, ctx)?
        } else {
            UAString::null()
        };
        let text = if encoding_mask & 0x2 != 0 {
            UAString::decode(stream, ctx)?
        } else {
            UAString::null()
        };
        Ok(LocalizedText { locale, text })
    }
}

impl LocalizedText {
    /// Create a new LocalizedText from the specified locale and text.
    pub fn new(locale: &str, text: &str) -> LocalizedText {
        LocalizedText {
            locale: UAString::from(locale),
            text: UAString::from(text),
        }
    }

    /// Create a null LocalizedText.
    pub fn null() -> LocalizedText {
        LocalizedText {
            locale: UAString::null(),
            text: UAString::null(),
        }
    }
}
