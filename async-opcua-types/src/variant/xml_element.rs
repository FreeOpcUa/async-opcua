// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2025 Einar Omang

use crate::{BinaryDecodable, BinaryEncodable, UAString, UaNullable};

/// XML element, represented as a string.
///
/// Note that this is deprecated, according to the OPC-UA standard,
/// it is kept in the library for backwards compatibility.
///
/// Constructors are not checked, so the contents are not guaranteed to
/// be valid XML, or really XML at all.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct XmlElement(UAString);

impl XmlElement {
    /// Create a new null XmlElement.
    pub fn null() -> Self {
        Self(UAString::null())
    }
}

impl std::fmt::Display for XmlElement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl From<String> for XmlElement {
    fn from(value: String) -> Self {
        Self(UAString::from(value))
    }
}

impl From<&str> for XmlElement {
    fn from(value: &str) -> Self {
        Self(UAString::from(value))
    }
}

impl From<UAString> for XmlElement {
    fn from(value: UAString) -> Self {
        Self(value)
    }
}

impl BinaryEncodable for XmlElement {
    fn byte_len(&self, ctx: &crate::Context<'_>) -> usize {
        self.0.byte_len(ctx)
    }

    fn encode<S: std::io::Write + ?Sized>(
        &self,
        stream: &mut S,
        ctx: &crate::Context<'_>,
    ) -> crate::EncodingResult<()> {
        self.0.encode(stream, ctx)
    }
}

impl BinaryDecodable for XmlElement {
    fn decode<S: std::io::Read + ?Sized>(
        stream: &mut S,
        ctx: &crate::Context<'_>,
    ) -> crate::EncodingResult<Self> {
        Ok(XmlElement(UAString::decode(stream, ctx)?))
    }
}

impl UaNullable for XmlElement {
    fn is_ua_null(&self) -> bool {
        self.0.is_null()
    }
}

#[cfg(feature = "json")]
mod json {
    use crate::{json::*, UAString};

    // XMLElement is stored as a string in JSON.

    impl JsonEncodable for super::XmlElement {
        fn encode(
            &self,
            stream: &mut JsonStreamWriter<&mut dyn std::io::Write>,
            ctx: &crate::Context<'_>,
        ) -> crate::EncodingResult<()> {
            self.0.encode(stream, ctx)
        }
    }

    impl JsonDecodable for super::XmlElement {
        fn decode(
            stream: &mut JsonStreamReader<&mut dyn std::io::Read>,
            ctx: &Context<'_>,
        ) -> crate::EncodingResult<Self> {
            Ok(super::XmlElement(UAString::decode(stream, ctx)?))
        }
    }
}

#[cfg(feature = "xml")]
mod xml {
    use crate::xml::*;

    impl XmlType for super::XmlElement {
        const TAG: &'static str = "XmlElement";
    }

    impl XmlEncodable for super::XmlElement {
        fn encode(
            &self,
            writer: &mut XmlStreamWriter<&mut dyn std::io::Write>,
            _context: &Context<'_>,
        ) -> EncodingResult<()> {
            writer.write_raw(self.0.as_ref().as_bytes())?;
            Ok(())
        }
    }

    impl XmlDecodable for super::XmlElement {
        fn decode(
            read: &mut XmlStreamReader<&mut dyn std::io::Read>,
            _context: &Context<'_>,
        ) -> Result<Self, Error>
        where
            Self: Sized,
        {
            let raw = read.consume_raw()?;
            let string = String::from_utf8(raw).map_err(Error::decoding)?;
            Ok(Self(string.into()))
        }
    }
}
