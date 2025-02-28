// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2024 Adam Lock

//! Contains the implementation of `DiagnosticInfo`.

use std::io::{Read, Write};

use crate::{
    encoding::{BinaryDecodable, BinaryEncodable, EncodingResult},
    status_code::StatusCode,
    string::UAString,
    write_i32, write_u8, Context,
};
use bitflags::bitflags;

bitflags! {
    /// Mask for fields present in DiagnosticInfo.
    #[derive(Copy, Clone, Debug, PartialEq, Default)]
    pub struct DiagnosticInfoMask: u8 {
        /// Symbolic ID is present.
        const HAS_SYMBOLIC_ID = 0x01;
        /// Namespace is present.
        const HAS_NAMESPACE = 0x02;
        /// Localized text is present.
        const HAS_LOCALIZED_TEXT = 0x04;
        /// Locale is present.
        const HAS_LOCALE = 0x08;
        /// AdditionalInfo is present.
        const HAS_ADDITIONAL_INFO = 0x10;
        /// Inner status code is present.
        const HAS_INNER_STATUS_CODE = 0x20;
        /// Inner diagnostic info is present.
        const HAS_INNER_DIAGNOSTIC_INFO = 0x40;
    }
}

bitflags! {
    #[derive(Copy, Clone, Debug, PartialEq, Default)]
    /// Requested diagnostic infos.
    pub struct DiagnosticBits: u32 {
        /// ServiceLevel / SymbolicId
        const SERVICE_LEVEL_SYMBOLIC_ID = 0x0000_0001;
        /// ServiceLevel / LocalizedText
        const SERVICE_LEVEL_LOCALIZED_TEXT = 0x0000_0002;
        /// ServiceLevel / AdditionalInfo
        const SERVICE_LEVEL_ADDITIONAL_INFO = 0x0000_0004;
        /// ServiceLevel / Inner StatusCode
        const SERVICE_LEVEL_LOCALIZED_INNER_STATUS_CODE = 0x0000_0008;
        /// ServiceLevel / Inner Diagnostics
        const SERVICE_LEVEL_LOCALIZED_INNER_DIAGNOSTICS = 0x0000_0010;
        /// OperationLevel / SymbolicId
        const OPERATIONAL_LEVEL_SYMBOLIC_ID = 0x0000_0020;
        /// OperationLevel / LocalizedText
        const OPERATIONAL_LEVEL_LOCALIZED_TEXT = 0x0000_0040;
        /// OperationLevel / AdditionalInfo
        const OPERATIONAL_LEVEL_ADDITIONAL_INFO = 0x0000_0080;
        /// OperationLevel / Inner StatusCode
        const OPERATIONAL_LEVEL_INNER_STATUS_CODE = 0x0000_0100;
        /// OperationLevel / Inner Diagnostics
        const OPERATIONAL_LEVEL_INNER_DIAGNOSTICS = 0x0000_0200;
    }
}

impl crate::UaNullable for DiagnosticBits {
    fn is_ua_null(&self) -> bool {
        self.is_empty()
    }
}

#[cfg(feature = "json")]
mod json {
    use crate::json::*;

    use super::DiagnosticBits;

    impl JsonEncodable for DiagnosticBits {
        fn encode(
            &self,
            stream: &mut JsonStreamWriter<&mut dyn std::io::Write>,
            _ctx: &crate::Context<'_>,
        ) -> super::EncodingResult<()> {
            stream.number_value(self.bits())?;
            Ok(())
        }
    }

    impl JsonDecodable for DiagnosticBits {
        fn decode(
            stream: &mut JsonStreamReader<&mut dyn std::io::Read>,
            _ctx: &Context<'_>,
        ) -> super::EncodingResult<Self> {
            Ok(Self::from_bits_truncate(stream.next_number()??))
        }
    }
}

#[cfg(feature = "xml")]
mod xml {
    use crate::xml::*;
    use std::io::{Read, Write};

    use super::DiagnosticBits;

    impl XmlType for DiagnosticBits {
        const TAG: &'static str = u32::TAG;
    }

    impl XmlEncodable for DiagnosticBits {
        fn encode(
            &self,
            writer: &mut XmlStreamWriter<&mut dyn Write>,
            context: &Context<'_>,
        ) -> EncodingResult<()> {
            self.bits().encode(writer, context)
        }
    }

    impl XmlDecodable for DiagnosticBits {
        fn decode(
            reader: &mut XmlStreamReader<&mut dyn Read>,
            context: &Context<'_>,
        ) -> EncodingResult<Self> {
            let v = u32::decode(reader, context)?;
            Ok(Self::from_bits_truncate(v))
        }
    }
}

#[allow(unused)]
mod opcua {
    pub use crate as types;
}

/// Diagnostic information.
#[derive(PartialEq, Debug, Clone, crate::UaNullable)]
#[cfg_attr(
    feature = "json",
    derive(opcua_macros::JsonEncodable, opcua_macros::JsonDecodable)
)]
#[cfg_attr(
    feature = "xml",
    derive(crate::XmlEncodable, crate::XmlDecodable, crate::XmlType)
)]
pub struct DiagnosticInfo {
    /// A symbolic name for the status code.
    pub symbolic_id: Option<i32>,
    /// A namespace that qualifies the symbolic id.
    pub namespace_uri: Option<i32>,
    /// The locale used for the localized text.
    pub locale: Option<i32>,
    /// A human readable summary of the status code.
    pub localized_text: Option<i32>,
    /// Detailed application specific diagnostic information.
    pub additional_info: Option<UAString>,
    /// A status code provided by an underlying system.
    pub inner_status_code: Option<StatusCode>,
    /// Diagnostic info associated with the inner status code.
    pub inner_diagnostic_info: Option<Box<DiagnosticInfo>>,
}

impl BinaryEncodable for DiagnosticInfo {
    fn byte_len(&self, ctx: &opcua::types::Context<'_>) -> usize {
        let mut size: usize = 0;
        size += 1; // self.encoding_mask())
        if let Some(ref symbolic_id) = self.symbolic_id {
            // Write symbolic id
            size += symbolic_id.byte_len(ctx);
        }
        if let Some(ref namespace_uri) = self.namespace_uri {
            // Write namespace
            size += namespace_uri.byte_len(ctx)
        }
        if let Some(ref locale) = self.locale {
            // Write locale
            size += locale.byte_len(ctx)
        }
        if let Some(ref localized_text) = self.localized_text {
            // Write localized text
            size += localized_text.byte_len(ctx)
        }
        if let Some(ref additional_info) = self.additional_info {
            // Write Additional info
            size += additional_info.byte_len(ctx)
        }
        if let Some(ref inner_status_code) = self.inner_status_code {
            // Write inner status code
            size += inner_status_code.byte_len(ctx)
        }
        if let Some(ref inner_diagnostic_info) = self.inner_diagnostic_info {
            // Write inner diagnostic info
            size += inner_diagnostic_info.byte_len(ctx)
        }
        size
    }

    fn encode<S: Write + ?Sized>(&self, stream: &mut S, ctx: &Context<'_>) -> EncodingResult<()> {
        write_u8(stream, self.encoding_mask().bits())?;
        if let Some(ref symbolic_id) = self.symbolic_id {
            // Write symbolic id
            write_i32(stream, *symbolic_id)?;
        }
        if let Some(ref namespace_uri) = self.namespace_uri {
            // Write namespace
            namespace_uri.encode(stream, ctx)?;
        }
        if let Some(ref locale) = self.locale {
            // Write locale
            locale.encode(stream, ctx)?;
        }
        if let Some(ref localized_text) = self.localized_text {
            // Write localized text
            localized_text.encode(stream, ctx)?;
        }
        if let Some(ref additional_info) = self.additional_info {
            // Write Additional info
            additional_info.encode(stream, ctx)?;
        }
        if let Some(ref inner_status_code) = self.inner_status_code {
            // Write inner status code
            inner_status_code.encode(stream, ctx)?;
        }
        if let Some(ref inner_diagnostic_info) = self.inner_diagnostic_info {
            // Write inner diagnostic info
            inner_diagnostic_info.clone().encode(stream, ctx)?;
        }
        Ok(())
    }
}

impl BinaryDecodable for DiagnosticInfo {
    fn decode<S: Read + ?Sized>(stream: &mut S, ctx: &Context<'_>) -> EncodingResult<Self> {
        let encoding_mask = DiagnosticInfoMask::from_bits_truncate(u8::decode(stream, ctx)?);
        let mut diagnostic_info = DiagnosticInfo::default();

        if encoding_mask.contains(DiagnosticInfoMask::HAS_SYMBOLIC_ID) {
            // Read symbolic id
            diagnostic_info.symbolic_id = Some(i32::decode(stream, ctx)?);
        }
        if encoding_mask.contains(DiagnosticInfoMask::HAS_NAMESPACE) {
            // Read namespace
            diagnostic_info.namespace_uri = Some(i32::decode(stream, ctx)?);
        }
        if encoding_mask.contains(DiagnosticInfoMask::HAS_LOCALE) {
            // Read locale
            diagnostic_info.locale = Some(i32::decode(stream, ctx)?);
        }
        if encoding_mask.contains(DiagnosticInfoMask::HAS_LOCALIZED_TEXT) {
            // Read localized text
            diagnostic_info.localized_text = Some(i32::decode(stream, ctx)?);
        }
        if encoding_mask.contains(DiagnosticInfoMask::HAS_ADDITIONAL_INFO) {
            // Read Additional info
            diagnostic_info.additional_info = Some(UAString::decode(stream, ctx)?);
        }
        if encoding_mask.contains(DiagnosticInfoMask::HAS_INNER_STATUS_CODE) {
            // Read inner status code
            diagnostic_info.inner_status_code = Some(StatusCode::decode(stream, ctx)?);
        }
        if encoding_mask.contains(DiagnosticInfoMask::HAS_INNER_DIAGNOSTIC_INFO) {
            // Read inner diagnostic info
            diagnostic_info.inner_diagnostic_info =
                Some(Box::new(DiagnosticInfo::decode(stream, ctx)?));
        }
        Ok(diagnostic_info)
    }
}

impl Default for DiagnosticInfo {
    fn default() -> Self {
        DiagnosticInfo::null()
    }
}

impl DiagnosticInfo {
    /// Return an empty diagnostic info.
    pub fn null() -> DiagnosticInfo {
        DiagnosticInfo {
            symbolic_id: None,
            namespace_uri: None,
            locale: None,
            localized_text: None,
            additional_info: None,
            inner_status_code: None,
            inner_diagnostic_info: None,
        }
    }

    /// Get the encoding mask for this diagnostic info.
    pub fn encoding_mask(&self) -> DiagnosticInfoMask {
        let mut encoding_mask = DiagnosticInfoMask::empty();
        if self.symbolic_id.is_some() {
            encoding_mask |= DiagnosticInfoMask::HAS_SYMBOLIC_ID;
        }
        if self.namespace_uri.is_some() {
            encoding_mask |= DiagnosticInfoMask::HAS_NAMESPACE;
        }
        if self.locale.is_some() {
            encoding_mask |= DiagnosticInfoMask::HAS_LOCALE;
        }
        if self.localized_text.is_some() {
            encoding_mask |= DiagnosticInfoMask::HAS_LOCALIZED_TEXT;
        }
        if self.additional_info.is_some() {
            encoding_mask |= DiagnosticInfoMask::HAS_ADDITIONAL_INFO;
        }
        if self.inner_status_code.is_some() {
            encoding_mask |= DiagnosticInfoMask::HAS_INNER_STATUS_CODE;
        }
        if self.inner_diagnostic_info.is_some() {
            encoding_mask |= DiagnosticInfoMask::HAS_INNER_DIAGNOSTIC_INFO;
        }
        encoding_mask
    }
}
