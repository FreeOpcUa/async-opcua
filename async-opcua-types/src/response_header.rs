// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2024 Adam Lock

//! Message header for responses.

use std::{
    self,
    io::{Read, Write},
};

use crate::{
    data_types::*,
    date_time::DateTime,
    diagnostic_info::DiagnosticInfo,
    encoding::{BinaryDecodable, BinaryEncodable, EncodingResult},
    extension_object::ExtensionObject,
    request_header::RequestHeader,
    status_code::StatusCode,
    string::UAString,
    Error,
};

#[allow(unused)]
mod opcua {
    pub use crate as types;
}

/// The `ResponseHeader` contains information common to every response from server to client.
#[derive(Debug, Clone, PartialEq, Default, crate::UaNullable)]
#[cfg_attr(
    feature = "json",
    derive(opcua_macros::JsonEncodable, opcua_macros::JsonDecodable)
)]
#[cfg_attr(
    feature = "xml",
    derive(crate::XmlEncodable, crate::XmlDecodable, crate::XmlType)
)]
pub struct ResponseHeader {
    /// Response timestamp.
    pub timestamp: UtcTime,
    /// Handle of the request this message is responding to.
    pub request_handle: IntegerId,
    /// Status of the service call as a whole.
    pub service_result: StatusCode,
    /// Requested diagnostics.
    pub service_diagnostics: DiagnosticInfo,
    /// String table for the message.
    pub string_table: Option<Vec<UAString>>,
    /// Reserved space for additional header details.
    pub additional_header: ExtensionObject,
}

impl BinaryEncodable for ResponseHeader {
    fn byte_len(&self, ctx: &opcua::types::Context<'_>) -> usize {
        let mut size = 0;
        size += self.timestamp.byte_len(ctx);
        size += self.request_handle.byte_len(ctx);
        size += self.service_result.byte_len(ctx);
        size += self.service_diagnostics.byte_len(ctx);
        size += self.string_table.byte_len(ctx);
        size += self.additional_header.byte_len(ctx);
        size
    }

    fn encode<S: Write + ?Sized>(
        &self,
        stream: &mut S,
        ctx: &crate::Context<'_>,
    ) -> EncodingResult<()> {
        self.timestamp.encode(stream, ctx)?;
        self.request_handle.encode(stream, ctx)?;
        self.service_result.encode(stream, ctx)?;
        self.service_diagnostics.encode(stream, ctx)?;
        self.string_table.encode(stream, ctx)?;
        self.additional_header.encode(stream, ctx)
    }
}

impl BinaryDecodable for ResponseHeader {
    fn decode<S: Read + ?Sized>(stream: &mut S, ctx: &crate::Context<'_>) -> EncodingResult<Self> {
        let timestamp = UtcTime::decode(stream, ctx)?;
        let request_handle = IntegerId::decode(stream, ctx)?;
        // Capture request handle if decoding fails after this.
        let (service_result, service_diagnostics, string_table, additional_header) = (|| {
            let service_result = StatusCode::decode(stream, ctx)?;
            let service_diagnostics = DiagnosticInfo::decode(stream, ctx)?;
            let string_table = BinaryDecodable::decode(stream, ctx)?;
            let additional_header = ExtensionObject::decode(stream, ctx)?;
            Ok((
                service_result,
                service_diagnostics,
                string_table,
                additional_header,
            ))
        })()
        .map_err(|e: Error| e.with_request_handle(request_handle))?;
        Ok(ResponseHeader {
            timestamp,
            request_handle,
            service_result,
            service_diagnostics,
            string_table,
            additional_header,
        })
    }
}

/// Trait for types that can contain a request handle.
pub trait AsRequestHandle {
    /// Get the handle of this request.
    fn as_request_handle(&self) -> u32;
}

impl AsRequestHandle for &RequestHeader {
    fn as_request_handle(&self) -> u32 {
        self.request_handle
    }
}

impl AsRequestHandle for u32 {
    fn as_request_handle(&self) -> u32 {
        *self
    }
}

impl ResponseHeader {
    /// Create a new response header with status `Good`.
    pub fn new_good(request_header: impl AsRequestHandle) -> ResponseHeader {
        ResponseHeader::new_service_result(request_header, StatusCode::Good)
    }

    /// Create a new response header with given status.
    pub fn new_service_result(
        request_header: impl AsRequestHandle,
        service_result: StatusCode,
    ) -> ResponseHeader {
        ResponseHeader::new_timestamped_service_result(
            DateTime::now(),
            request_header,
            service_result,
        )
    }

    /// Create a new response header with given status and timestamp.
    pub fn new_timestamped_service_result(
        timestamp: DateTime,
        request_header: impl AsRequestHandle,
        service_result: StatusCode,
    ) -> ResponseHeader {
        ResponseHeader {
            timestamp,
            request_handle: request_header.as_request_handle(),
            service_result,
            service_diagnostics: DiagnosticInfo::default(),
            string_table: None,
            additional_header: ExtensionObject::null(),
        }
    }

    /// For testing, nothing else
    pub fn null() -> ResponseHeader {
        ResponseHeader {
            timestamp: DateTime::now(),
            request_handle: 0,
            service_result: StatusCode::Good,
            service_diagnostics: DiagnosticInfo::default(),
            string_table: None,
            additional_header: ExtensionObject::null(),
        }
    }
}
