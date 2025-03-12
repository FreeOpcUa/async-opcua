use opcua_types::{
    AttributeId, DataEncoding, DataValue, DateTime, DiagnosticBits, DiagnosticInfo, NodeId,
    NumericRange, ReadValueId, StatusCode, WriteValue,
};

use super::IntoResult;

#[derive(Debug, Clone)]
/// Parsed and validated version of a raw ReadValueId from OPC-UA.
pub struct ParsedReadValueId {
    /// ID of the node to read from.
    pub node_id: NodeId,
    /// Attribute ID to read.
    pub attribute_id: AttributeId,
    /// Index range to read.
    pub index_range: NumericRange,
    /// Requested data encoding.
    pub data_encoding: DataEncoding,
}

impl ParsedReadValueId {
    /// Try to parse from a `ReadValueId`.
    pub fn parse(val: ReadValueId) -> Result<Self, StatusCode> {
        let attribute_id = AttributeId::from_u32(val.attribute_id)
            .map_err(|_| StatusCode::BadAttributeIdInvalid)?;

        Ok(Self {
            node_id: val.node_id,
            attribute_id,
            index_range: val.index_range,
            data_encoding: DataEncoding::from_browse_name(val.data_encoding)?,
        })
    }

    /// Create a "null" `ParsedReadValueId`, with no node ID.
    pub fn null() -> Self {
        Self {
            node_id: NodeId::null(),
            attribute_id: AttributeId::NodeId,
            index_range: NumericRange::None,
            data_encoding: DataEncoding::Binary,
        }
    }

    /// Check whether this `ParsedReadValueId` is null.
    pub fn is_null(&self) -> bool {
        self.node_id.is_null()
    }
}

impl Default for ParsedReadValueId {
    fn default() -> Self {
        Self::null()
    }
}

#[derive(Debug)]
/// Container for a single item in a `Read` service call.
pub struct ReadNode {
    node: ParsedReadValueId,
    pub(crate) result: DataValue,
    diagnostic_bits: DiagnosticBits,

    diagnostic_info: Option<DiagnosticInfo>,
}

impl ReadNode {
    /// Create a `ReadNode` from a `ReadValueId`.
    pub(crate) fn new(node: ReadValueId, diagnostic_bits: DiagnosticBits) -> Self {
        let mut status = StatusCode::BadNodeIdUnknown;

        let node = match ParsedReadValueId::parse(node) {
            Ok(r) => r,
            Err(e) => {
                status = e;
                ParsedReadValueId::null()
            }
        };

        Self {
            node,
            result: DataValue {
                status: Some(status),
                server_timestamp: Some(DateTime::now()),
                ..Default::default()
            },
            diagnostic_bits,
            diagnostic_info: None,
        }
    }

    /// Get the current result status code.
    pub fn status(&self) -> StatusCode {
        self.result.status()
    }

    /// Get the node/attribute pair to read.
    pub fn node(&self) -> &ParsedReadValueId {
        &self.node
    }

    /// Set the result of this read operation.
    pub fn set_result(&mut self, result: DataValue) {
        self.result = result;
    }

    /// Set the result of this read operation to an error with no value or
    /// timestamp. Use this not if the value is an error, but if the read
    /// failed.
    pub fn set_error(&mut self, status: StatusCode) {
        self.result = DataValue {
            status: Some(status),
            server_timestamp: Some(DateTime::now()),
            ..Default::default()
        }
    }

    /// Header diagnostic bits for requesting operation-level diagnostics.
    pub fn diagnostic_bits(&self) -> DiagnosticBits {
        self.diagnostic_bits
    }

    /// Set diagnostic infos, you don't need to do this if
    /// `diagnostic_bits` are not set.
    pub fn set_diagnostic_info(&mut self, diagnostic_info: DiagnosticInfo) {
        self.diagnostic_info = Some(diagnostic_info);
    }
}

impl IntoResult for ReadNode {
    type Result = DataValue;

    fn into_result(self) -> (Self::Result, Option<DiagnosticInfo>) {
        (self.result, self.diagnostic_info)
    }
}

#[derive(Debug, Clone)]
/// Parsed and validated version of the raw OPC-UA `WriteValue`.
pub struct ParsedWriteValue {
    /// ID of node to write to.
    pub node_id: NodeId,
    /// Attribute to write.
    pub attribute_id: AttributeId,
    /// Index range of value to write.
    pub index_range: NumericRange,
    /// Value to write.
    pub value: DataValue,
}

impl ParsedWriteValue {
    /// Try to parse from a `WriteValue`.
    pub fn parse(val: WriteValue) -> Result<Self, StatusCode> {
        let attribute_id = AttributeId::from_u32(val.attribute_id)
            .map_err(|_| StatusCode::BadAttributeIdInvalid)?;

        Ok(Self {
            node_id: val.node_id,
            attribute_id,
            index_range: val.index_range,
            value: val.value,
        })
    }

    /// Create a "null" `ParsedWriteValue`.
    pub fn null() -> Self {
        Self {
            node_id: NodeId::null(),
            attribute_id: AttributeId::NodeId,
            index_range: NumericRange::None,
            value: DataValue::null(),
        }
    }

    /// Check if this `ParsedWriteValue` is null.
    pub fn is_null(&self) -> bool {
        self.node_id.is_null()
    }
}

impl Default for ParsedWriteValue {
    fn default() -> Self {
        Self::null()
    }
}

/// Container for a single item in a `Write` service call.
#[derive(Debug)]
pub struct WriteNode {
    value: ParsedWriteValue,
    diagnostic_bits: DiagnosticBits,

    status: StatusCode,
    diagnostic_info: Option<DiagnosticInfo>,
}

impl WriteNode {
    /// Create a `WriteNode` from a raw OPC-UA `WriteValue`.
    pub(crate) fn new(value: WriteValue, diagnostic_bits: DiagnosticBits) -> Self {
        let mut status = StatusCode::BadNodeIdUnknown;

        let value = match ParsedWriteValue::parse(value) {
            Ok(r) => r,
            Err(e) => {
                status = e;
                ParsedWriteValue::null()
            }
        };

        Self {
            value,
            status,
            diagnostic_bits,
            diagnostic_info: None,
        }
    }

    /// Get the current status.
    pub fn status(&self) -> StatusCode {
        self.status
    }

    /// Set the status code result of this operation.
    pub fn set_status(&mut self, status: StatusCode) {
        self.status = status;
    }

    /// Get the value to write.
    pub fn value(&self) -> &ParsedWriteValue {
        &self.value
    }

    /// Header diagnostic bits for requesting operation-level diagnostics.
    pub fn diagnostic_bits(&self) -> DiagnosticBits {
        self.diagnostic_bits
    }

    /// Set diagnostic infos, you don't need to do this if
    /// `diagnostic_bits` are not set.
    pub fn set_diagnostic_info(&mut self, diagnostic_info: DiagnosticInfo) {
        self.diagnostic_info = Some(diagnostic_info);
    }
}

impl IntoResult for WriteNode {
    type Result = StatusCode;

    fn into_result(self) -> (Self::Result, Option<DiagnosticInfo>) {
        (self.status(), self.diagnostic_info)
    }
}
