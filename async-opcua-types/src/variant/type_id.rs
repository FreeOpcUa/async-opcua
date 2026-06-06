// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2024 Adam Lock

//! The [`VariantTypeId`] type, which is used to inspect variant types without looking at the value.

use std::fmt::Display;

use crate::{DataTypeId, NodeId, NodeIdError, StatusCode};

/// The variant type id is the type of the variant but without its payload.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum VariantTypeId<'a> {
    /// The variant is empty.
    Empty,
    /// The variant is a scalar with this inner type.
    Scalar(VariantScalarTypeId),
    /// The variant is an array with this inner type and optionally these ArrayDimensions.
    Array(VariantScalarTypeId, Option<&'a [u32]>),
}

impl From<VariantScalarTypeId> for VariantTypeId<'_> {
    fn from(value: VariantScalarTypeId) -> Self {
        Self::Scalar(value)
    }
}

impl<'a> From<(VariantScalarTypeId, &'a [u32])> for VariantTypeId<'a> {
    fn from(value: (VariantScalarTypeId, &'a [u32])) -> Self {
        Self::Array(value.0, Some(value.1))
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u32)]
/// The scalar type of a variant.
pub enum VariantScalarTypeId {
    /// Boolean
    Boolean = 1,
    /// Signed byte
    SByte = 2,
    /// Unsigned byte
    Byte = 3,
    /// Signed 16 bit integer
    Int16 = 4,
    /// Unsigned 16 bit integer
    UInt16 = 5,
    /// Signed 32 bit integer
    Int32 = 6,
    /// Unsigned 32 bit integer
    UInt32 = 7,
    /// Signed 64 bit integer
    Int64 = 8,
    /// Unsigned 64 bit integer
    UInt64 = 9,
    /// 32 bit floating point number
    Float = 10,
    /// 64 bit floating point number
    Double = 11,
    /// String
    String = 12,
    /// Datetime
    DateTime = 13,
    /// Globally unique ID
    Guid = 14,
    /// Byte string
    ByteString = 15,
    /// XmlElement
    XmlElement = 16,
    /// Node ID
    NodeId = 17,
    /// Expanded node ID
    ExpandedNodeId = 18,
    /// Status code
    StatusCode = 19,
    /// Qualified name
    QualifiedName = 20,
    /// Localized text
    LocalizedText = 21,
    /// Extension object, containing some dynamic structure.
    ExtensionObject = 22,
    /// Data value
    DataValue = 23,
    /// A nested variant.
    Variant = 24,
    /// Diagnostic info
    DiagnosticInfo = 25,
}

impl Display for VariantScalarTypeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VariantScalarTypeId::Boolean => write!(f, "Boolean"),
            VariantScalarTypeId::SByte => write!(f, "SByte"),
            VariantScalarTypeId::Byte => write!(f, "Byte"),
            VariantScalarTypeId::Int16 => write!(f, "Int16"),
            VariantScalarTypeId::UInt16 => write!(f, "UInt16"),
            VariantScalarTypeId::Int32 => write!(f, "Int32"),
            VariantScalarTypeId::UInt32 => write!(f, "UInt32"),
            VariantScalarTypeId::Int64 => write!(f, "Int64"),
            VariantScalarTypeId::UInt64 => write!(f, "UInt64"),
            VariantScalarTypeId::Float => write!(f, "Float"),
            VariantScalarTypeId::Double => write!(f, "Double"),
            VariantScalarTypeId::String => write!(f, "String"),
            VariantScalarTypeId::DateTime => write!(f, "DateTime"),
            VariantScalarTypeId::Guid => write!(f, "Guid"),
            VariantScalarTypeId::ByteString => write!(f, "ByteString"),
            VariantScalarTypeId::XmlElement => write!(f, "XmlElement"),
            VariantScalarTypeId::NodeId => write!(f, "NodeId"),
            VariantScalarTypeId::ExpandedNodeId => write!(f, "ExpandedNodeId"),
            VariantScalarTypeId::StatusCode => write!(f, "StatusCode"),
            VariantScalarTypeId::QualifiedName => write!(f, "QualifiedName"),
            VariantScalarTypeId::LocalizedText => write!(f, "LocalizedText"),
            VariantScalarTypeId::ExtensionObject => write!(f, "ExtensionObject"),
            VariantScalarTypeId::DataValue => write!(f, "DataValue"),
            VariantScalarTypeId::Variant => write!(f, "Variant"),
            VariantScalarTypeId::DiagnosticInfo => write!(f, "DiagnosticInfo"),
        }
    }
}

impl TryFrom<u32> for VariantScalarTypeId {
    type Error = StatusCode;
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        Ok(match value {
            1 => Self::Boolean,
            2 => Self::SByte,
            3 => Self::Byte,
            4 => Self::Int16,
            5 => Self::UInt16,
            6 => Self::Int32,
            7 => Self::UInt32,
            8 => Self::Int64,
            9 => Self::UInt64,
            10 => Self::Float,
            11 => Self::Double,
            12 => Self::String,
            13 => Self::DateTime,
            14 => Self::Guid,
            15 => Self::ByteString,
            16 => Self::XmlElement,
            17 => Self::NodeId,
            18 => Self::ExpandedNodeId,
            19 => Self::StatusCode,
            20 => Self::QualifiedName,
            21 => Self::LocalizedText,
            22 => Self::ExtensionObject,
            23 => Self::DataValue,
            24 => Self::Variant,
            25 => Self::DiagnosticInfo,
            r => {
                tracing::error!("Got unexpected vlaue for enum VariantScalarTypeId: {r}");
                return Err(StatusCode::BadDecodingError);
            }
        })
    }
}

impl TryFrom<&NodeId> for VariantScalarTypeId {
    type Error = NodeIdError;
    fn try_from(value: &NodeId) -> Result<Self, NodeIdError> {
        let type_id = value.as_data_type_id()?;

        Ok(match type_id {
            DataTypeId::Boolean => Self::Boolean,
            DataTypeId::Byte => Self::Byte,
            DataTypeId::Int16 => Self::Int16,
            DataTypeId::UInt16 => Self::UInt16,
            DataTypeId::Int32 => Self::Int32,
            DataTypeId::UInt32 => Self::UInt32,
            DataTypeId::Int64 => Self::Int64,
            DataTypeId::UInt64 => Self::UInt64,
            DataTypeId::Float => Self::Float,
            DataTypeId::Double => Self::Double,
            DataTypeId::String => Self::String,
            DataTypeId::DateTime => Self::DateTime,
            DataTypeId::Guid => Self::Guid,
            DataTypeId::ByteString => Self::ByteString,
            DataTypeId::XmlElement => Self::XmlElement,
            DataTypeId::NodeId => Self::NodeId,
            DataTypeId::ExpandedNodeId => Self::ExpandedNodeId,
            DataTypeId::StatusCode => Self::StatusCode,
            DataTypeId::QualifiedName => Self::QualifiedName,
            DataTypeId::LocalizedText => Self::LocalizedText,
            DataTypeId::DataValue => Self::DataValue,
            DataTypeId::BaseDataType => Self::Variant,
            DataTypeId::DiagnosticInfo => Self::DiagnosticInfo,
            _ => return Err(NodeIdError),
        })
    }
}

impl TryFrom<&NodeId> for VariantTypeId<'_> {
    type Error = NodeIdError;
    fn try_from(value: &NodeId) -> Result<Self, NodeIdError> {
        Ok(Self::Scalar(VariantScalarTypeId::try_from(value)?))
    }
}

impl VariantScalarTypeId {
    /// Get the encoding mask corresponding to this type ID.
    pub fn encoding_mask(&self) -> u8 {
        match self {
            Self::Boolean => EncodingMask::BOOLEAN,
            Self::SByte => EncodingMask::SBYTE,
            Self::Byte => EncodingMask::BYTE,
            Self::Int16 => EncodingMask::INT16,
            Self::UInt16 => EncodingMask::UINT16,
            Self::Int32 => EncodingMask::INT32,
            Self::UInt32 => EncodingMask::UINT32,
            Self::Int64 => EncodingMask::INT64,
            Self::UInt64 => EncodingMask::UINT64,
            Self::Float => EncodingMask::FLOAT,
            Self::Double => EncodingMask::DOUBLE,
            Self::String => EncodingMask::STRING,
            Self::DateTime => EncodingMask::DATE_TIME,
            Self::Guid => EncodingMask::GUID,
            Self::StatusCode => EncodingMask::STATUS_CODE,
            Self::ByteString => EncodingMask::BYTE_STRING,
            Self::XmlElement => EncodingMask::XML_ELEMENT,
            Self::QualifiedName => EncodingMask::QUALIFIED_NAME,
            Self::LocalizedText => EncodingMask::LOCALIZED_TEXT,
            Self::NodeId => EncodingMask::NODE_ID,
            Self::ExpandedNodeId => EncodingMask::EXPANDED_NODE_ID,
            Self::ExtensionObject => EncodingMask::EXTENSION_OBJECT,
            Self::Variant => EncodingMask::VARIANT,
            Self::DataValue => EncodingMask::DATA_VALUE,
            Self::DiagnosticInfo => EncodingMask::DIAGNOSTIC_INFO,
        }
    }

    /// Try to get a scalar type from the encoding mask.
    pub fn from_encoding_mask(encoding_mask: u8) -> Option<Self> {
        Some(match encoding_mask & !EncodingMask::ARRAY_MASK {
            EncodingMask::BOOLEAN => Self::Boolean,
            EncodingMask::SBYTE => Self::SByte,
            EncodingMask::BYTE => Self::Byte,
            EncodingMask::INT16 => Self::Int16,
            EncodingMask::UINT16 => Self::UInt16,
            EncodingMask::INT32 => Self::Int32,
            EncodingMask::UINT32 => Self::UInt32,
            EncodingMask::INT64 => Self::Int64,
            EncodingMask::UINT64 => Self::UInt64,
            EncodingMask::FLOAT => Self::Float,
            EncodingMask::DOUBLE => Self::Double,
            EncodingMask::STRING => Self::String,
            EncodingMask::DATE_TIME => Self::DateTime,
            EncodingMask::GUID => Self::Guid,
            EncodingMask::STATUS_CODE => Self::StatusCode,
            EncodingMask::BYTE_STRING => Self::ByteString,
            EncodingMask::XML_ELEMENT => Self::XmlElement,
            EncodingMask::QUALIFIED_NAME => Self::QualifiedName,
            EncodingMask::LOCALIZED_TEXT => Self::LocalizedText,
            EncodingMask::NODE_ID => Self::NodeId,
            EncodingMask::EXPANDED_NODE_ID => Self::ExpandedNodeId,
            EncodingMask::EXTENSION_OBJECT => Self::ExtensionObject,
            EncodingMask::VARIANT => Self::Variant,
            EncodingMask::DATA_VALUE => Self::DataValue,
            EncodingMask::DIAGNOSTIC_INFO => Self::DiagnosticInfo,
            _ => {
                return None;
            }
        })
    }

    /// Tests and returns true if the variant holds a numeric type
    pub fn is_numeric(&self) -> bool {
        matches!(
            self,
            Self::SByte
                | Self::Byte
                | Self::Int16
                | Self::UInt16
                | Self::Int32
                | Self::UInt32
                | Self::Int64
                | Self::UInt64
                | Self::Float
                | Self::Double
        )
    }

    /// Returns a data precedence rank for scalar types, OPC UA part 4 table 119. This is used
    /// when operators are comparing values of differing types. The type with
    /// the highest precedence dictates how values are converted in order to be compared.
    pub fn precedence(&self) -> u8 {
        match self {
            Self::Double => 1,
            Self::Float => 2,
            Self::Int64 => 3,
            Self::UInt64 => 4,
            Self::Int32 => 5,
            Self::UInt32 => 6,
            Self::StatusCode => 7,
            Self::Int16 => 8,
            Self::UInt16 => 9,
            Self::SByte => 10,
            Self::Byte => 11,
            Self::Boolean => 12,
            Self::Guid => 13,
            Self::String => 14,
            Self::ExpandedNodeId => 15,
            Self::NodeId => 16,
            Self::LocalizedText => 17,
            Self::QualifiedName => 18,
            _ => 100,
        }
    }
}

impl VariantTypeId<'_> {
    /// Get the encoding mask.
    pub fn encoding_mask(&self) -> u8 {
        match self {
            // Null / Empty
            VariantTypeId::Empty => 0u8,
            // Scalar types
            VariantTypeId::Scalar(s) => s.encoding_mask(),
            VariantTypeId::Array(s, dims) => {
                let mask = s.encoding_mask() | EncodingMask::ARRAY_VALUES_BIT;
                if dims.is_some() {
                    mask | EncodingMask::ARRAY_DIMENSIONS_BIT
                } else {
                    mask
                }
            }
        }
    }

    /// Get the precedence when converting between different variant types.
    pub fn precedence(&self) -> u8 {
        match self {
            Self::Scalar(s) => s.precedence(),
            Self::Array(s, _) => s.precedence(),
            Self::Empty => 100,
        }
    }
}

pub(crate) struct EncodingMask;

impl EncodingMask {
    // These are values, not bits
    pub(crate) const BOOLEAN: u8 = DataTypeId::Boolean as u8;
    pub(crate) const SBYTE: u8 = DataTypeId::SByte as u8;
    pub(crate) const BYTE: u8 = DataTypeId::Byte as u8;
    pub(crate) const INT16: u8 = DataTypeId::Int16 as u8;
    pub(crate) const UINT16: u8 = DataTypeId::UInt16 as u8;
    pub(crate) const INT32: u8 = DataTypeId::Int32 as u8;
    pub(crate) const UINT32: u8 = DataTypeId::UInt32 as u8;
    pub(crate) const INT64: u8 = DataTypeId::Int64 as u8;
    pub(crate) const UINT64: u8 = DataTypeId::UInt64 as u8;
    pub(crate) const FLOAT: u8 = DataTypeId::Float as u8;
    pub(crate) const DOUBLE: u8 = DataTypeId::Double as u8;
    pub(crate) const STRING: u8 = DataTypeId::String as u8;
    pub(crate) const DATE_TIME: u8 = DataTypeId::DateTime as u8;
    pub(crate) const GUID: u8 = DataTypeId::Guid as u8;
    pub(crate) const BYTE_STRING: u8 = DataTypeId::ByteString as u8;
    pub(crate) const XML_ELEMENT: u8 = DataTypeId::XmlElement as u8;
    pub(crate) const NODE_ID: u8 = DataTypeId::NodeId as u8;
    pub(crate) const EXPANDED_NODE_ID: u8 = DataTypeId::ExpandedNodeId as u8;
    pub(crate) const STATUS_CODE: u8 = DataTypeId::StatusCode as u8;
    pub(crate) const QUALIFIED_NAME: u8 = DataTypeId::QualifiedName as u8;
    pub(crate) const LOCALIZED_TEXT: u8 = DataTypeId::LocalizedText as u8;
    pub(crate) const EXTENSION_OBJECT: u8 = 22; // DataTypeId::ExtensionObject as u8;
    pub(crate) const DATA_VALUE: u8 = DataTypeId::DataValue as u8;
    pub(crate) const VARIANT: u8 = 24;
    pub(crate) const DIAGNOSTIC_INFO: u8 = DataTypeId::DiagnosticInfo as u8;
    /// Bit indicates an array with dimensions
    pub(crate) const ARRAY_DIMENSIONS_BIT: u8 = 1 << 6;
    /// Bit indicates an array with values
    pub(crate) const ARRAY_VALUES_BIT: u8 = 1 << 7;

    pub(crate) const ARRAY_MASK: u8 =
        EncodingMask::ARRAY_DIMENSIONS_BIT | EncodingMask::ARRAY_VALUES_BIT;
}
