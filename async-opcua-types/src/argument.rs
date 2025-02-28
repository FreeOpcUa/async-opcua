// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2024 Adam Lock

//! The [`Argument`] type, used for input and output arguments of methods.
//!
//! OPC UA Part 3, 8.6:
//!
//! This Structured DataType defines a Method input or output argument specification.
//! It is for example used in the input and output argument Properties for Methods.
//! Its elements are described in Table 28.

use std::io::{Read, Write};

use crate::{
    encoding::{BinaryDecodable, BinaryEncodable, EncodingResult},
    localized_text::LocalizedText,
    node_id::NodeId,
    string::UAString,
    write_u32, Context, DataTypeId, Error, MessageInfo, ObjectId,
};

// From OPC UA Part 3 - Address Space Model 1.03 Specification
//
// This Structured DataType defines a Method input or output argument specification. It is for
// example used in the input and output argument Properties for Methods. Its elements are described in
// Table23

#[allow(unused)]
mod opcua {
    pub use crate as types;
}

#[derive(Clone, Debug, PartialEq, Default, crate::UaNullable)]
#[cfg_attr(feature = "json", derive(crate::JsonEncodable, crate::JsonDecodable))]
#[cfg_attr(
    feature = "xml",
    derive(crate::XmlEncodable, crate::XmlDecodable, crate::XmlType)
)]
/// OPC-UA method argument.
pub struct Argument {
    /// Argument name.
    pub name: UAString,
    /// Node ID of the argument data type.
    pub data_type: NodeId,
    /// Argument value rank.
    pub value_rank: i32,
    /// Argument array dimensions.
    pub array_dimensions: Option<Vec<u32>>,
    /// Argument description.
    pub description: LocalizedText,
}

impl MessageInfo for Argument {
    fn type_id(&self) -> ObjectId {
        ObjectId::Argument_Encoding_DefaultBinary
    }
    fn json_type_id(&self) -> ObjectId {
        ObjectId::Argument_Encoding_DefaultJson
    }
    fn xml_type_id(&self) -> ObjectId {
        ObjectId::Argument_Encoding_DefaultXml
    }
    fn data_type_id(&self) -> crate::DataTypeId {
        DataTypeId::Argument
    }
}

impl BinaryEncodable for Argument {
    fn byte_len(&self, ctx: &crate::Context<'_>) -> usize {
        let mut size = 0;
        size += self.name.byte_len(ctx);
        size += self.data_type.byte_len(ctx);
        size += self.value_rank.byte_len(ctx);
        size += self.array_dimensions.byte_len(ctx);
        size += self.description.byte_len(ctx);
        size
    }

    fn encode<S: Write + ?Sized>(&self, stream: &mut S, ctx: &Context<'_>) -> EncodingResult<()> {
        self.name.encode(stream, ctx)?;
        self.data_type.encode(stream, ctx)?;
        self.value_rank.encode(stream, ctx)?;
        // Encode the array dimensions
        if self.value_rank > 0 {
            if let Some(ref array_dimensions) = self.array_dimensions {
                if self.value_rank as usize != array_dimensions.len() {
                    return Err(Error::encoding(
                        format!("The array dimensions {} of the Argument should match value rank {} and they don't", array_dimensions.len(), self.value_rank)));
                }
                self.array_dimensions.encode(stream, ctx)?;
            } else {
                return Err(Error::encoding(format!("The array dimensions are expected in the Argument matching value rank {} and they aren't", self.value_rank)));
            }
        } else {
            write_u32(stream, 0u32)?;
        }

        self.description.encode(stream, ctx)?;
        Ok(())
    }
}

impl BinaryDecodable for Argument {
    fn decode<S: Read + ?Sized>(stream: &mut S, ctx: &Context<'_>) -> EncodingResult<Self> {
        let name = UAString::decode(stream, ctx)?;
        let data_type = NodeId::decode(stream, ctx)?;
        let value_rank = i32::decode(stream, ctx)?;
        // Decode array dimensions
        let array_dimensions: Option<Vec<u32>> = BinaryDecodable::decode(stream, ctx)?;
        if let Some(ref array_dimensions) = array_dimensions {
            if value_rank > 0 && value_rank as usize != array_dimensions.len() {
                return Err(Error::decoding(format!("The array dimensions {} of the Argument should match value rank {} and they don't", array_dimensions.len(), value_rank)));
            }
        }
        let description = LocalizedText::decode(stream, ctx)?;
        Ok(Argument {
            name,
            data_type,
            value_rank,
            array_dimensions,
            description,
        })
    }
}
