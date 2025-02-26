// This file was autogenerated from schemas/1.05/Opc.Ua.Types.bsd by async-opcua-codegen
//
// DO NOT EDIT THIS FILE

// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2024 Adam Lock, Einar Omang
#[allow(unused)]
mod opcua {
    pub use crate as types;
}
#[derive(Debug, Clone, PartialEq, opcua::types::BinaryEncodable, opcua::types::BinaryDecodable)]
#[cfg_attr(
    feature = "json",
    derive(opcua::types::JsonEncodable, opcua::types::JsonDecodable)
)]
#[cfg_attr(
    feature = "xml",
    derive(
        opcua::types::XmlEncodable,
        opcua::types::XmlDecodable,
        opcua::types::XmlType
    )
)]
#[derive(Default)]
pub struct EndpointConfiguration {
    pub operation_timeout: i32,
    pub use_binary_encoding: bool,
    pub max_string_length: i32,
    pub max_byte_string_length: i32,
    pub max_array_length: i32,
    pub max_message_size: i32,
    pub max_buffer_size: i32,
    pub channel_lifetime: i32,
    pub security_token_lifetime: i32,
}
impl opcua::types::MessageInfo for EndpointConfiguration {
    fn type_id(&self) -> opcua::types::ObjectId {
        opcua::types::ObjectId::EndpointConfiguration_Encoding_DefaultBinary
    }
    fn json_type_id(&self) -> opcua::types::ObjectId {
        opcua::types::ObjectId::EndpointConfiguration_Encoding_DefaultJson
    }
    fn xml_type_id(&self) -> opcua::types::ObjectId {
        opcua::types::ObjectId::EndpointConfiguration_Encoding_DefaultXml
    }
    fn data_type_id(&self) -> opcua::types::DataTypeId {
        opcua::types::DataTypeId::EndpointConfiguration
    }
}
