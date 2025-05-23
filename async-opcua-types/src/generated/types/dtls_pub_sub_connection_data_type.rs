// This file was autogenerated from schemas/1.05/Opc.Ua.NodeSet2.Services.xml by async-opcua-codegen
//
// DO NOT EDIT THIS FILE

// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2024 Adam Lock, Einar Omang
#[allow(unused)]
mod opcua {
    pub(super) use crate as types;
}
#[opcua::types::ua_encodable]
///https://reference.opcfoundation.org/v105/Core/docs/Part14/6.4.1/#6.4.1.7.6
#[derive(Debug, Clone, PartialEq, Default)]
pub struct DtlsPubSubConnectionDataType {
    pub client_cipher_suite: opcua::types::string::UAString,
    pub server_cipher_suites: Option<Vec<opcua::types::string::UAString>>,
    pub zero_rtt: bool,
    pub certificate_group_id: opcua::types::node_id::NodeId,
    pub verify_client_certificate: bool,
}
impl opcua::types::MessageInfo for DtlsPubSubConnectionDataType {
    fn type_id(&self) -> opcua::types::ObjectId {
        opcua::types::ObjectId::DtlsPubSubConnectionDataType_Encoding_DefaultBinary
    }
    fn json_type_id(&self) -> opcua::types::ObjectId {
        opcua::types::ObjectId::DtlsPubSubConnectionDataType_Encoding_DefaultJson
    }
    fn xml_type_id(&self) -> opcua::types::ObjectId {
        opcua::types::ObjectId::DtlsPubSubConnectionDataType_Encoding_DefaultXml
    }
    fn data_type_id(&self) -> opcua::types::DataTypeId {
        opcua::types::DataTypeId::DtlsPubSubConnectionDataType
    }
}
