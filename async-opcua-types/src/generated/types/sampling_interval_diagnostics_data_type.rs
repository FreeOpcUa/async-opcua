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
///https://reference.opcfoundation.org/v105/Core/docs/Part5/12.8
#[derive(Debug, Clone, PartialEq, Default)]
pub struct SamplingIntervalDiagnosticsDataType {
    pub sampling_interval: opcua::types::data_types::Duration,
    pub monitored_item_count: u32,
    pub max_monitored_item_count: u32,
    pub disabled_monitored_item_count: u32,
}
impl opcua::types::MessageInfo for SamplingIntervalDiagnosticsDataType {
    fn type_id(&self) -> opcua::types::ObjectId {
        opcua::types::ObjectId::SamplingIntervalDiagnosticsDataType_Encoding_DefaultBinary
    }
    fn json_type_id(&self) -> opcua::types::ObjectId {
        opcua::types::ObjectId::SamplingIntervalDiagnosticsDataType_Encoding_DefaultJson
    }
    fn xml_type_id(&self) -> opcua::types::ObjectId {
        opcua::types::ObjectId::SamplingIntervalDiagnosticsDataType_Encoding_DefaultXml
    }
    fn data_type_id(&self) -> opcua::types::DataTypeId {
        opcua::types::DataTypeId::SamplingIntervalDiagnosticsDataType
    }
}
