mod opcua {
    pub(super) use opcua_types as types;
}

#[derive(Debug, Clone, PartialEq, Default)]
#[opcua::types::ua_encodable]
pub enum ConnectionEndpointDefinitionDataType {
    #[default]
    Null,
    Parameter(opcua::types::ExtensionObject),
    Node(opcua::types::NodeId),
}

impl opcua::types::ExpandedMessageInfo for ConnectionEndpointDefinitionDataType {
    fn full_type_id(&self) -> opcua::types::ExpandedNodeId {
        let id: opcua::types::NodeId =
            crate::ObjectId::ConnectionEndpointDefinitionDataType_Encoding_DefaultBinary.into();
        opcua::types::ExpandedNodeId::from((id, crate::FX_DATA_NAMESPACE))
    }

    fn full_json_type_id(&self) -> opcua::types::ExpandedNodeId {
        let id: opcua::types::NodeId =
            crate::ObjectId::ConnectionEndpointDefinitionDataType_Encoding_DefaultJson.into();
        opcua::types::ExpandedNodeId::from((id, crate::FX_DATA_NAMESPACE))
    }

    fn full_xml_type_id(&self) -> opcua::types::ExpandedNodeId {
        let id: opcua::types::NodeId =
            crate::ObjectId::ConnectionEndpointDefinitionDataType_Encoding_DefaultXml.into();
        opcua::types::ExpandedNodeId::from((id, crate::FX_DATA_NAMESPACE))
    }

    fn full_data_type_id(&self) -> opcua::types::ExpandedNodeId {
        let id: opcua::types::NodeId =
            crate::DataTypeId::ConnectionEndpointDefinitionDataType.into();
        opcua::types::ExpandedNodeId::from((id, crate::FX_DATA_NAMESPACE))
    }
}
