mod opcua {
    pub(super) use opcua_types as types;
}

#[derive(Debug, Clone, PartialEq, Default)]
#[opcua::types::ua_encodable]
pub enum NodeIdentifier {
    #[default]
    Null,
    Node(opcua::types::node_id::NodeId),
    Alias(opcua::types::string::UAString),
    IdentifierBrowsePath(opcua::types::RelativePath),
}

impl opcua::types::ExpandedMessageInfo for NodeIdentifier {
    fn full_type_id(&self) -> opcua::types::ExpandedNodeId {
        let id: opcua::types::NodeId =
            crate::cm_ids::ObjectId::NodeIdentifier_Encoding_DefaultBinary.into();
        opcua::types::ExpandedNodeId::from((id, crate::FX_CM_NAMESPACE))
    }

    fn full_json_type_id(&self) -> opcua::types::ExpandedNodeId {
        let id: opcua::types::NodeId =
            crate::cm_ids::ObjectId::NodeIdentifier_Encoding_DefaultJson.into();
        opcua::types::ExpandedNodeId::from((id, crate::FX_CM_NAMESPACE))
    }

    fn full_xml_type_id(&self) -> opcua::types::ExpandedNodeId {
        let id: opcua::types::NodeId =
            crate::cm_ids::ObjectId::NodeIdentifier_Encoding_DefaultXml.into();
        opcua::types::ExpandedNodeId::from((id, crate::FX_CM_NAMESPACE))
    }

    fn full_data_type_id(&self) -> opcua::types::ExpandedNodeId {
        let id: opcua::types::NodeId = crate::cm_ids::DataTypeId::NodeIdentifier.into();
        opcua::types::ExpandedNodeId::from((id, crate::FX_CM_NAMESPACE))
    }
}
