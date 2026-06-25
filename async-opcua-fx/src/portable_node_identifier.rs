mod opcua {
    pub(super) use opcua_types as types;
}

#[derive(Debug, Clone, PartialEq, Default)]
#[opcua::types::ua_encodable]
pub enum PortableNodeIdentifier {
    #[default]
    Null,
    Node(opcua::types::portable_node_id::PortableNodeId),
    Alias(opcua::types::string::UAString),
    IdentifierBrowsePath(crate::generated::cm::structs::PortableRelativePath),
}

impl opcua::types::ExpandedMessageInfo for PortableNodeIdentifier {
    fn full_type_id(&self) -> opcua::types::ExpandedNodeId {
        let id: opcua::types::NodeId =
            crate::cm_ids::ObjectId::PortableNodeIdentifier_Encoding_DefaultBinary.into();
        opcua::types::ExpandedNodeId::from((id, crate::FX_CM_NAMESPACE))
    }

    fn full_json_type_id(&self) -> opcua::types::ExpandedNodeId {
        let id: opcua::types::NodeId =
            crate::cm_ids::ObjectId::PortableNodeIdentifier_Encoding_DefaultJson.into();
        opcua::types::ExpandedNodeId::from((id, crate::FX_CM_NAMESPACE))
    }

    fn full_xml_type_id(&self) -> opcua::types::ExpandedNodeId {
        let id: opcua::types::NodeId =
            crate::cm_ids::ObjectId::PortableNodeIdentifier_Encoding_DefaultXml.into();
        opcua::types::ExpandedNodeId::from((id, crate::FX_CM_NAMESPACE))
    }

    fn full_data_type_id(&self) -> opcua::types::ExpandedNodeId {
        let id: opcua::types::NodeId = crate::cm_ids::DataTypeId::PortableNodeIdentifier.into();
        opcua::types::ExpandedNodeId::from((id, crate::FX_CM_NAMESPACE))
    }
}
