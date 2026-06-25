#[allow(non_camel_case_types, clippy::enum_variant_names)]
#[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
#[repr(u32)]
pub enum DataTypeId {
    PortableKeyValuePair = 1035u32,
    ServerAddressDataType = 1036u32,
    PortableRelativePath = 1047u32,
    PortableRelativePathElement = 1051u32,
    FxEditEnum = 3001u32,
    FxProcessEnum = 3002u32,
    CommunicationFlowQosDataType = 3004u32,
    PortableNodeIdentifierValuePair = 3005u32,
    NodeIdTranslationDataType = 3006u32,
    ConnectionDiagnosticsDataType = 3008u32,
    LastActivityMask = 3009u32,
    ConnectionStateEnum = 3011u32,
    PortableNodeIdentifier = 3012u32,
    FxErrorEnum = 3015u32,
    SecurityKeyServerAddressDataType = 3021u32,
    ConnectionConfigurationSetConfDataType = 13003u32,
    ConnectionConfigurationConfDataType = 13006u32,
    ConnectionEndpointConfigurationConfDataType = 13009u32,
    CommunicationFlowConfigurationConfDataType = 13012u32,
    PubSubCommunicationFlowConfigurationConfDataType = 13015u32,
    SubscriberConfigurationConfDataType = 13018u32,
    AutomationComponentConfigurationConfDataType = 13021u32,
    SecurityKeyServerAddressConfDataType = 13024u32,
    ServerAddressConfDataType = 13027u32,
    AssetVerificationConfDataType = 13030u32,
    CommunicationModelConfigurationDataType = 13033u32,
    PubSubCommunicationModelConfigurationDataType = 13036u32,
    NodeIdentifier = 13039u32,
    NodeIdentifierValuePair = 13042u32,
    NodeIdTranslationConfDataType = 13045u32,
    AddressSelectionDataType = 13048u32,
    ReceiveQosSelectionDataType = 13051u32,
    ConnectionConfigurationSetOperation = 13054u32,
}

impl From<DataTypeId> for opcua_types::NodeId {
    fn from(id: DataTypeId) -> Self {
        opcua_types::NodeId::new(0, id as u32)
    }
}

impl From<DataTypeId> for opcua_types::ExpandedNodeId {
    fn from(id: DataTypeId) -> Self {
        let node_id = opcua_types::NodeId::new(0, id as u32);
        opcua_types::ExpandedNodeId::from((node_id, crate::FX_CM_NAMESPACE))
    }
}

#[allow(non_camel_case_types, clippy::enum_variant_names)]
#[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
#[repr(u32)]
pub enum ObjectId {
    PortableKeyValuePair_Encoding_DefaultBinary = 1114u32,
    PortableKeyValuePair_Encoding_DefaultXml = 1115u32,
    PortableKeyValuePair_Encoding_DefaultJson = 1116u32,
    ServerAddressDataType_Encoding_DefaultBinary = 1117u32,
    ServerAddressDataType_Encoding_DefaultXml = 1118u32,
    ServerAddressDataType_Encoding_DefaultJson = 1119u32,
    PortableRelativePath_Encoding_DefaultBinary = 1159u32,
    PortableRelativePath_Encoding_DefaultXml = 1160u32,
    PortableRelativePath_Encoding_DefaultJson = 1161u32,
    PortableRelativePathElement_Encoding_DefaultBinary = 1222u32,
    PortableRelativePathElement_Encoding_DefaultXml = 1223u32,
    PortableRelativePathElement_Encoding_DefaultJson = 1224u32,
    PortableNodeIdentifierValuePair_Encoding_DefaultXml = 5012u32,
    PortableNodeIdentifierValuePair_Encoding_DefaultJson = 5015u32,
    PortableNodeIdentifierValuePair_Encoding_DefaultBinary = 5016u32,
    CommunicationFlowQosDataType_Encoding_DefaultBinary = 5017u32,
    CommunicationFlowQosDataType_Encoding_DefaultXml = 5018u32,
    CommunicationFlowQosDataType_Encoding_DefaultJson = 5019u32,
    NodeIdTranslationDataType_Encoding_DefaultBinary = 5025u32,
    NodeIdTranslationDataType_Encoding_DefaultXml = 5026u32,
    NodeIdTranslationDataType_Encoding_DefaultJson = 5027u32,
    ConnectionConfigurationSetConfDataType_Encoding_DefaultBinary = 5029u32,
    ConnectionConfigurationSetConfDataType_Encoding_DefaultXml = 5030u32,
    ConnectionConfigurationSetConfDataType_Encoding_DefaultJson = 5031u32,
    ConnectionConfigurationConfDataType_Encoding_DefaultBinary = 5032u32,
    ConnectionConfigurationConfDataType_Encoding_DefaultXml = 5033u32,
    ConnectionConfigurationConfDataType_Encoding_DefaultJson = 5034u32,
    ConnectionEndpointConfigurationConfDataType_Encoding_DefaultBinary = 5035u32,
    ConnectionEndpointConfigurationConfDataType_Encoding_DefaultXml = 5036u32,
    ConnectionEndpointConfigurationConfDataType_Encoding_DefaultJson = 5037u32,
    PubSubCommunicationFlowConfigurationConfDataType_Encoding_DefaultBinary = 5038u32,
    PubSubCommunicationFlowConfigurationConfDataType_Encoding_DefaultXml = 5039u32,
    PubSubCommunicationFlowConfigurationConfDataType_Encoding_DefaultJson = 5040u32,
    SubscriberConfigurationConfDataType_Encoding_DefaultBinary = 5041u32,
    SubscriberConfigurationConfDataType_Encoding_DefaultXml = 5042u32,
    SubscriberConfigurationConfDataType_Encoding_DefaultJson = 5043u32,
    AutomationComponentConfigurationConfDataType_Encoding_DefaultBinary = 5044u32,
    AutomationComponentConfigurationConfDataType_Encoding_DefaultXml = 5048u32,
    AutomationComponentConfigurationConfDataType_Encoding_DefaultJson = 5049u32,
    SecurityKeyServerAddressConfDataType_Encoding_DefaultBinary = 5050u32,
    SecurityKeyServerAddressConfDataType_Encoding_DefaultXml = 5051u32,
    SecurityKeyServerAddressConfDataType_Encoding_DefaultJson = 5054u32,
    ServerAddressConfDataType_Encoding_DefaultBinary = 5055u32,
    ServerAddressConfDataType_Encoding_DefaultXml = 5056u32,
    PortableNodeIdentifier_Encoding_DefaultBinary = 5057u32,
    PortableNodeIdentifier_Encoding_DefaultXml = 5058u32,
    PortableNodeIdentifier_Encoding_DefaultJson = 5059u32,
    ServerAddressConfDataType_Encoding_DefaultJson = 5060u32,
    AssetVerificationConfDataType_Encoding_DefaultBinary = 5061u32,
    AssetVerificationConfDataType_Encoding_DefaultXml = 5062u32,
    AssetVerificationConfDataType_Encoding_DefaultJson = 5063u32,
    PubSubCommunicationModelConfigurationDataType_Encoding_DefaultBinary = 5064u32,
    PubSubCommunicationModelConfigurationDataType_Encoding_DefaultXml = 5065u32,
    PubSubCommunicationModelConfigurationDataType_Encoding_DefaultJson = 5066u32,
    NodeIdentifier_Encoding_DefaultBinary = 5067u32,
    NodeIdentifier_Encoding_DefaultXml = 5068u32,
    NodeIdentifier_Encoding_DefaultJson = 5069u32,
    NodeIdentifierValuePair_Encoding_DefaultBinary = 5070u32,
    NodeIdentifierValuePair_Encoding_DefaultXml = 5071u32,
    NodeIdentifierValuePair_Encoding_DefaultJson = 5072u32,
    NodeIdTranslationConfDataType_Encoding_DefaultBinary = 5073u32,
    NodeIdTranslationConfDataType_Encoding_DefaultXml = 5074u32,
    NodeIdTranslationConfDataType_Encoding_DefaultJson = 5075u32,
    AddressSelectionDataType_Encoding_DefaultBinary = 5076u32,
    AddressSelectionDataType_Encoding_DefaultXml = 5077u32,
    AddressSelectionDataType_Encoding_DefaultJson = 5078u32,
    ReceiveQosSelectionDataType_Encoding_DefaultBinary = 5080u32,
    ReceiveQosSelectionDataType_Encoding_DefaultXml = 5081u32,
    ReceiveQosSelectionDataType_Encoding_DefaultJson = 5082u32,
    ConnectionDiagnosticsDataType_Encoding_DefaultBinary = 5088u32,
    ConnectionDiagnosticsDataType_Encoding_DefaultXml = 5089u32,
    ConnectionDiagnosticsDataType_Encoding_DefaultJson = 5090u32,
    SecurityKeyServerAddressDataType_Encoding_DefaultBinary = 5091u32,
    SecurityKeyServerAddressDataType_Encoding_DefaultXml = 5092u32,
    SecurityKeyServerAddressDataType_Encoding_DefaultJson = 5093u32,
}

impl From<ObjectId> for opcua_types::NodeId {
    fn from(id: ObjectId) -> Self {
        opcua_types::NodeId::new(0, id as u32)
    }
}

impl From<ObjectId> for opcua_types::ExpandedNodeId {
    fn from(id: ObjectId) -> Self {
        let node_id = opcua_types::NodeId::new(0, id as u32);
        opcua_types::ExpandedNodeId::from((node_id, crate::FX_CM_NAMESPACE))
    }
}
