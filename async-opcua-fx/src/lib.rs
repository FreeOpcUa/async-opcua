//! OPC UA FX generated data types.

pub mod cm_ids;
pub mod connection_endpoint_definition_data_type;
pub mod establish;
pub mod generated;
pub mod last_activity_mask;
pub mod methods;
pub mod node_identifier;
pub mod portable_node_identifier;
pub mod pub_sub_connection_endpoint_mode_enum;

pub use connection_endpoint_definition_data_type::ConnectionEndpointDefinitionDataType;
pub use establish::{
    process_close_connections, process_establish_connections, EstablishResults,
    EstablishedEndpoint, FxConnectionState, FxVerifier,
};
pub use generated::cm::{enums::*, structs::*, GeneratedTypeLoader as CmGeneratedTypeLoader};
pub use generated::types::*;
pub use last_activity_mask::LastActivityMask;
pub use methods::{
    handle_close_connections, handle_establish_connections, register_fx_connection_methods,
};
pub use node_identifier::NodeIdentifier;
pub use portable_node_identifier::PortableNodeIdentifier;
pub use pub_sub_connection_endpoint_mode_enum::PubSubConnectionEndpointModeEnum;

const FX_CM_NAMESPACE: &str = "http://opcfoundation.org/UA/FX/CM/";
const FX_DATA_NAMESPACE: &str = "http://opcfoundation.org/UA/FX/Data/";

#[allow(non_camel_case_types, clippy::enum_variant_names)]
#[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
#[repr(u32)]
pub enum DataTypeId {
    NodeIdValuePair = 1028u32,
    PubSubCommunicationLinkConfigurationDataType = 1031u32,
    NodeIdArray = 1034u32,
    AssetVerificationResultDataType = 1038u32,
    PubSubCommunicationConfigurationResultDataType = 1039u32,
    ConnectionEndpointConfigurationDataType = 1044u32,
    PubSubCommunicationConfigurationDataType = 1045u32,
    AssetVerificationDataType = 1048u32,
    RelatedEndpointDataType = 3003u32,
    PubSubReserveCommunicationIds2DataType = 3005u32,
    PubSubConnectionEndpointParameterDataType = 3006u32,
    ConnectionEndpointConfigurationResultDataType = 3008u32,
    ConnectionEndpointDefinitionDataType = 3011u32,
    PubSubReserveCommunicationIdsResult2DataType = 3013u32,
    PubSubReserveCommunicationIdsDataType = 3018u32,
    PubSubReserveCommunicationIdsResultDataType = 3020u32,
    PubSubConnectionEndpointModeEnum = 31u32,
}

impl From<DataTypeId> for opcua_types::NodeId {
    fn from(id: DataTypeId) -> Self {
        opcua_types::NodeId::new(0, id as u32)
    }
}

impl From<DataTypeId> for opcua_types::ExpandedNodeId {
    fn from(id: DataTypeId) -> Self {
        Self {
            node_id: opcua_types::NodeId::new(0, id as u32),
            namespace_uri: Default::default(),
            server_index: 0,
        }
    }
}

#[allow(non_camel_case_types, clippy::enum_variant_names)]
#[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
#[repr(u32)]
pub enum ObjectId {
    NodeIdValuePair_Encoding_DefaultBinary = 1093u32,
    NodeIdValuePair_Encoding_DefaultXml = 1094u32,
    NodeIdValuePair_Encoding_DefaultJson = 1095u32,
    PubSubCommunicationLinkConfigurationDataType_Encoding_DefaultBinary = 1102u32,
    PubSubCommunicationLinkConfigurationDataType_Encoding_DefaultXml = 1103u32,
    PubSubCommunicationLinkConfigurationDataType_Encoding_DefaultJson = 1104u32,
    NodeIdArray_Encoding_DefaultBinary = 1111u32,
    NodeIdArray_Encoding_DefaultXml = 1112u32,
    NodeIdArray_Encoding_DefaultJson = 1113u32,
    ConnectionEndpointConfigurationDataType_Encoding_DefaultBinary = 1141u32,
    ConnectionEndpointConfigurationDataType_Encoding_DefaultXml = 1142u32,
    ConnectionEndpointConfigurationDataType_Encoding_DefaultJson = 1143u32,
    PubSubCommunicationConfigurationDataType_Encoding_DefaultBinary = 1144u32,
    PubSubCommunicationConfigurationDataType_Encoding_DefaultXml = 1145u32,
    PubSubCommunicationConfigurationDataType_Encoding_DefaultJson = 1146u32,
    AssetVerificationDataType_Encoding_DefaultBinary = 1153u32,
    AssetVerificationDataType_Encoding_DefaultXml = 1154u32,
    AssetVerificationDataType_Encoding_DefaultJson = 1155u32,
    AssetVerificationResultDataType_Encoding_DefaultBinary = 1205u32,
    AssetVerificationResultDataType_Encoding_DefaultXml = 1206u32,
    AssetVerificationResultDataType_Encoding_DefaultJson = 1207u32,
    PubSubCommunicationConfigurationResultDataType_Encoding_DefaultBinary = 1208u32,
    PubSubCommunicationConfigurationResultDataType_Encoding_DefaultXml = 1209u32,
    PubSubCommunicationConfigurationResultDataType_Encoding_DefaultJson = 1210u32,
    RelatedEndpointDataType_Encoding_DefaultBinary = 5001u32,
    RelatedEndpointDataType_Encoding_DefaultXml = 5002u32,
    RelatedEndpointDataType_Encoding_DefaultJson = 5003u32,
    PubSubReserveCommunicationIds2DataType_Encoding_DefaultBinary = 5004u32,
    PubSubReserveCommunicationIds2DataType_Encoding_DefaultXml = 5005u32,
    PubSubReserveCommunicationIds2DataType_Encoding_DefaultJson = 5006u32,
    PubSubReserveCommunicationIdsResult2DataType_Encoding_DefaultBinary = 5007u32,
    PubSubReserveCommunicationIdsResult2DataType_Encoding_DefaultXml = 5008u32,
    PubSubReserveCommunicationIdsResult2DataType_Encoding_DefaultJson = 5009u32,
    ConnectionEndpointDefinitionDataType_Encoding_DefaultBinary = 5054u32,
    ConnectionEndpointDefinitionDataType_Encoding_DefaultXml = 5055u32,
    ConnectionEndpointDefinitionDataType_Encoding_DefaultJson = 5056u32,
    PubSubConnectionEndpointParameterDataType_Encoding_DefaultBinary = 5060u32,
    PubSubConnectionEndpointParameterDataType_Encoding_DefaultXml = 5061u32,
    PubSubConnectionEndpointParameterDataType_Encoding_DefaultJson = 5062u32,
    PubSubReserveCommunicationIdsDataType_Encoding_DefaultBinary = 5082u32,
    PubSubReserveCommunicationIdsDataType_Encoding_DefaultXml = 5083u32,
    PubSubReserveCommunicationIdsDataType_Encoding_DefaultJson = 5084u32,
    PubSubReserveCommunicationIdsResultDataType_Encoding_DefaultBinary = 5088u32,
    PubSubReserveCommunicationIdsResultDataType_Encoding_DefaultXml = 5089u32,
    PubSubReserveCommunicationIdsResultDataType_Encoding_DefaultJson = 5090u32,
    ConnectionEndpointConfigurationResultDataType_Encoding_DefaultBinary = 5036u32,
    ConnectionEndpointConfigurationResultDataType_Encoding_DefaultXml = 5037u32,
    ConnectionEndpointConfigurationResultDataType_Encoding_DefaultJson = 5038u32,
}

impl From<ObjectId> for opcua_types::NodeId {
    fn from(id: ObjectId) -> Self {
        opcua_types::NodeId::new(0, id as u32)
    }
}

impl From<ObjectId> for opcua_types::ExpandedNodeId {
    fn from(id: ObjectId) -> Self {
        Self {
            node_id: opcua_types::NodeId::new(0, id as u32),
            namespace_uri: Default::default(),
            server_index: 0,
        }
    }
}
