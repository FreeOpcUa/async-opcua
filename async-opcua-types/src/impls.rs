use std::{self, fmt};

use tracing::error;

use crate::{
    argument::Argument,
    attribute::AttributeId,
    byte_string::ByteString,
    constants,
    localized_text::LocalizedText,
    node_id::NodeId,
    profiles,
    qualified_name::QualifiedName,
    response_header::{AsRequestHandle, ResponseHeader},
    status_code::StatusCode,
    string::UAString,
    variant::Variant,
    AnonymousIdentityToken, ApplicationDescription, CallMethodRequest, DataTypeId, DataValue,
    EndpointDescription, Error, ExpandedNodeId, HistoryUpdateType, IdentityCriteriaType,
    MessageSecurityMode, MonitoredItemCreateRequest, MonitoringMode, MonitoringParameters,
    NumericRange, ObjectId, ReadValueId, ServiceCounterDataType, ServiceFault, SignatureData,
    UserNameIdentityToken, UserTokenPolicy, UserTokenType, WriteValue,
};

use super::PerformUpdateType;

/// Implemented by messages
pub trait MessageInfo {
    /// The binary type id associated with the message
    fn type_id(&self) -> ObjectId;
    /// The JSON type id associated with the message.
    fn json_type_id(&self) -> ObjectId;
    /// The XML type id associated with the message.
    fn xml_type_id(&self) -> ObjectId;
    /// The data type id associated with the message.
    fn data_type_id(&self) -> DataTypeId;
}

/// Trait implemented by all messages, allowing for custom message types.
pub trait ExpandedMessageInfo {
    /// The binary type id associated with the message.
    fn full_type_id(&self) -> ExpandedNodeId;
    /// The JSON type id associated with the message.
    fn full_json_type_id(&self) -> ExpandedNodeId;
    /// The XML type id associated with the message.
    fn full_xml_type_id(&self) -> ExpandedNodeId;
    /// The data type ID associated with the message.
    fn full_data_type_id(&self) -> ExpandedNodeId;
}

impl<T> ExpandedMessageInfo for T
where
    T: MessageInfo,
{
    fn full_type_id(&self) -> ExpandedNodeId {
        self.type_id().into()
    }

    fn full_json_type_id(&self) -> ExpandedNodeId {
        self.json_type_id().into()
    }

    fn full_xml_type_id(&self) -> ExpandedNodeId {
        self.xml_type_id().into()
    }

    fn full_data_type_id(&self) -> ExpandedNodeId {
        self.data_type_id().into()
    }
}

impl ServiceFault {
    /// Create a new ServiceFault from a request handle and a status code.
    pub fn new(request_header: impl AsRequestHandle, service_result: StatusCode) -> ServiceFault {
        ServiceFault {
            response_header: ResponseHeader::new_service_result(request_header, service_result),
        }
    }
}

impl UserTokenPolicy {
    /// Return the anonymous user token policy.
    pub fn anonymous() -> UserTokenPolicy {
        UserTokenPolicy {
            policy_id: UAString::from("anonymous"),
            token_type: UserTokenType::Anonymous,
            issued_token_type: UAString::null(),
            issuer_endpoint_url: UAString::null(),
            security_policy_uri: UAString::null(),
        }
    }
}

impl EndpointDescription {
    /// Returns a reference to a policy that matches the supplied token type, otherwise None
    pub fn find_policy(&self, token_type: UserTokenType) -> Option<&UserTokenPolicy> {
        if let Some(ref policies) = self.user_identity_tokens {
            policies.iter().find(|t| t.token_type == token_type)
        } else {
            None
        }
    }

    /// Returns a reference to a policy that matches the supplied policy id
    pub fn find_policy_by_id(&self, policy_id: &str) -> Option<&UserTokenPolicy> {
        if let Some(ref policies) = self.user_identity_tokens {
            policies.iter().find(|t| t.policy_id.as_ref() == policy_id)
        } else {
            None
        }
    }
}

impl UserNameIdentityToken {
    /// Ensures the token is valid
    pub fn is_valid(&self) -> bool {
        !self.user_name.is_null() && !self.password.is_null()
    }

    /// Get the plaintext password as a string, if possible.
    pub fn plaintext_password(&self) -> Result<String, Error> {
        if !self.encryption_algorithm.is_empty() {
            // Should not be calling this function at all encryption is applied
            panic!();
        }
        String::from_utf8(self.password.as_ref().to_vec()).map_err(Error::decoding)
    }

    /// Authenticates the token against the supplied username and password.
    pub fn authenticate(&self, username: &str, password: &[u8]) -> Result<(), StatusCode> {
        // No comparison will be made unless user and pass are explicitly set to something in the token
        // Even if someone has a blank password, client should pass an empty string, not null.
        let valid = if self.is_valid() {
            // Plaintext encryption
            if self.encryption_algorithm.is_null() {
                // Password shall be a UTF-8 encoded string
                let id_user = self.user_name.as_ref();
                let id_pass = self.password.value.as_ref().unwrap();
                if username == id_user {
                    if password == id_pass.as_slice() {
                        true
                    } else {
                        error!("Authentication error: User name {} supplied by client is recognised but password is not", username);
                        false
                    }
                } else {
                    error!("Authentication error: User name supplied by client is unrecognised");
                    false
                }
            } else {
                // TODO See 7.36.3. UserTokenPolicy and SecurityPolicy should be used to provide
                //  a means to encrypt a password and not send it plain text. Sending a plaintext
                //  password over unsecured network is a bad thing!!!
                error!(
                    "Authentication error: Unsupported encryption algorithm {}",
                    self.encryption_algorithm.as_ref()
                );
                false
            }
        } else {
            error!("Authentication error: User / pass credentials not supplied in token");
            false
        };
        if valid {
            Ok(())
        } else {
            Err(StatusCode::BadIdentityTokenRejected)
        }
    }
}

impl<'a> From<&'a NodeId> for ReadValueId {
    fn from(node_id: &'a NodeId) -> Self {
        Self::from(node_id.clone())
    }
}

impl From<NodeId> for ReadValueId {
    fn from(node_id: NodeId) -> Self {
        ReadValueId {
            node_id,
            attribute_id: AttributeId::Value as u32,
            index_range: NumericRange::None,
            data_encoding: QualifiedName::null(),
        }
    }
}

impl<'a> From<(u16, &'a str)> for ReadValueId {
    fn from(v: (u16, &'a str)) -> Self {
        Self::from(NodeId::from(v))
    }
}

impl ReadValueId {
    /// Create a new simple read value ID.
    pub fn new(node_id: NodeId, attribute_id: AttributeId) -> Self {
        Self {
            node_id,
            attribute_id: attribute_id as u32,
            ..Default::default()
        }
    }

    /// Create a new read value ID for values.
    pub fn new_value(node_id: NodeId) -> Self {
        Self {
            node_id,
            attribute_id: AttributeId::Value as u32,
            ..Default::default()
        }
    }
}

impl Default for AnonymousIdentityToken {
    fn default() -> Self {
        AnonymousIdentityToken {
            policy_id: UAString::from(profiles::SECURITY_USER_TOKEN_POLICY_ANONYMOUS),
        }
    }
}

impl SignatureData {
    /// Return an empty SignatureData.
    pub fn null() -> SignatureData {
        SignatureData {
            algorithm: UAString::null(),
            signature: ByteString::null(),
        }
    }
}

impl From<NodeId> for MonitoredItemCreateRequest {
    fn from(value: NodeId) -> Self {
        Self::new(
            value.into(),
            MonitoringMode::Reporting,
            MonitoringParameters::default(),
        )
    }
}

impl MonitoredItemCreateRequest {
    /// Adds an item to monitor to the subscription
    pub fn new(
        item_to_monitor: ReadValueId,
        monitoring_mode: MonitoringMode,
        requested_parameters: MonitoringParameters,
    ) -> MonitoredItemCreateRequest {
        MonitoredItemCreateRequest {
            item_to_monitor,
            monitoring_mode,
            requested_parameters,
        }
    }
}

impl From<(NodeId, NodeId, Option<Vec<Variant>>)> for CallMethodRequest {
    fn from(value: (NodeId, NodeId, Option<Vec<Variant>>)) -> Self {
        Self {
            object_id: value.0,
            method_id: value.1,
            input_arguments: value.2,
        }
    }
}

impl<'a> From<&'a str> for EndpointDescription {
    fn from(v: &'a str) -> Self {
        EndpointDescription::from((
            v,
            constants::SECURITY_POLICY_NONE_URI,
            MessageSecurityMode::None,
        ))
    }
}

impl<'a> From<(&'a str, &'a str, MessageSecurityMode)> for EndpointDescription {
    fn from(v: (&'a str, &'a str, MessageSecurityMode)) -> Self {
        EndpointDescription::from((v.0, v.1, v.2, None))
    }
}

impl<'a> From<(&'a str, &'a str, MessageSecurityMode, UserTokenPolicy)> for EndpointDescription {
    fn from(v: (&'a str, &'a str, MessageSecurityMode, UserTokenPolicy)) -> Self {
        EndpointDescription::from((v.0, v.1, v.2, Some(vec![v.3])))
    }
}

impl<'a> From<(&'a str, &'a str, MessageSecurityMode, Vec<UserTokenPolicy>)>
    for EndpointDescription
{
    fn from(v: (&'a str, &'a str, MessageSecurityMode, Vec<UserTokenPolicy>)) -> Self {
        EndpointDescription::from((v.0, v.1, v.2, Some(v.3)))
    }
}

impl<'a>
    From<(
        &'a str,
        &'a str,
        MessageSecurityMode,
        Option<Vec<UserTokenPolicy>>,
    )> for EndpointDescription
{
    fn from(
        v: (
            &'a str,
            &'a str,
            MessageSecurityMode,
            Option<Vec<UserTokenPolicy>>,
        ),
    ) -> Self {
        EndpointDescription {
            endpoint_url: UAString::from(v.0),
            security_policy_uri: UAString::from(v.1),
            security_mode: v.2,
            server: ApplicationDescription::default(),
            security_level: 0,
            server_certificate: ByteString::null(),
            transport_profile_uri: UAString::null(),
            user_identity_tokens: v.3,
        }
    }
}

const MESSAGE_SECURITY_MODE_NONE: &str = "None";
const MESSAGE_SECURITY_MODE_SIGN: &str = "Sign";
const MESSAGE_SECURITY_MODE_SIGN_AND_ENCRYPT: &str = "SignAndEncrypt";

impl fmt::Display for MessageSecurityMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            MessageSecurityMode::None => MESSAGE_SECURITY_MODE_NONE,
            MessageSecurityMode::Sign => MESSAGE_SECURITY_MODE_SIGN,
            MessageSecurityMode::SignAndEncrypt => MESSAGE_SECURITY_MODE_SIGN_AND_ENCRYPT,
            _ => "",
        };
        write!(f, "{}", name)
    }
}

impl From<MessageSecurityMode> for String {
    fn from(security_mode: MessageSecurityMode) -> Self {
        security_mode.to_string()
    }
}

impl<'a> From<&'a str> for MessageSecurityMode {
    fn from(str: &'a str) -> Self {
        match str {
            MESSAGE_SECURITY_MODE_NONE => MessageSecurityMode::None,
            MESSAGE_SECURITY_MODE_SIGN => MessageSecurityMode::Sign,
            MESSAGE_SECURITY_MODE_SIGN_AND_ENCRYPT => MessageSecurityMode::SignAndEncrypt,
            _ => {
                error!("Specified security mode \"{}\" is not recognized", str);
                MessageSecurityMode::Invalid
            }
        }
    }
}

impl From<(&str, DataTypeId)> for Argument {
    fn from(v: (&str, DataTypeId)) -> Self {
        Argument {
            name: UAString::from(v.0),
            data_type: v.1.into(),
            value_rank: -1,
            array_dimensions: None,
            description: LocalizedText::null(),
        }
    }
}

impl ServiceCounterDataType {
    /// Register a successful entry.
    pub fn success(&mut self) {
        self.total_count += 1;
    }

    /// Register an error.
    pub fn error(&mut self) {
        self.total_count += 1;
        self.error_count += 1;
    }
}

impl Default for PerformUpdateType {
    fn default() -> Self {
        Self::Insert
    }
}

impl Default for NumericRange {
    fn default() -> Self {
        Self::None
    }
}

/* impl Default for ServerState {
    fn default() -> Self {
        Self::Shutdown
    }
} */

impl Default for HistoryUpdateType {
    fn default() -> Self {
        Self::Insert
    }
}

impl Default for IdentityCriteriaType {
    fn default() -> Self {
        Self::Anonymous
    }
}

impl WriteValue {
    /// default constructor with all struct members
    pub fn new(
        node_id: NodeId,
        attribute_id: AttributeId,
        index_range: NumericRange,
        value: DataValue,
    ) -> Self {
        Self {
            node_id,
            attribute_id: attribute_id as u32,
            index_range,
            value,
        }
    }

    /// return a WriteValue with AttributeId::Value and no index rane,
    ///  which is the most common case
    pub fn value_attr(node_id: NodeId, val: Variant) -> Self {
        Self {
            node_id,
            attribute_id: AttributeId::Value as u32,
            index_range: NumericRange::None,
            value: val.into(),
        }
    }
}
