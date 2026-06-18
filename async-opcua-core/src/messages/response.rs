use crate::comms::message_chunk::MessageChunkType;

use super::{Message, MessageType};
use opcua_types::*;
use std::io::{Read, Write};
use std::sync::Arc;

#[derive(Debug, PartialEq, Clone)]
/// Publish response body that shares the notification message allocation.
pub struct PublishResponseShared {
    /// Common response header.
    pub response_header: ResponseHeader,
    /// Subscription identifier.
    pub subscription_id: IntegerId,
    /// Sequence numbers available for republish.
    pub available_sequence_numbers: Option<Vec<Counter>>,
    /// Whether more notifications are available after this response.
    pub more_notifications: bool,
    /// Shared notification message.
    pub notification_message: Arc<NotificationMessage>,
    /// Acknowledgement results.
    pub results: Option<Vec<StatusCode>>,
    /// Diagnostic information.
    pub diagnostic_infos: Option<Vec<DiagnosticInfo>>,
}

impl MessageInfo for PublishResponseShared {
    fn type_id(&self) -> ObjectId {
        ObjectId::PublishResponse_Encoding_DefaultBinary
    }

    fn json_type_id(&self) -> ObjectId {
        ObjectId::PublishResponse_Encoding_DefaultJson
    }

    fn xml_type_id(&self) -> ObjectId {
        ObjectId::PublishResponse_Encoding_DefaultXml
    }

    fn data_type_id(&self) -> DataTypeId {
        DataTypeId::PublishResponse
    }
}

impl BinaryEncodable for PublishResponseShared {
    fn byte_len(&self, ctx: &opcua_types::Context<'_>) -> usize {
        let mut size = 0usize;
        size += BinaryEncodable::byte_len(&self.response_header, ctx);
        size += BinaryEncodable::byte_len(&self.subscription_id, ctx);
        size += BinaryEncodable::byte_len(&self.available_sequence_numbers, ctx);
        size += BinaryEncodable::byte_len(&self.more_notifications, ctx);
        size += BinaryEncodable::byte_len(&self.notification_message, ctx);
        size += BinaryEncodable::byte_len(&self.results, ctx);
        size += BinaryEncodable::byte_len(&self.diagnostic_infos, ctx);
        size
    }

    fn encode<S: Write + ?Sized>(
        &self,
        stream: &mut S,
        ctx: &opcua_types::Context<'_>,
    ) -> EncodingResult<()> {
        BinaryEncodable::encode(&self.response_header, stream, ctx)?;
        BinaryEncodable::encode(&self.subscription_id, stream, ctx)?;
        BinaryEncodable::encode(&self.available_sequence_numbers, stream, ctx)?;
        BinaryEncodable::encode(&self.more_notifications, stream, ctx)?;
        BinaryEncodable::encode(&self.notification_message, stream, ctx)?;
        BinaryEncodable::encode(&self.results, stream, ctx)?;
        BinaryEncodable::encode(&self.diagnostic_infos, stream, ctx)?;
        Ok(())
    }
}

#[derive(Debug, PartialEq, Clone)]
/// Republish response body that shares the notification message allocation.
pub struct RepublishResponseShared {
    /// Common response header.
    pub response_header: ResponseHeader,
    /// Shared notification message.
    pub notification_message: Arc<NotificationMessage>,
}

impl MessageInfo for RepublishResponseShared {
    fn type_id(&self) -> ObjectId {
        ObjectId::RepublishResponse_Encoding_DefaultBinary
    }

    fn json_type_id(&self) -> ObjectId {
        ObjectId::RepublishResponse_Encoding_DefaultJson
    }

    fn xml_type_id(&self) -> ObjectId {
        ObjectId::RepublishResponse_Encoding_DefaultXml
    }

    fn data_type_id(&self) -> DataTypeId {
        DataTypeId::RepublishResponse
    }
}

impl BinaryEncodable for RepublishResponseShared {
    fn byte_len(&self, ctx: &opcua_types::Context<'_>) -> usize {
        let mut size = 0usize;
        size += BinaryEncodable::byte_len(&self.response_header, ctx);
        size += BinaryEncodable::byte_len(&self.notification_message, ctx);
        size
    }

    fn encode<S: Write + ?Sized>(
        &self,
        stream: &mut S,
        ctx: &opcua_types::Context<'_>,
    ) -> EncodingResult<()> {
        BinaryEncodable::encode(&self.response_header, stream, ctx)?;
        BinaryEncodable::encode(&self.notification_message, stream, ctx)?;
        Ok(())
    }
}

macro_rules! response_enum {
    (
        decodable {
            $($name:ident: $value:ident; $enc:ident),* $(,)?
        }
        encode_only {
            $($shared_name:ident: $shared_value:ident),* $(,)?
        }
    ) => {
        #[derive(Debug, PartialEq, Clone)]
        /// Enum of all possible _response_ service messages.
        pub enum ResponseMessage {
            $(
                #[doc = stringify!($name)]
                $name(Box<$value>),
            )*
            $(
                #[doc = stringify!($shared_name)]
                $shared_name(Box<$shared_value>),
            )*
        }
        $(
            impl From<$value> for ResponseMessage {
                fn from(value: $value) -> Self {
                    Self::$name(Box::new(value))
                }
            }
        )*
        $(
            impl From<$shared_value> for ResponseMessage {
                fn from(value: $shared_value) -> Self {
                    Self::$shared_name(Box::new(value))
                }
            }
        )*
        impl BinaryEncodable for ResponseMessage {
            fn byte_len(&self, ctx: &opcua_types::Context<'_>) -> usize {
                match self {
                    $( Self::$name(value) => value.byte_len(ctx), )*
                    $( Self::$shared_name(value) => value.byte_len(ctx), )*
                }
            }

            fn encode<S: Write + ?Sized>(&self, stream: &mut S, ctx: &opcua_types::Context<'_>) -> EncodingResult<()> {
                match self {
                    $( Self::$name(value) => value.encode(stream, ctx), )*
                    $( Self::$shared_name(value) => value.encode(stream, ctx), )*
                }
            }
        }

        impl ResponseMessage {
            /// Get the response header.
            pub fn response_header(&self) -> &ResponseHeader {
                match self {
                    $( Self::$name(value) => &value.response_header, )*
                    $( Self::$shared_name(value) => &value.response_header, )*
                }
            }

            /// Get the name of the request variant, for debugging and logging.
            pub fn type_name(&self) -> &'static str {
                match self {
                    $( Self::$name(_) => stringify!($name), )*
                    $( Self::$shared_name(_) => stringify!($shared_name), )*
                }
            }
        }

        impl Message for ResponseMessage {
            fn request_handle(&self) -> u32 {
                self.response_header().request_handle
            }

            fn decode_by_object_id<S: Read>(
                stream: &mut S,
                object_id: ObjectId,
                ctx: &opcua_types::Context<'_>
            ) -> EncodingResult<Self> {
                match object_id {
                    $( ObjectId::$enc => {
                        Ok($value::decode(stream, ctx)?.into())
                    }, )*
                    _ => {
                        Err(Error::decoding(format!("decoding unsupported for object id {:?}", object_id)))
                    }
                }
            }

            fn type_id(&self) -> NodeId {
                match self {
                    $( Self::$name(v) => v.type_id().into(), )*
                    $( Self::$shared_name(v) => v.type_id().into(), )*
                }
            }
        }
    };
}

impl MessageType for ResponseMessage {
    fn message_type(&self) -> MessageChunkType {
        match self {
            Self::OpenSecureChannel(_) => MessageChunkType::OpenSecureChannel,
            Self::CloseSecureChannel(_) => MessageChunkType::CloseSecureChannel,
            _ => MessageChunkType::Message,
        }
    }
}

response_enum! {
    decodable {
    OpenSecureChannel: OpenSecureChannelResponse; OpenSecureChannelResponse_Encoding_DefaultBinary,
    CloseSecureChannel: CloseSecureChannelResponse; CloseSecureChannelResponse_Encoding_DefaultBinary,
    GetEndpoints: GetEndpointsResponse; GetEndpointsResponse_Encoding_DefaultBinary,
    FindServers: FindServersResponse; FindServersResponse_Encoding_DefaultBinary,
    FindServersOnNetwork: FindServersOnNetworkResponse; FindServersOnNetworkResponse_Encoding_DefaultBinary,
    RegisterServer: RegisterServerResponse; RegisterServerResponse_Encoding_DefaultBinary,
    RegisterServer2: RegisterServer2Response; RegisterServer2Response_Encoding_DefaultBinary,
    CreateSession: CreateSessionResponse; CreateSessionResponse_Encoding_DefaultBinary,
    CloseSession: CloseSessionResponse; CloseSessionResponse_Encoding_DefaultBinary,
    Cancel: CancelResponse; CancelResponse_Encoding_DefaultBinary,
    ActivateSession: ActivateSessionResponse; ActivateSessionResponse_Encoding_DefaultBinary,
    AddNodes: AddNodesResponse; AddNodesResponse_Encoding_DefaultBinary,
    AddReferences: AddReferencesResponse; AddReferencesResponse_Encoding_DefaultBinary,
    DeleteNodes: DeleteNodesResponse; DeleteNodesResponse_Encoding_DefaultBinary,
    DeleteReferences: DeleteReferencesResponse; DeleteReferencesResponse_Encoding_DefaultBinary,
    CreateMonitoredItems: CreateMonitoredItemsResponse; CreateMonitoredItemsResponse_Encoding_DefaultBinary,
    ModifyMonitoredItems: ModifyMonitoredItemsResponse; ModifyMonitoredItemsResponse_Encoding_DefaultBinary,
    DeleteMonitoredItems: DeleteMonitoredItemsResponse; DeleteMonitoredItemsResponse_Encoding_DefaultBinary,
    SetMonitoringMode: SetMonitoringModeResponse; SetMonitoringModeResponse_Encoding_DefaultBinary,
    SetTriggering: SetTriggeringResponse; SetTriggeringResponse_Encoding_DefaultBinary,
    CreateSubscription: CreateSubscriptionResponse; CreateSubscriptionResponse_Encoding_DefaultBinary,
    ModifySubscription: ModifySubscriptionResponse; ModifySubscriptionResponse_Encoding_DefaultBinary,
    DeleteSubscriptions: DeleteSubscriptionsResponse; DeleteSubscriptionsResponse_Encoding_DefaultBinary,
    TransferSubscriptions: TransferSubscriptionsResponse; TransferSubscriptionsResponse_Encoding_DefaultBinary,
    SetPublishingMode: SetPublishingModeResponse; SetPublishingModeResponse_Encoding_DefaultBinary,
    QueryFirst: QueryFirstResponse; QueryFirstResponse_Encoding_DefaultBinary,
    QueryNext: QueryNextResponse; QueryNextResponse_Encoding_DefaultBinary,
    Browse: BrowseResponse; BrowseResponse_Encoding_DefaultBinary,
    BrowseNext: BrowseNextResponse; BrowseNextResponse_Encoding_DefaultBinary,
    Publish: PublishResponse; PublishResponse_Encoding_DefaultBinary,
    Republish: RepublishResponse; RepublishResponse_Encoding_DefaultBinary,
    TranslateBrowsePathsToNodeIds: TranslateBrowsePathsToNodeIdsResponse; TranslateBrowsePathsToNodeIdsResponse_Encoding_DefaultBinary,
    RegisterNodes: RegisterNodesResponse; RegisterNodesResponse_Encoding_DefaultBinary,
    UnregisterNodes: UnregisterNodesResponse; UnregisterNodesResponse_Encoding_DefaultBinary,
    Read: ReadResponse; ReadResponse_Encoding_DefaultBinary,
    HistoryRead: HistoryReadResponse; HistoryReadResponse_Encoding_DefaultBinary,
    Write: WriteResponse; WriteResponse_Encoding_DefaultBinary,
    HistoryUpdate: HistoryUpdateResponse; HistoryUpdateResponse_Encoding_DefaultBinary,
    Call: CallResponse; CallResponse_Encoding_DefaultBinary,
    ServiceFault: ServiceFault; ServiceFault_Encoding_DefaultBinary,
    }
    encode_only {
        PublishShared: PublishResponseShared,
        RepublishShared: RepublishResponseShared,
    }
}

#[cfg(test)]
mod tests {
    use super::{PublishResponseShared, RepublishResponseShared, ResponseMessage};
    use crate::messages::Message;
    use opcua_types::{
        BinaryEncodable, ContextOwned, DataValue, DateTime, MessageInfo, MonitoredItemNotification,
        NotificationMessage, PublishResponse, RepublishResponse, ResponseHeader, StatusCode,
    };
    use std::sync::Arc;

    fn notification_message() -> NotificationMessage {
        NotificationMessage::data_change(
            17,
            DateTime::from((2026, 6, 18, 12, 34, 56)),
            vec![
                MonitoredItemNotification {
                    client_handle: 1001,
                    value: DataValue::new_now(123_i32),
                },
                MonitoredItemNotification {
                    client_handle: 1002,
                    value: DataValue::new_now(456_i32),
                },
            ],
            Vec::new(),
        )
    }

    fn publish_response() -> PublishResponse {
        PublishResponse {
            response_header: ResponseHeader::new_timestamped_service_result(
                DateTime::from((2026, 6, 18, 12, 35, 0)),
                42,
                StatusCode::Good,
            ),
            subscription_id: 99,
            available_sequence_numbers: Some(vec![17, 18, 19]),
            more_notifications: true,
            notification_message: notification_message(),
            results: Some(vec![StatusCode::Good, StatusCode::BadSequenceNumberUnknown]),
            diagnostic_infos: None,
        }
    }

    fn shared_publish_response(response: &PublishResponse) -> PublishResponseShared {
        PublishResponseShared {
            response_header: response.response_header.clone(),
            subscription_id: response.subscription_id,
            available_sequence_numbers: response.available_sequence_numbers.clone(),
            more_notifications: response.more_notifications,
            notification_message: Arc::new(response.notification_message.clone()),
            results: response.results.clone(),
            diagnostic_infos: response.diagnostic_infos.clone(),
        }
    }

    fn republish_response() -> RepublishResponse {
        RepublishResponse {
            response_header: ResponseHeader::new_timestamped_service_result(
                DateTime::from((2026, 6, 18, 12, 36, 0)),
                43,
                StatusCode::Good,
            ),
            notification_message: notification_message(),
        }
    }

    fn shared_republish_response(response: &RepublishResponse) -> RepublishResponseShared {
        RepublishResponseShared {
            response_header: response.response_header.clone(),
            notification_message: Arc::new(response.notification_message.clone()),
        }
    }

    fn encode_response_message(response: &ResponseMessage) -> Vec<u8> {
        let ctx_owner = ContextOwned::default();
        let ctx = ctx_owner.context();
        let mut bytes =
            Vec::with_capacity(response.type_id().byte_len(&ctx) + response.byte_len(&ctx));
        response.type_id().encode(&mut bytes, &ctx).unwrap();
        response.encode(&mut bytes, &ctx).unwrap();
        bytes
    }

    #[test]
    fn shared_publish_response_encodes_like_generated_publish_response() {
        let ctx_owner = ContextOwned::default();
        let ctx = ctx_owner.context();
        let generated = publish_response();
        let shared = shared_publish_response(&generated);

        assert_eq!(generated.type_id(), shared.type_id());
        assert_eq!(generated.byte_len(&ctx), shared.byte_len(&ctx));
        assert_eq!(generated.encode_to_vec(&ctx), shared.encode_to_vec(&ctx));

        let generated_message = ResponseMessage::from(generated);
        let shared_message = ResponseMessage::from(shared);

        assert_eq!(generated_message.type_id(), shared_message.type_id());
        assert_eq!(
            generated_message.byte_len(&ctx),
            shared_message.byte_len(&ctx)
        );
        assert_eq!(
            encode_response_message(&generated_message),
            encode_response_message(&shared_message)
        );
    }

    #[test]
    fn shared_republish_response_encodes_like_generated_republish_response() {
        let ctx_owner = ContextOwned::default();
        let ctx = ctx_owner.context();
        let generated = republish_response();
        let shared = shared_republish_response(&generated);

        assert_eq!(generated.type_id(), shared.type_id());
        assert_eq!(generated.byte_len(&ctx), shared.byte_len(&ctx));
        assert_eq!(generated.encode_to_vec(&ctx), shared.encode_to_vec(&ctx));

        let generated_message = ResponseMessage::from(generated);
        let shared_message = ResponseMessage::from(shared);

        assert_eq!(generated_message.type_id(), shared_message.type_id());
        assert_eq!(
            generated_message.byte_len(&ctx),
            shared_message.byte_len(&ctx)
        );
        assert_eq!(
            encode_response_message(&generated_message),
            encode_response_message(&shared_message)
        );
    }
}
