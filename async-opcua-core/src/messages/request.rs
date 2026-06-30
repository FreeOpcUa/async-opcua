use crate::comms::message_chunk::MessageChunkType;

use super::{Message, MessageType};
use opcua_types::*;
use std::io::{Read, Write};

macro_rules! request_enum {
    ($($name:ident: $value:ident; $enc:ident),*,) => {
        #[derive(Debug, PartialEq, Clone)]
        /// Enum of all possible _request_ service messages.
        pub enum RequestMessage {
            $(
                #[doc = stringify!($name)]
                $name(Box<$value>),
            )*
        }
        $(
            impl From<$value> for RequestMessage {
                fn from(value: $value) -> Self {
                    Self::$name(Box::new(value))
                }
            }
        )*
        impl BinaryEncodable for RequestMessage {
            fn byte_len(&self, ctx: &opcua_types::Context<'_>) -> usize {
                match self {
                    $( Self::$name(value) => value.byte_len(ctx), )*
                }
            }

            fn encode<S: Write + ?Sized>(&self, stream: &mut S, ctx: &opcua_types::Context<'_>) -> EncodingResult<()> {
                match self {
                    $( Self::$name(value) => value.encode(stream, ctx), )*
                }
            }
        }

        impl RequestMessage {
            /// Get the request header.
            pub fn request_header(&self) -> &RequestHeader {
                match self {
                    $( Self::$name(value) => &value.request_header, )*
                }
            }

            /// Get the name of the request variant, for debugging and logging.
            pub fn type_name(&self) -> &'static str {
                match self {
                    $( Self::$name(_) => stringify!($name), )*
                }
            }
        }

        impl Message for RequestMessage {
            fn request_handle(&self) -> u32 {
                self.request_header().request_handle
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
                        let request_header = RequestHeader::decode(stream, ctx)?;
                        Err(Error::new(
                            StatusCode::BadServiceUnsupported,
                            format!("unsupported service request object id {:?}", object_id),
                        )
                        .with_request_handle(request_header.request_handle))
                    }
                }
            }

            fn type_id(&self) -> NodeId {
                match self {
                    $( Self::$name(v) => v.type_id().into(), )*
                }
            }
        }
    };
}

impl MessageType for RequestMessage {
    fn message_type(&self) -> crate::comms::message_chunk::MessageChunkType {
        match self {
            Self::OpenSecureChannel(_) => MessageChunkType::OpenSecureChannel,
            Self::CloseSecureChannel(_) => MessageChunkType::CloseSecureChannel,
            _ => MessageChunkType::Message,
        }
    }
}

request_enum! {
    OpenSecureChannel: OpenSecureChannelRequest; OpenSecureChannelRequest_Encoding_DefaultBinary,
    CloseSecureChannel: CloseSecureChannelRequest; CloseSecureChannelRequest_Encoding_DefaultBinary,
    GetEndpoints: GetEndpointsRequest; GetEndpointsRequest_Encoding_DefaultBinary,
    FindServers: FindServersRequest; FindServersRequest_Encoding_DefaultBinary,
    FindServersOnNetwork: FindServersOnNetworkRequest; FindServersOnNetworkRequest_Encoding_DefaultBinary,
    RegisterServer: RegisterServerRequest; RegisterServerRequest_Encoding_DefaultBinary,
    RegisterServer2: RegisterServer2Request; RegisterServer2Request_Encoding_DefaultBinary,
    CreateSession: CreateSessionRequest; CreateSessionRequest_Encoding_DefaultBinary,
    CloseSession: CloseSessionRequest; CloseSessionRequest_Encoding_DefaultBinary,
    Cancel: CancelRequest; CancelRequest_Encoding_DefaultBinary,
    ActivateSession: ActivateSessionRequest; ActivateSessionRequest_Encoding_DefaultBinary,
    AddNodes: AddNodesRequest; AddNodesRequest_Encoding_DefaultBinary,
    AddReferences: AddReferencesRequest; AddReferencesRequest_Encoding_DefaultBinary,
    DeleteNodes: DeleteNodesRequest; DeleteNodesRequest_Encoding_DefaultBinary,
    DeleteReferences: DeleteReferencesRequest; DeleteReferencesRequest_Encoding_DefaultBinary,
    CreateMonitoredItems: CreateMonitoredItemsRequest; CreateMonitoredItemsRequest_Encoding_DefaultBinary,
    ModifyMonitoredItems: ModifyMonitoredItemsRequest; ModifyMonitoredItemsRequest_Encoding_DefaultBinary,
    DeleteMonitoredItems: DeleteMonitoredItemsRequest; DeleteMonitoredItemsRequest_Encoding_DefaultBinary,
    SetMonitoringMode: SetMonitoringModeRequest; SetMonitoringModeRequest_Encoding_DefaultBinary,
    SetTriggering: SetTriggeringRequest; SetTriggeringRequest_Encoding_DefaultBinary,
    CreateSubscription: CreateSubscriptionRequest; CreateSubscriptionRequest_Encoding_DefaultBinary,
    ModifySubscription: ModifySubscriptionRequest; ModifySubscriptionRequest_Encoding_DefaultBinary,
    DeleteSubscriptions: DeleteSubscriptionsRequest; DeleteSubscriptionsRequest_Encoding_DefaultBinary,
    TransferSubscriptions: TransferSubscriptionsRequest; TransferSubscriptionsRequest_Encoding_DefaultBinary,
    SetPublishingMode: SetPublishingModeRequest; SetPublishingModeRequest_Encoding_DefaultBinary,
    QueryFirst: QueryFirstRequest; QueryFirstRequest_Encoding_DefaultBinary,
    QueryNext: QueryNextRequest; QueryNextRequest_Encoding_DefaultBinary,
    Browse: BrowseRequest; BrowseRequest_Encoding_DefaultBinary,
    BrowseNext: BrowseNextRequest; BrowseNextRequest_Encoding_DefaultBinary,
    Publish: PublishRequest; PublishRequest_Encoding_DefaultBinary,
    Republish: RepublishRequest; RepublishRequest_Encoding_DefaultBinary,
    TranslateBrowsePathsToNodeIds: TranslateBrowsePathsToNodeIdsRequest; TranslateBrowsePathsToNodeIdsRequest_Encoding_DefaultBinary,
    RegisterNodes: RegisterNodesRequest; RegisterNodesRequest_Encoding_DefaultBinary,
    UnregisterNodes: UnregisterNodesRequest; UnregisterNodesRequest_Encoding_DefaultBinary,
    Read: ReadRequest; ReadRequest_Encoding_DefaultBinary,
    HistoryRead: HistoryReadRequest; HistoryReadRequest_Encoding_DefaultBinary,
    Write: WriteRequest; WriteRequest_Encoding_DefaultBinary,
    HistoryUpdate: HistoryUpdateRequest; HistoryUpdateRequest_Encoding_DefaultBinary,
    Call: CallRequest; CallRequest_Encoding_DefaultBinary,
}

#[cfg(test)]
mod tests {
    use super::RequestMessage;
    use crate::messages::Message;
    use opcua_types::{BinaryEncodable, ContextOwned, ObjectId, RequestHeader, StatusCode};

    #[test]
    fn unknown_service_id_reports_unsupported_fault_status_with_recoverable_context() {
        let ctx_owner = ContextOwned::default();
        let ctx = ctx_owner.context();
        let request_id = 0x1020_3040;
        let request_handle = 0x5566_7788;
        let header = RequestHeader {
            request_handle,
            ..RequestHeader::default()
        };
        let mut request_body = Vec::with_capacity(header.byte_len(&ctx));
        header
            .encode(&mut request_body, &ctx)
            .expect("test request header should encode");
        let mut stream = request_body.as_slice();

        let err = RequestMessage::decode_by_object_id(
            &mut stream,
            ObjectId::Node_Encoding_DefaultBinary,
            &ctx,
        )
        .expect_err("unknown service ids must be rejected, not decoded as a request");

        assert_eq!(
            err.status(),
            StatusCode::BadServiceUnsupported,
            "OPC-10000-4 5.3 and 7.34 require an unsupported service request to be returned as a ServiceFault with Bad_ServiceUnsupported, not as a fatal decoding error"
        );
        assert_eq!(
            err.with_request_id(request_id).full_context(),
            Some((request_id, request_handle)),
            "a reusable channel can send the unsupported-service ServiceFault only if the decode error preserves the request id and request handle"
        );
    }
}
