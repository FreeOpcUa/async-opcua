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
                        Err(Error::decoding(format!("decoding unsupported for object id {:?}", object_id)))
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
