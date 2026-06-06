use crate::comms::message_chunk::MessageChunkType;

use super::{Message, MessageType};
use opcua_types::*;
use std::io::{Read, Write};

macro_rules! response_enum {
    ($($name:ident: $value:ident; $enc:ident),*,) => {
        #[derive(Debug, PartialEq, Clone)]
        /// Enum of all possible _response_ service messages.
        pub enum ResponseMessage {
            $(
                #[doc = stringify!($name)]
                $name(Box<$value>),
            )*
        }
        $(
            impl From<$value> for ResponseMessage {
                fn from(value: $value) -> Self {
                    Self::$name(Box::new(value))
                }
            }
        )*
        impl BinaryEncodable for ResponseMessage {
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

        impl ResponseMessage {
            /// Get the response header.
            pub fn response_header(&self) -> &ResponseHeader {
                match self {
                    $( Self::$name(value) => &value.response_header, )*
                }
            }

            /// Get the name of the request variant, for debugging and logging.
            pub fn type_name(&self) -> &'static str {
                match self {
                    $( Self::$name(_) => stringify!($name), )*
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
