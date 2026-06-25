mod opcua {
    pub(super) use opcua_types as types;
}

#[opcua::types::ua_encodable]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(i32)]
pub enum PubSubConnectionEndpointModeEnum {
    #[opcua(default)]
    PublisherSubscriber = 1i32,
    Publisher = 2i32,
    Subscriber = 3i32,
}
