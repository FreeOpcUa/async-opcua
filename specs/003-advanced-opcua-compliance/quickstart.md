# Quickstart

## Setting up Advanced Compliance Features

These examples use the implemented crate APIs.

## 1. Enable Secure PubSub and `GetSecurityKeys`

```rust
use std::{sync::Arc, time::Duration};

use opcua_core::sync::RwLock;
use opcua_pubsub::{PubSubEngine, SecurityGroup};
use opcua_server::{
    address_space::AddressSpace,
    services::security::{
        GetSecurityKeysRequest, SecurityGroupKeys, SecurityKeyService,
        CURRENT_SECURITY_TOKEN_ID,
    },
};
use opcua_types::{ByteString, StatusCode};

fn configure_pubsub_security() -> Result<(), StatusCode> {
    let key_service = SecurityKeyService::new();
    let group_keys = SecurityGroupKeys::new(
        "http://opcfoundation.org/UA/SecurityPolicy#Aes128_Sha256_RsaOaep",
        7,
        vec![ByteString::from(vec![0; 16]), ByteString::from(vec![1; 16])],
        Duration::from_secs(3600),
    )?;

    key_service.register_security_group("group-1", group_keys)?;
    let response = key_service.get_security_keys(GetSecurityKeysRequest::new(
        "group-1",
        CURRENT_SECURITY_TOKEN_ID,
        2,
    ))?;
    assert_eq!(response.keys.len(), 2);

    let address_space = Arc::new(RwLock::new(AddressSpace::new()));
    let mut engine = PubSubEngine::new(address_space);
    let security_group =
        SecurityGroup::new("group-1", Duration::from_secs(3600)).map_err(|err| err.status())?;
    engine.register_security_group(security_group);

    Ok(())
}
```

## 2. Subscribe with an `EventFilter`

```rust
use std::time::Duration;

use opcua_client::{EventCallback, Session};
use opcua_types::{
    AttributeId, ContentFilterBuilder, EventFilter, ExtensionObject,
    MonitoredItemCreateRequest, MonitoringMode, MonitoringParameters, NodeId, NumericRange,
    ObjectId, ObjectTypeId, Operand, ReadValueId, SimpleAttributeOperand, TimestampsToReturn,
};

async fn subscribe_to_high_severity_events(session: &Session) -> Result<u32, opcua_types::Error> {
    let subscription_id = session
        .create_subscription(
            Duration::from_millis(100),
            30,
            10,
            0,
            0,
            true,
            EventCallback::new(|event_fields, _| {
                let _ = event_fields;
            }),
        )
        .await?;

    let base_event_type = NodeId::from(ObjectTypeId::BaseEventType);
    let filter = EventFilter {
        select_clauses: Some(vec![
            SimpleAttributeOperand::new_value(base_event_type.clone(), "Message"),
            SimpleAttributeOperand::new_value(base_event_type.clone(), "Severity"),
        ]),
        where_clause: ContentFilterBuilder::new()
            .gte(
                Operand::simple_attribute(
                    base_event_type,
                    "Severity",
                    AttributeId::Value,
                    NumericRange::None,
                ),
                Operand::literal(500u16),
            )
            .build(),
    };

    let item = MonitoredItemCreateRequest::new(
        ReadValueId::new(ObjectId::Server.into(), AttributeId::EventNotifier),
        MonitoringMode::Reporting,
        MonitoringParameters {
            client_handle: 1,
            sampling_interval: 0.0,
            filter: ExtensionObject::from_message(filter),
            queue_size: 10,
            discard_oldest: true,
        },
    );

    session
        .create_monitored_items(subscription_id, TimestampsToReturn::Both, vec![item])
        .await?;

    Ok(subscription_id)
}
```

## 3. Run Graph Queries

```rust
use std::time::Duration;

use opcua_client::{services::Read, Session};
use opcua_core::ResponseMessage;
use opcua_types::{
    ContentFilter, Error, QueryFirstRequest, QueryFirstResponse, QueryNextRequest,
    QueryNextResponse, StatusCode, ViewDescription,
};

async fn query_first(
    session: &Session,
    mut request: QueryFirstRequest,
) -> Result<QueryFirstResponse, Error> {
    request.request_header = Read::new(session).header().clone();
    let response = session.channel().send(request, Duration::from_secs(5)).await?;

    match response {
        ResponseMessage::QueryFirst(response) => Ok(*response),
        _ => Err(Error::new(
            StatusCode::BadUnexpectedError,
            "unexpected QueryFirst response",
        )),
    }
}

async fn query_next(
    session: &Session,
    continuation_point: opcua_types::ContinuationPoint,
) -> Result<QueryNextResponse, Error> {
    let request = QueryNextRequest {
        request_header: Read::new(session).header().clone(),
        release_continuation_point: false,
        continuation_point,
    };
    let response = session.channel().send(request, Duration::from_secs(5)).await?;

    match response {
        ResponseMessage::QueryNext(response) => Ok(*response),
        _ => Err(Error::new(
            StatusCode::BadUnexpectedError,
            "unexpected QueryNext response",
        )),
    }
}

async fn run_query(session: &Session) -> Result<(), Error> {
    let first = query_first(
        session,
        QueryFirstRequest {
            view: ViewDescription::default(),
            node_types: None,
            filter: ContentFilter::default(),
            max_data_sets_to_return: 100,
            max_references_to_return: 0,
            ..Default::default()
        },
    )
    .await?;

    if !first.continuation_point.is_null() {
        let _next = query_next(session, first.continuation_point).await?;
    }

    Ok(())
}
```

## 4. Validate

Run the scenario tests from the repository root:

```sh
cargo test -p async-opcua-pubsub --test security_tests
cargo test -p async-opcua-server --test security_tests get_security_keys
cargo test -p async-opcua-server --test event_filter_tests
cargo test -p async-opcua-server --test query_tests
```
