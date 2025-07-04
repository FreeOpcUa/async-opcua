// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2024 Adam Lock

//! This OPC UA client will subscribe to events and print them out when it receives them
//!
//! 1. Create a client configuration
//! 2. Connect to an endpoint specified by the url with security None
//! 3. Subscribe to values and loop forever printing out their values
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use opcua::client::{ClientBuilder, EventCallback, IdentityToken, Session};
use opcua::crypto::SecurityPolicy;
use opcua::types::{
    AttributeId, ContentFilter, EventFilter, ExtensionObject, MessageSecurityMode,
    MonitoredItemCreateRequest, NodeId, ObjectTypeId, QualifiedName, SimpleAttributeOperand,
    StatusCode, TimestampsToReturn, UserTokenPolicy,
};

struct Args {
    help: bool,
    url: String,
    event_source: String,
    event_fields: String,
}

impl Args {
    pub fn parse_args() -> Result<Args, Box<dyn std::error::Error>> {
        let mut args = pico_args::Arguments::from_env();
        Ok(Args {
            help: args.contains(["-h", "--help"]),
            url: args
                .opt_value_from_str("--url")?
                .unwrap_or_else(|| String::from(DEFAULT_URL)),
            event_source: args
                .opt_value_from_str("--event-source")?
                .unwrap_or_else(|| String::from(DEFAULT_EVENT_SOURCE)),
            event_fields: args
                .opt_value_from_str("--event-fields")?
                .unwrap_or_else(|| String::from(DEFAULT_EVENT_FIELDS)),
        })
    }

    pub fn usage() {
        println!(
            r#"Event Client
Usage:
  -h, --help                Show help
  --url [url]               Url to connect to (default: {DEFAULT_URL})
  --event-source [node-id]  Node id to monitor for events (default: {DEFAULT_EVENT_SOURCE})
  --event-fields [fields]   Comma separated list of variables within the event to print out (default: {DEFAULT_EVENT_FIELDS})"#
        );
    }
}

const DEFAULT_URL: &str = "opc.tcp://localhost:4855";
const DEFAULT_EVENT_SOURCE: &str = "i=2253";
const DEFAULT_EVENT_FIELDS: &str = "EventId,EventType,Message";

#[tokio::main]
async fn main() -> Result<(), ()> {
    // Read command line arguments
    let args = Args::parse_args().map_err(|_| Args::usage())?;
    if args.help {
        Args::usage();
        return Ok(());
    }
    // Optional - enable OPC UA logging
    env_logger::init();

    // Make the client configuration
    let mut client = ClientBuilder::new()
        .application_name("Simple Client")
        .application_uri("urn:SimpleClient")
        .product_uri("urn:SimpleClient")
        .trust_server_certs(true)
        .create_sample_keypair(true)
        .session_retry_limit(3)
        .client()
        .unwrap();

    let (session, event_loop) = client
        .connect_to_matching_endpoint(
            (
                args.url.as_ref(),
                SecurityPolicy::None.to_str(),
                MessageSecurityMode::None,
                UserTokenPolicy::anonymous(),
            ),
            IdentityToken::Anonymous,
        )
        .await
        .unwrap();

    let handle = event_loop.spawn();
    session.wait_for_connection().await;

    if let Err(result) =
        subscribe_to_events(session.clone(), &args.event_source, &args.event_fields).await
    {
        println!("ERROR: Got an error while subscribing to variables - {result}");
        let _ = session.disconnect().await;
    }

    handle.await.unwrap();

    Ok(())
}

async fn subscribe_to_events(
    session: Arc<Session>,
    event_source: &str,
    event_fields: &str,
) -> Result<(), StatusCode> {
    let event_fields: Vec<String> = event_fields.split(',').map(|s| s.into()).collect();

    let event_callback = {
        let event_fields = event_fields.clone();
        EventCallback::new(move |event, _item| {
            // Handle events
            println!("Event from server:");
            if let Some(ref event_values) = event {
                event_values.iter().enumerate().for_each(|(idx, field)| {
                    println!("  {}: {}", event_fields[idx], field);
                });
            }
        })
    };

    // Creates a subscription with an event callback
    let subscription_id = session
        .create_subscription(
            Duration::from_millis(100),
            12000,
            50,
            65535,
            0,
            true,
            event_callback,
        )
        .await?;
    println!("Created a subscription with id = {subscription_id}");

    // Create monitored item on an event

    let event_source = NodeId::from_str(event_source).unwrap();
    println!("Creating a subscription to events from the event source {event_source}");

    // The where clause is looking for events that are change events
    let where_clause = ContentFilter { elements: None };

    // Select clauses
    let select_clauses = Some(
        event_fields
            .iter()
            .map(|s| SimpleAttributeOperand {
                type_definition_id: ObjectTypeId::BaseEventType.into(),
                browse_path: Some(vec![QualifiedName::from(s)]),
                attribute_id: AttributeId::Value as u32,
                index_range: opcua::types::NumericRange::None,
            })
            .collect(),
    );

    let event_filter = EventFilter {
        where_clause,
        select_clauses,
    };

    let mut item_to_create: MonitoredItemCreateRequest = event_source.into();
    item_to_create.item_to_monitor.attribute_id = AttributeId::EventNotifier as u32;
    item_to_create.requested_parameters.sampling_interval = 100.0;
    item_to_create.requested_parameters.queue_size = 2;
    item_to_create.requested_parameters.filter = ExtensionObject::from_message(event_filter);
    if let Ok(result) = session
        .create_monitored_items(
            subscription_id,
            TimestampsToReturn::Neither,
            vec![item_to_create],
        )
        .await
    {
        println!("Result of subscribing to event = {result:?}");
    } else {
        println!("Cannot create monitored event!");
    }

    Ok(())
}
