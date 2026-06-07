use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use lapin::{
    options::{BasicPublishOptions, QueueDeclareOptions},
    types::FieldTable,
    BasicProperties, Channel, Connection, ConnectionProperties,
};
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;

use opcua_core::sync::RwLock;
use opcua_server::address_space::{AddressSpace, NodeType};
use opcua_types::{
    BinaryEncodable, ContextOwned, DataEncoding, NumericRange, StatusCode, TimestampsToReturn,
};

use crate::{
    codec::json::{opcua_to_json_value, JsonDataSetMessage, JsonNetworkMessage},
    codec::uadp::{PublisherId, UadpDataSetMessage, UadpNetworkMessage},
    MessageEncoding, PubSubConnectionConfig, PubSubPublisher,
};

const MAX_CACHE_SIZE: usize = 1000;
const DEFAULT_AMQP_PORT: u16 = 5672;
const DEFAULT_ROUTING_KEY: &str = "opcua.telemetry";
const DEFAULT_EXCHANGE: &str = "";

#[derive(Debug, Clone, PartialEq, Eq)]
struct AmqpAddressSettings {
    broker_url: String,
    routing_key: String,
}

/// AMQP implementation of `PubSubPublisher` with reconnection, backoff, and local cache.
pub struct AmqpPublisher {
    address_space: Arc<RwLock<AddressSpace>>,
    cache: Arc<Mutex<VecDeque<(String, Vec<u8>)>>>,
}

impl AmqpPublisher {
    /// Creates a new `AmqpPublisher` with the given AddressSpace reference.
    pub fn new(address_space: Arc<RwLock<AddressSpace>>) -> Self {
        Self {
            address_space,
            cache: Arc::new(Mutex::new(VecDeque::new())),
        }
    }

    /// Instantly queues a message in the local bounded cache.
    pub fn publish_immediate(&self, routing_key: String, payload: Vec<u8>) {
        push_cached_message(&self.cache, routing_key, payload);
    }

    #[cfg(test)]
    fn cached_message_count(&self) -> usize {
        self.cache.lock().map_or(0, |cache| cache.len())
    }

    #[cfg(test)]
    fn pop_cached_message(&self) -> Option<(String, Vec<u8>)> {
        self.cache
            .lock()
            .ok()
            .and_then(|mut cache| cache.pop_front())
    }
}

impl PubSubPublisher for AmqpPublisher {
    fn start_publishing(
        &self,
        connection_config: PubSubConnectionConfig,
        cancel_token: CancellationToken,
    ) -> Result<tokio::task::JoinHandle<()>, StatusCode> {
        let settings = parse_amqp_address(&connection_config.address);
        let address_space = self.address_space.clone();
        let cache = self.cache.clone();
        let publisher_id = connection_config.connection_id.clone();

        for writer_group in connection_config.writer_groups.clone() {
            let address_space = address_space.clone();
            let publisher = self.cache.clone();
            let cancel_token = cancel_token.clone();
            let publisher_id = publisher_id.clone();
            let routing_key = settings.routing_key.clone();

            tokio::spawn(async move {
                let mut sequence_number: u16 = 0;
                loop {
                    if cancel_token.is_cancelled() {
                        break;
                    }

                    sleep(Duration::from_millis(writer_group.publishing_interval)).await;

                    let payload = {
                        let space = address_space.read();
                        build_writer_group_payload(
                            &space,
                            &writer_group,
                            &publisher_id,
                            &mut sequence_number,
                        )
                    };

                    if let Some(payload) = payload {
                        push_cached_message(&publisher, routing_key.clone(), payload);
                    }
                }
            });
        }

        let handle = tokio::spawn(async move {
            let mut backoff = Duration::from_secs(1);

            loop {
                if cancel_token.is_cancelled() {
                    break;
                }

                let connection = match Connection::connect(
                    &settings.broker_url,
                    ConnectionProperties::default(),
                )
                .await
                {
                    Ok(connection) => connection,
                    Err(error) => {
                        tracing::warn!(
                            broker_url = %settings.broker_url,
                            ?error,
                            "failed to connect AMQP publisher"
                        );
                        wait_for_reconnect(&cancel_token, &mut backoff).await;
                        continue;
                    }
                };

                let channel = match connection.create_channel().await {
                    Ok(channel) => channel,
                    Err(error) => {
                        tracing::warn!(?error, "failed to create AMQP channel");
                        wait_for_reconnect(&cancel_token, &mut backoff).await;
                        continue;
                    }
                };

                if let Err(error) = channel
                    .queue_declare(
                        &settings.routing_key,
                        QueueDeclareOptions::default(),
                        FieldTable::default(),
                    )
                    .await
                {
                    tracing::warn!(
                        routing_key = %settings.routing_key,
                        ?error,
                        "failed to declare AMQP queue"
                    );
                    wait_for_reconnect(&cancel_token, &mut backoff).await;
                    continue;
                }

                backoff = Duration::from_secs(1);

                loop {
                    if cancel_token.is_cancelled() {
                        return;
                    }

                    let next_item = cache
                        .lock()
                        .ok()
                        .and_then(|mut cache_lock| cache_lock.pop_front());

                    if let Some((routing_key, payload)) = next_item {
                        if let Err(error) = publish_payload(&channel, &routing_key, &payload).await
                        {
                            tracing::warn!(routing_key = %routing_key, ?error, "failed to publish AMQP payload");
                            if let Ok(mut cache_lock) = cache.lock() {
                                cache_lock.push_front((routing_key, payload));
                            }
                            wait_for_reconnect(&cancel_token, &mut backoff).await;
                            break;
                        }
                        continue;
                    }

                    tokio::select! {
                        _ = cancel_token.cancelled() => {
                            return;
                        }
                        _ = sleep(Duration::from_millis(20)) => {}
                    }
                }
            }
        });

        Ok(handle)
    }
}

fn parse_amqp_address(address: &str) -> AmqpAddressSettings {
    let (scheme, addr) = if let Some(addr) = address.strip_prefix("amqp://") {
        ("amqp", addr)
    } else if let Some(addr) = address.strip_prefix("amqps://") {
        ("amqps", addr)
    } else {
        ("amqp", address)
    };

    let default_port = if scheme == "amqps" {
        5671
    } else {
        DEFAULT_AMQP_PORT
    };
    let (authority, routing_key) = addr.split_once('/').unwrap_or((addr, ""));
    let authority = if authority.is_empty() {
        format!("127.0.0.1:{default_port}")
    } else if authority_has_port(authority) {
        authority.to_string()
    } else {
        format!("{authority}:{default_port}")
    };

    AmqpAddressSettings {
        broker_url: format!("{scheme}://{authority}"),
        routing_key: if routing_key.is_empty() {
            DEFAULT_ROUTING_KEY.to_string()
        } else {
            routing_key.to_string()
        },
    }
}

fn authority_has_port(authority: &str) -> bool {
    let host_port = authority.rsplit('@').next().unwrap_or(authority);
    if let Some(rest) = host_port.strip_prefix('[') {
        return rest
            .find(']')
            .is_some_and(|end| rest[end + 1..].starts_with(':'));
    }
    host_port.rsplit_once(':').is_some()
}

fn push_cached_message(
    cache: &Arc<Mutex<VecDeque<(String, Vec<u8>)>>>,
    routing_key: String,
    payload: Vec<u8>,
) {
    if let Ok(mut cache) = cache.lock() {
        if cache.len() >= MAX_CACHE_SIZE {
            let _ = cache.pop_front();
        }
        cache.push_back((routing_key, payload));
    }
}

fn build_writer_group_payload(
    space: &AddressSpace,
    writer_group: &crate::WriterGroupConfig,
    publisher_id: &str,
    sequence_number: &mut u16,
) -> Option<Vec<u8>> {
    let mut json_dataset_messages = Vec::new();
    let mut uadp_dataset_messages = Vec::new();

    for writer in &writer_group.dataset_writers {
        let mut payload_map = std::collections::HashMap::new();
        let mut uadp_fields = Vec::new();

        for node_id in &writer.published_dataset.published_variables {
            if let Some(NodeType::Variable(var)) = space.find(node_id) {
                let ctx_owned = ContextOwned::default();
                let ctx = ctx_owned.context();
                let data_value = var.value(
                    TimestampsToReturn::Both,
                    &NumericRange::None,
                    &DataEncoding::Binary,
                    0.0,
                );

                if writer_group.encoding == MessageEncoding::Json {
                    if let Ok(val) = opcua_to_json_value(&data_value, &ctx) {
                        payload_map.insert(node_id.to_string(), val);
                    }
                } else if let Some(ref val) = data_value.value {
                    uadp_fields.push(val.clone());
                }
            }
        }

        *sequence_number = sequence_number.wrapping_add(1);

        match writer_group.encoding {
            MessageEncoding::Json => {
                json_dataset_messages.push(JsonDataSetMessage {
                    dataset_writer_id: writer.dataset_writer_id,
                    sequence_number: *sequence_number,
                    payload: payload_map,
                });
            }
            MessageEncoding::Uadp => {
                uadp_dataset_messages.push(UadpDataSetMessage {
                    dataset_writer_id: writer.dataset_writer_id,
                    sequence_number: *sequence_number,
                    timestamp: Some(opcua_types::DateTime::now()),
                    status: Some(StatusCode::Good),
                    fields: uadp_fields,
                });
            }
        }
    }

    match writer_group.encoding {
        MessageEncoding::Json => {
            let msg = JsonNetworkMessage {
                message_id: uuid::Uuid::new_v4().to_string(),
                message_type: "ua-data".to_string(),
                publisher_id: publisher_id.to_string(),
                writer_group_id: writer_group.writer_group_id,
                messages: json_dataset_messages,
            };
            msg.to_json_string().ok().map(String::into_bytes)
        }
        MessageEncoding::Uadp => {
            let msg = UadpNetworkMessage {
                publisher_id: PublisherId::String(publisher_id.to_string()),
                writer_group_id: writer_group.writer_group_id,
                dataset_messages: uadp_dataset_messages,
            };
            let ctx_owned = ContextOwned::default();
            let ctx = ctx_owned.context();
            Some(msg.encode_to_vec(&ctx))
        }
    }
}

async fn publish_payload(
    channel: &Channel,
    routing_key: &str,
    payload: &[u8],
) -> lapin::Result<()> {
    let confirmation = channel
        .basic_publish(
            DEFAULT_EXCHANGE,
            routing_key,
            BasicPublishOptions::default(),
            payload,
            BasicProperties::default(),
        )
        .await?;
    let _ = confirmation.await?;
    Ok(())
}

async fn wait_for_reconnect(cancel_token: &CancellationToken, backoff: &mut Duration) {
    tokio::select! {
        _ = cancel_token.cancelled() => {}
        _ = sleep(*backoff) => {
            *backoff = std::cmp::min(*backoff * 2, Duration::from_secs(60));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opcua_core::sync::RwLock;
    use opcua_server::address_space::AddressSpace;
    use std::sync::Arc;

    #[test]
    fn parses_amqp_address_with_prefix_and_queue() {
        let settings = parse_amqp_address("amqp://broker.local:5673/plant.telemetry");

        assert_eq!(settings.broker_url, "amqp://broker.local:5673");
        assert_eq!(settings.routing_key, "plant.telemetry");
    }

    #[test]
    fn parses_amqp_address_without_prefix_using_default_port_and_queue() {
        let settings = parse_amqp_address("broker.local");

        assert_eq!(settings.broker_url, "amqp://broker.local:5672");
        assert_eq!(settings.routing_key, "opcua.telemetry");
    }

    #[test]
    fn publish_immediate_keeps_bounded_fifo_cache() {
        let publisher = AmqpPublisher::new(Arc::new(RwLock::new(AddressSpace::new())));

        for i in 0..1100 {
            publisher.publish_immediate(format!("key-{i}"), vec![i as u8]);
        }

        assert_eq!(publisher.cached_message_count(), 1000);
        let first = publisher.pop_cached_message();
        assert_eq!(first, Some(("key-100".to_string(), vec![100u8])));
    }
}
