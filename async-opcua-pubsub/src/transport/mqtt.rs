use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;

use opcua_core::sync::RwLock;
use opcua_server::address_space::{AddressSpace, NodeType};
use opcua_types::{
    BinaryEncodable, ContextOwned, DataEncoding, NumericRange, StatusCode, TimestampsToReturn,
};
use rumqttc::{AsyncClient, MqttOptions, QoS};

use crate::{
    codec::json::{opcua_to_json_value, JsonDataSetMessage, JsonNetworkMessage},
    codec::uadp::{PublisherId, UadpDataSetMessage, UadpNetworkMessage},
    MessageEncoding, PubSubConnectionConfig, PubSubPublisher,
};

/// Maximum number of messages to keep in the local cache when disconnected.
const MAX_CACHE_SIZE: usize = 1000;

/// MQTT implementation of `PubSubPublisher` with reconnection, backoff, and local cache.
pub struct MqttPublisher {
    address_space: Arc<RwLock<AddressSpace>>,
    cache: Arc<Mutex<VecDeque<(String, Vec<u8>)>>>,
}

impl MqttPublisher {
    /// Creates a new `MqttPublisher` with the given AddressSpace reference.
    pub fn new(address_space: Arc<RwLock<AddressSpace>>) -> Self {
        Self {
            address_space,
            cache: Arc::new(Mutex::new(VecDeque::new())),
        }
    }

    /// Instantly queues a message in the local bounded cache.
    pub fn publish_immediate(&self, topic: String, payload: Vec<u8>) {
        let mut cache = self.cache.lock().unwrap();
        if cache.len() >= MAX_CACHE_SIZE {
            let _ = cache.pop_front();
        }
        cache.push_back((topic, payload));
    }
}

impl PubSubPublisher for MqttPublisher {
    fn start_publishing(
        &self,
        connection_config: PubSubConnectionConfig,
        cancel_token: CancellationToken,
    ) -> Result<tokio::task::JoinHandle<()>, StatusCode> {
        // Parse host and port from address
        let addr = connection_config
            .address
            .strip_prefix("mqtt://")
            .unwrap_or(&connection_config.address);
        let parts: Vec<&str> = addr.split(':').collect();
        let host = parts[0].to_string();
        let port = if parts.len() > 1 {
            parts[1].parse::<u16>().unwrap_or(1883)
        } else {
            1883
        };

        let address_space = self.address_space.clone();
        let cache = self.cache.clone();
        let publisher_id = connection_config.connection_id.clone();

        // 1. Spawn the cyclic publishing task(s)
        for writer_group in connection_config.writer_groups.clone() {
            let address_space = address_space.clone();
            let publisher = self.cache.clone();
            let cancel_token = cancel_token.clone();
            let publisher_id = publisher_id.clone();

            tokio::spawn(async move {
                let mut sequence_number: u16 = 0;
                loop {
                    if cancel_token.is_cancelled() {
                        break;
                    }

                    sleep(Duration::from_millis(writer_group.publishing_interval)).await;

                    // Query address space
                    let space = address_space.read();
                    let mut json_dataset_messages = Vec::new();
                    let mut uadp_dataset_messages = Vec::new();

                    for writer in &writer_group.dataset_writers {
                        let mut payload_map = std::collections::HashMap::new();
                        let mut uadp_fields = Vec::new();

                        for node_id in &writer.published_dataset.published_variables {
                            if let Some(node) = space.find(node_id) {
                                if let NodeType::Variable(ref var) = *node {
                                    // Use standard OPC UA getter
                                    let ctx_owned = ContextOwned::default();
                                    let ctx = ctx_owned.context();
                                    let data_value = var.value(
                                        TimestampsToReturn::Both,
                                        &NumericRange::None,
                                        &DataEncoding::Binary,
                                        0.0,
                                    );

                                    // For JSON
                                    if writer_group.encoding == MessageEncoding::Json {
                                        if let Ok(val) = opcua_to_json_value(&data_value, &ctx) {
                                            payload_map.insert(node_id.to_string(), val);
                                        }
                                    } else if let Some(ref val) = data_value.value {
                                        // For UADP
                                        uadp_fields.push(val.clone());
                                    }
                                }
                            }
                        }

                        sequence_number = sequence_number.wrapping_add(1);

                        match writer_group.encoding {
                            MessageEncoding::Json => {
                                json_dataset_messages.push(JsonDataSetMessage {
                                    dataset_writer_id: writer.dataset_writer_id,
                                    sequence_number,
                                    payload: payload_map,
                                });
                            }
                            MessageEncoding::Uadp => {
                                uadp_dataset_messages.push(UadpDataSetMessage {
                                    dataset_writer_id: writer.dataset_writer_id,
                                    sequence_number,
                                    timestamp: Some(opcua_types::DateTime::now()),
                                    status: Some(StatusCode::Good),
                                    fields: uadp_fields,
                                });
                            }
                        }
                    }

                    // Format and queue payload
                    let topic = format!("opcua/telemetry/{}", writer_group.writer_group_id);
                    match writer_group.encoding {
                        MessageEncoding::Json => {
                            let msg = JsonNetworkMessage {
                                message_id: uuid::Uuid::new_v4().to_string(),
                                message_type: "ua-data".to_string(),
                                publisher_id: publisher_id.clone(),
                                writer_group_id: writer_group.writer_group_id,
                                messages: json_dataset_messages,
                            };
                            if let Ok(json_str) = msg.to_json_string() {
                                let mut cache = publisher.lock().unwrap();
                                if cache.len() >= MAX_CACHE_SIZE {
                                    let _ = cache.pop_front();
                                }
                                cache.push_back((topic, json_str.into_bytes()));
                            }
                        }
                        MessageEncoding::Uadp => {
                            let msg = UadpNetworkMessage {
                                publisher_id: PublisherId::String(publisher_id.clone()),
                                writer_group_id: writer_group.writer_group_id,
                                dataset_messages: uadp_dataset_messages,
                            };
                            let ctx_owned = ContextOwned::default();
                            let ctx = ctx_owned.context();
                            let payload = msg.encode_to_vec(&ctx);
                            let mut cache = publisher.lock().unwrap();
                            if cache.len() >= MAX_CACHE_SIZE {
                                let _ = cache.pop_front();
                            }
                            cache.push_back((topic, payload));
                        }
                    }
                }
            });
        }

        // 2. Spawn the MQTT connection and sender loop with backoff
        let handle = tokio::spawn(async move {
            let mut backoff = Duration::from_secs(1);

            loop {
                if cancel_token.is_cancelled() {
                    break;
                }

                let client_id = format!("opcua-publisher-{}", uuid::Uuid::new_v4());
                let mut options = MqttOptions::new(client_id, host.clone(), port);
                options.set_keep_alive(Duration::from_secs(5));

                let (client, mut event_loop) = AsyncClient::new(options, 50);

                // Background loop draining the cache and polling MQTT
                loop {
                    if cancel_token.is_cancelled() {
                        return;
                    }

                    // Attempt to publish one item from cache
                    let mut next_item = None;
                    {
                        let mut cache_lock = cache.lock().unwrap();
                        if let Some((topic, payload)) = cache_lock.pop_front() {
                            next_item = Some((topic, payload));
                        }
                    }

                    if let Some((topic, payload)) = next_item {
                        if let Err(_) = client
                            .publish(topic.clone(), QoS::AtLeastOnce, false, payload.clone())
                            .await
                        {
                            // Put it back at the front and break to reconnect
                            {
                                let mut cache_lock = cache.lock().unwrap();
                                cache_lock.push_front((topic, payload));
                            }
                            sleep(backoff).await;
                            backoff = std::cmp::min(backoff * 2, Duration::from_secs(60));
                            break;
                        }
                        // Success: continue draining cache immediately without polling event loop
                        continue;
                    }

                    // Cache is empty, poll the event loop to keep connection alive
                    tokio::select! {
                        _ = cancel_token.cancelled() => {
                            return;
                        }
                        res = event_loop.poll() => {
                            match res {
                                Ok(_) => {
                                    // Successful communication, reset backoff
                                    backoff = Duration::from_secs(1);
                                }
                                Err(_) => {
                                    // Connection lost, sleep and reconnect
                                    sleep(backoff).await;
                                    backoff = std::cmp::min(backoff * 2, Duration::from_secs(60));
                                    break;
                                }
                            }
                        }
                        _ = sleep(Duration::from_millis(20)) => {
                            // Wake up to check cache again
                        }
                    }
                }
            }
        });

        Ok(handle)
    }
}
