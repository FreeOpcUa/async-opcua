use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;

use opcua_core::sync::RwLock;
use opcua_server::address_space::{AddressSpace, NodeType};
use opcua_types::{
    BinaryEncodable, ContextOwned, DataEncoding, NumericRange, StatusCode, TimestampsToReturn,
};

use crate::{
    codec::json::{JsonDataSetMessage, JsonNetworkMessage},
    codec::uadp::{PublisherId, UadpDataSetMessage, UadpNetworkMessage},
    MessageEncoding, PubSubConnectionConfig, PubSubPublisher,
};

/// Maximum transmission unit for a single UDP packet to avoid IP-level fragmentation.
const MTU: usize = 1400;

/// UDP Multicast implementation of `PubSubPublisher` with datagram fragmentation.
pub struct UdpPublisher {
    address_space: Arc<RwLock<AddressSpace>>,
}

impl UdpPublisher {
    /// Creates a new `UdpPublisher` with the given AddressSpace reference.
    pub fn new(address_space: Arc<RwLock<AddressSpace>>) -> Self {
        Self { address_space }
    }

    /// Instantly sends a payload to the destination address.
    pub async fn publish_immediate(&self, payload: Vec<u8>, destination_address: &str) {
        if let Ok(socket) = UdpSocket::bind("0.0.0.0:0").await {
            let _ = socket.send_to(&payload, destination_address).await;
        }
    }
}

impl PubSubPublisher for UdpPublisher {
    fn start_publishing(
        &self,
        connection_config: PubSubConnectionConfig,
        cancel_token: CancellationToken,
    ) -> Result<tokio::task::JoinHandle<()>, StatusCode> {
        let addr = connection_config
            .address
            .strip_prefix("udp://")
            .unwrap_or(&connection_config.address);
        let destination_address = addr.to_string();

        let address_space = self.address_space.clone();
        let publisher_id = connection_config.connection_id.clone();

        // Spawn a coordinator task that manages the individual writer group loops
        let handle = tokio::spawn(async move {
            for writer_group in connection_config.writer_groups {
                let address_space = address_space.clone();
                let cancel_token = cancel_token.clone();
                let destination_address = destination_address.clone();
                let publisher_id = publisher_id.clone();

                // Bind a local UDP socket for this group
                let socket = match UdpSocket::bind("0.0.0.0:0").await {
                    Ok(s) => Arc::new(s),
                    Err(e) => {
                        tracing::error!("Failed to bind UDP socket for writer group: {:?}", e);
                        continue;
                    }
                };

                let _ = socket.set_multicast_loop_v4(true);
                let _ = socket.set_multicast_ttl_v4(32);

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
                                        let ctx_owned = ContextOwned::default();
                                        let ctx = ctx_owned.context();
                                        let data_value = var.value(
                                            TimestampsToReturn::Both,
                                            &NumericRange::None,
                                            &DataEncoding::Binary,
                                            0.0,
                                        );

                                        if writer_group.encoding == MessageEncoding::Json {
                                            if let Ok(val) = opcua_to_json_value(&data_value, &ctx)
                                            {
                                                payload_map.insert(node_id.to_string(), val);
                                            }
                                        } else if let Some(ref val) = data_value.value {
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

                        // Format payload
                        let payload = match writer_group.encoding {
                            MessageEncoding::Json => {
                                let msg = JsonNetworkMessage {
                                    message_id: uuid::Uuid::new_v4().to_string(),
                                    message_type: "ua-data".to_string(),
                                    publisher_id: publisher_id.clone(),
                                    writer_group_id: writer_group.writer_group_id,
                                    messages: json_dataset_messages,
                                };
                                msg.to_json_string().ok().map(|s| s.into_bytes())
                            }
                            MessageEncoding::Uadp => {
                                let msg = UadpNetworkMessage {
                                    publisher_id: PublisherId::String(publisher_id.clone()),
                                    writer_group_id: writer_group.writer_group_id,
                                    dataset_messages: uadp_dataset_messages,
                                };
                                let ctx_owned = ContextOwned::default();
                                let ctx = ctx_owned.context();
                                Some(msg.encode_to_vec(&ctx))
                            }
                        };

                        if let Some(payload) = payload {
                            // Send payload with datagram fragmentation if size > MTU
                            if payload.len() <= MTU {
                                let _ = socket.send_to(&payload, &destination_address).await;
                            } else {
                                let total_fragments = ((payload.len() + MTU - 1) / MTU) as u8;
                                for fragment_index in 0..total_fragments {
                                    let start = fragment_index as usize * MTU;
                                    let end = std::cmp::min(start + MTU, payload.len());
                                    let chunk = &payload[start..end];

                                    // Fragment header: sequence_number (2b), total_fragments (1b), fragment_index (1b), chunk_size (2b)
                                    let mut packet = Vec::with_capacity(6 + chunk.len());
                                    packet.extend_from_slice(&sequence_number.to_be_bytes());
                                    packet.push(total_fragments);
                                    packet.push(fragment_index);
                                    packet.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
                                    packet.extend_from_slice(chunk);

                                    let _ = socket.send_to(&packet, &destination_address).await;
                                }
                            }
                        }
                    }
                });
            }

            // Keep coordinator task alive until cancelled
            cancel_token.cancelled().await;
        });

        Ok(handle)
    }
}

/// Helper function to convert an OPC-UA `JsonEncodable` type to a `serde_json::Value`.
fn opcua_to_json_value<T: opcua_types::json::JsonEncodable>(
    value: &T,
    ctx: &opcua_types::Context<'_>,
) -> Result<serde_json::Value, opcua_types::Error> {
    let json_str = opcua_types::json::to_string(value, ctx)?;
    let val =
        serde_json::from_str(&json_str).map_err(|e| opcua_types::Error::decoding(e.to_string()))?;
    Ok(val)
}
