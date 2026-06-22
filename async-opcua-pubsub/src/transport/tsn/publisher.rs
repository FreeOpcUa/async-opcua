// TSN transport publisher implementation

use std::sync::Arc;
use std::time::Duration;
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

use super::af_xdp::AfXdp;
use super::taprio::{TaprioConfig, TaprioDriver};

/// TSN implementation of `PubSubPublisher`.
/// Supports both AF_XDP raw socket transmission and a fallback to standard UDP with `tc taprio` scheduling.
pub struct TsnPublisher {
    address_space: Arc<RwLock<AddressSpace>>,
}

impl TsnPublisher {
    /// Creates a new `TsnPublisher` with the given AddressSpace reference.
    pub fn new(address_space: Arc<RwLock<AddressSpace>>) -> Self {
        Self { address_space }
    }
}

impl PubSubPublisher for TsnPublisher {
    fn start_publishing(
        &self,
        connection_config: PubSubConnectionConfig,
        cancel_token: CancellationToken,
    ) -> Result<tokio::task::JoinHandle<()>, StatusCode> {
        // Parse the interface name from the address, e.g. "tsn://eth0"
        let addr = connection_config
            .address
            .strip_prefix("tsn://")
            .unwrap_or(&connection_config.address);
        let interface_name = addr.to_string();

        // 1. Try to set up the kernel-space fallback driver (tc taprio)
        let taprio_config = TaprioConfig {
            interface: interface_name.clone(),
            num_tc: 2,
            map: vec![0, 1, 0, 0, 0, 0, 0, 0],
            queues: vec!["0".to_string(), "1".to_string()],
            base_time: 0,
            cycle_time: 1000000,
            sched_entries: vec![
                "sched-entry S 01 500000".to_string(),
                "sched-entry S 02 500000".to_string(),
            ],
        };
        let taprio = TaprioDriver::new(taprio_config);
        if let Err(e) = taprio.apply() {
            tracing::warn!(
                "Failed to apply tc taprio configuration on {}: {:?}. Proceeding with user-space simulation.",
                interface_name,
                e
            );
        }

        // 2. Initialize the user-space AF_XDP socket
        let af_xdp = Arc::new(AfXdp::new(&interface_name));
        let address_space = self.address_space.clone();
        let publisher_id = connection_config.connection_id.clone();

        // Spawn a coordinator task that manages the individual writer group loops
        let handle = tokio::spawn(async move {
            for writer_group in connection_config.writer_groups {
                let address_space = address_space.clone();
                let cancel_token = cancel_token.clone();
                let publisher_id = publisher_id.clone();
                let af_xdp = af_xdp.clone();

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
                                    network_message_number: 0,
                                    sequence_number,
                                    dataset_messages: uadp_dataset_messages,
                                };
                                let ctx_owned = ContextOwned::default();
                                let ctx = ctx_owned.context();
                                Some(msg.encode_to_vec(&ctx))
                            }
                        };

                        if let Some(payload) = payload {
                            // Send payload via AF_XDP socket
                            if let Err(e) = af_xdp.send(&payload) {
                                tracing::error!("TSN AF_XDP send error: {:?}", e);
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
