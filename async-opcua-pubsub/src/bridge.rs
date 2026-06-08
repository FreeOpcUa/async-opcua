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
    transport::amqp::AmqpPublisher,
    transport::mqtt::MqttPublisher,
    transport::udp::UdpPublisher,
    transport::websocket::WebSocketPublisher,
    MessageEncoding, PubSubConnectionConfig,
};

/// A bridge connecting OPC UA server Address Space changes to PubSub publishers.
pub struct PubSubBridge {
    address_space: Arc<RwLock<AddressSpace>>,
    connection_config: PubSubConnectionConfig,
    mqtt_publisher: Option<Arc<MqttPublisher>>,
    udp_publisher: Option<Arc<UdpPublisher>>,
    amqp_publisher: Option<Arc<AmqpPublisher>>,
    websocket_publisher: Option<Arc<WebSocketPublisher>>,
}

impl PubSubBridge {
    /// Creates a new `PubSubBridge`.
    pub fn new(
        address_space: Arc<RwLock<AddressSpace>>,
        connection_config: PubSubConnectionConfig,
        mqtt_publisher: Option<Arc<MqttPublisher>>,
        udp_publisher: Option<Arc<UdpPublisher>>,
    ) -> Self {
        Self {
            address_space,
            connection_config,
            mqtt_publisher,
            udp_publisher,
            amqp_publisher: None,
            websocket_publisher: None,
        }
    }

    /// Creates a new `PubSubBridge` with all supported transport publishers.
    pub fn with_publishers(
        address_space: Arc<RwLock<AddressSpace>>,
        connection_config: PubSubConnectionConfig,
        mqtt_publisher: Option<Arc<MqttPublisher>>,
        udp_publisher: Option<Arc<UdpPublisher>>,
        amqp_publisher: Option<Arc<AmqpPublisher>>,
        websocket_publisher: Option<Arc<WebSocketPublisher>>,
    ) -> Self {
        Self {
            address_space,
            connection_config,
            mqtt_publisher,
            udp_publisher,
            amqp_publisher,
            websocket_publisher,
        }
    }

    /// Starts the background monitoring loop for changes in the Address Space.
    pub fn start(&self, cancel_token: CancellationToken) -> tokio::task::JoinHandle<()> {
        let address_space = self.address_space.clone();
        let config = self.connection_config.clone();
        let mqtt = self.mqtt_publisher.clone();
        let udp = self.udp_publisher.clone();
        let amqp = self.amqp_publisher.clone();
        let websocket = self.websocket_publisher.clone();

        tokio::spawn(async move {
            let mut last_values = std::collections::HashMap::new();
            let mut sequence_number: u16 = 0;
            let publisher_id = config.connection_id.clone();

            loop {
                if cancel_token.is_cancelled() {
                    break;
                }

                sleep(Duration::from_millis(50)).await;

                let space = address_space.read();

                for writer_group in &config.writer_groups {
                    let mut group_changed = false;
                    let mut json_dataset_messages = Vec::new();
                    let mut uadp_dataset_messages = Vec::new();

                    for writer in &writer_group.dataset_writers {
                        let mut payload_map = std::collections::HashMap::new();
                        let mut uadp_fields = Vec::new();
                        let mut writer_changed = false;

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

                                    if let Some(ref val) = data_value.value {
                                        let prev = last_values.insert(node_id.clone(), val.clone());
                                        if prev.as_ref() != Some(val) {
                                            writer_changed = true;
                                            group_changed = true;
                                        }

                                        if writer_group.encoding == MessageEncoding::Json {
                                            if let Ok(val) = opcua_to_json_value(&data_value, &ctx)
                                            {
                                                payload_map.insert(node_id.to_string(), val);
                                            }
                                        } else {
                                            uadp_fields.push(val.clone());
                                        }
                                    }
                                }
                            }
                        }

                        if writer_changed {
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
                    }

                    if group_changed {
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
                                    let payload = json_str.into_bytes();
                                    if let Some(ref m) = mqtt {
                                        m.publish_immediate(topic.clone(), payload.clone());
                                    }
                                    if let Some(ref u) = udp {
                                        let addr = config
                                            .address
                                            .strip_prefix("udp://")
                                            .unwrap_or(&config.address);
                                        u.publish_immediate(payload.clone(), addr).await;
                                    }
                                    if let Some(ref a) = amqp {
                                        a.publish_immediate(topic.clone(), payload.clone());
                                    }
                                    if let Some(ref w) = websocket {
                                        w.publish_immediate(
                                            payload.clone(),
                                            &config.address,
                                            &writer_group.encoding,
                                        );
                                    }
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
                                if let Some(ref m) = mqtt {
                                    m.publish_immediate(topic.clone(), payload.clone());
                                }
                                if let Some(ref a) = amqp {
                                    a.publish_immediate(topic.clone(), payload.clone());
                                }
                                if let Some(ref w) = websocket {
                                    w.publish_immediate(
                                        payload.clone(),
                                        &config.address,
                                        &writer_group.encoding,
                                    );
                                }
                                if let Some(ref u) = udp {
                                    let addr = config
                                        .address
                                        .strip_prefix("udp://")
                                        .unwrap_or(&config.address);
                                    u.publish_immediate(payload.clone(), addr).await;
                                }
                            }
                        }
                    }
                }
            }
        })
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::{amqp::AmqpPublisher, websocket::WebSocketPublisher};

    #[test]
    fn bridge_accepts_publishers_for_all_transport_mappings() {
        let address_space = Arc::new(RwLock::new(AddressSpace::new()));
        let config = PubSubConnectionConfig {
            connection_id: "all-transports".to_string(),
            name: "all-transports".to_string(),
            address: "udp://127.0.0.1:4840".to_string(),
            writer_groups: Vec::new(),
        };

        let bridge = PubSubBridge::with_publishers(
            address_space.clone(),
            config,
            Some(Arc::new(MqttPublisher::new(address_space.clone()))),
            Some(Arc::new(UdpPublisher::new(address_space.clone()))),
            Some(Arc::new(AmqpPublisher::new(address_space.clone()))),
            Some(Arc::new(WebSocketPublisher::new(address_space))),
        );

        assert!(bridge.mqtt_publisher.is_some());
        assert!(bridge.udp_publisher.is_some());
        assert!(bridge.amqp_publisher.is_some());
        assert!(bridge.websocket_publisher.is_some());
    }
}
