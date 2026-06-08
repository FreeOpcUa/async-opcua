use std::sync::Arc;
use std::time::Duration;

use futures::SinkExt;
use opcua_core::sync::RwLock;
use opcua_server::address_space::{AddressSpace, NodeType};
use opcua_types::{
    BinaryEncodable, ContextOwned, DataEncoding, NumericRange, StatusCode, TimestampsToReturn,
};
use tokio::time::sleep;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;
use tokio_util::sync::CancellationToken;

use crate::{
    codec::json::{opcua_to_json_value, JsonDataSetMessage, JsonNetworkMessage},
    codec::uadp::{PublisherId, UadpDataSetMessage, UadpNetworkMessage},
    MessageEncoding, PubSubConnectionConfig, PubSubPublisher,
};

#[derive(Debug, Clone, PartialEq, Eq)]
struct WebSocketAddressSettings {
    url: String,
}

/// WebSocket implementation of `PubSubPublisher`.
pub struct WebSocketPublisher {
    address_space: Arc<RwLock<AddressSpace>>,
}

impl WebSocketPublisher {
    /// Creates a new `WebSocketPublisher` with the given AddressSpace reference.
    pub fn new(address_space: Arc<RwLock<AddressSpace>>) -> Self {
        Self { address_space }
    }

    /// Sends a single payload to a WebSocket endpoint without starting a cyclic publisher loop.
    pub fn publish_immediate(
        &self,
        payload: Vec<u8>,
        destination_address: &str,
        encoding: &MessageEncoding,
    ) {
        let destination_address = destination_address.to_string();
        let encoding = encoding.clone();

        tokio::spawn(async move {
            let settings = match parse_websocket_address(&destination_address) {
                Ok(settings) => settings,
                Err(error) => {
                    tracing::warn!(
                        address = %destination_address,
                        ?error,
                        "invalid WebSocket PubSub destination"
                    );
                    return;
                }
            };

            let Some(frame) = frame_for_payload(&encoding, payload) else {
                tracing::warn!("failed to encode WebSocket PubSub frame");
                return;
            };

            match connect_async(&settings.url).await {
                Ok((mut websocket, _)) => {
                    if let Err(error) = websocket.send(frame).await {
                        tracing::warn!(url = %settings.url, ?error, "failed to publish WebSocket payload");
                    }
                }
                Err(error) => {
                    tracing::warn!(url = %settings.url, ?error, "failed to connect WebSocket publisher");
                }
            }
        });
    }
}

impl PubSubPublisher for WebSocketPublisher {
    fn start_publishing(
        &self,
        connection_config: PubSubConnectionConfig,
        cancel_token: CancellationToken,
    ) -> Result<tokio::task::JoinHandle<()>, StatusCode> {
        let settings = parse_websocket_address(&connection_config.address)?;
        let address_space = self.address_space.clone();
        let publisher_id = connection_config.connection_id.clone();

        let handle = tokio::spawn(async move {
            let mut group_handles = Vec::with_capacity(connection_config.writer_groups.len());

            for writer_group in connection_config.writer_groups {
                let address_space = address_space.clone();
                let cancel_token = cancel_token.clone();
                let publisher_id = publisher_id.clone();
                let url = settings.url.clone();

                group_handles.push(tokio::spawn(async move {
                    let mut sequence_number: u16 = 0;
                    let mut backoff = Duration::from_secs(1);

                    loop {
                        if cancel_token.is_cancelled() {
                            break;
                        }

                        let (mut websocket, _) = match connect_async(&url).await {
                            Ok(connection) => connection,
                            Err(error) => {
                                tracing::warn!(%url, ?error, "failed to connect WebSocket publisher");
                                wait_for_reconnect(&cancel_token, &mut backoff).await;
                                continue;
                            }
                        };

                        backoff = Duration::from_secs(1);

                        loop {
                            tokio::select! {
                                _ = cancel_token.cancelled() => {
                                    return;
                                }
                                _ = sleep(Duration::from_millis(writer_group.publishing_interval)) => {}
                            }

                            let payload = {
                                let space = address_space.read();
                                build_writer_group_payload(
                                    &space,
                                    &writer_group,
                                    &publisher_id,
                                    &mut sequence_number,
                                )
                            };

                            let Some(payload) = payload else {
                                continue;
                            };

                            let Some(frame) = frame_for_payload(&writer_group.encoding, payload)
                            else {
                                tracing::warn!(
                                    writer_group_id = writer_group.writer_group_id,
                                    "failed to encode WebSocket JSON text frame"
                                );
                                continue;
                            };

                            if let Err(error) = websocket.send(frame).await {
                                tracing::warn!(%url, ?error, "failed to publish WebSocket payload");
                                wait_for_reconnect(&cancel_token, &mut backoff).await;
                                break;
                            }
                        }
                    }
                }));
            }

            cancel_token.cancelled().await;

            for group_handle in group_handles {
                group_handle.abort();
            }
        });

        Ok(handle)
    }
}

fn parse_websocket_address(address: &str) -> Result<WebSocketAddressSettings, StatusCode> {
    let address = address.trim();
    if address.is_empty() {
        return Err(StatusCode::BadInvalidArgument);
    }

    let url = if address.starts_with("ws://") || address.starts_with("wss://") {
        address.to_string()
    } else {
        format!("ws://{address}")
    };

    Ok(WebSocketAddressSettings { url })
}

fn frame_for_payload(encoding: &MessageEncoding, payload: Vec<u8>) -> Option<Message> {
    match encoding {
        MessageEncoding::Json => String::from_utf8(payload).ok().map(Message::Text),
        MessageEncoding::Uadp => Some(Message::Binary(payload)),
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
            if let Some(NodeType::Variable(var)) = space.find(node_id).as_deref() {
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

    #[test]
    fn parses_websocket_address_with_prefix() {
        let settings = parse_websocket_address("ws://broker.local:9001/opcua").unwrap();

        assert_eq!(settings.url, "ws://broker.local:9001/opcua");
    }

    #[test]
    fn parses_websocket_address_without_prefix_as_ws_url() {
        let settings = parse_websocket_address("broker.local:9001/opcua").unwrap();

        assert_eq!(settings.url, "ws://broker.local:9001/opcua");
    }

    #[test]
    fn rejects_empty_websocket_address() {
        let error = parse_websocket_address("  ").unwrap_err();

        assert_eq!(error, StatusCode::BadInvalidArgument);
    }

    #[test]
    fn sends_json_payload_as_text_frame() {
        let frame = frame_for_payload(
            &MessageEncoding::Json,
            br#"{"MessageType":"ua-data"}"#.to_vec(),
        )
        .unwrap();

        assert_eq!(
            frame,
            Message::Text(r#"{"MessageType":"ua-data"}"#.to_string())
        );
    }

    #[test]
    fn sends_uadp_payload_as_binary_frame() {
        let frame = frame_for_payload(&MessageEncoding::Uadp, vec![1, 2, 3]).unwrap();

        assert_eq!(frame, Message::Binary(vec![1, 2, 3]));
    }
}
