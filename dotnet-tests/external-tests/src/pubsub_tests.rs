use opcua::core::sync::RwLock;
use opcua::server::address_space::{AddressSpace, NodeType, VariableBuilder};
use opcua::types::{BinaryDecodable, DataValue, NodeId, Variant};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

use crate::client::ClientTestState;
use opcua::client::Session;
use opcua_pubsub::{
    DataSetWriterConfig, MessageEncoding, MqttPublisher, PubSubBridge, PubSubConnectionConfig,
    PubSubPublisher, PublishedDataSetConfig, UadpNetworkMessage, UdpPublisher, WriterGroupConfig,
};

pub async fn test_pubsub(_session: Arc<Session>, _ctx: &mut ClientTestState) {
    println!("Starting PubSub Integration Tests...");

    // 1. Test UDP Multicast Publish-Subscribe
    test_udp_multicast().await;

    // 2. Test MQTT Publish-Subscribe with mock broker
    test_mqtt_broker().await;

    println!("PubSub Integration Tests complete!");
}

async fn test_udp_multicast() {
    println!("Running UDP Multicast PubSub test...");

    // Find an unused local UDP port
    let receiver_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let local_addr = receiver_socket.local_addr().unwrap();

    let node_id = NodeId::new(1, "UdpTempSensor");
    let mut space = AddressSpace::new();
    space.add_namespace("http://opcfoundation.org/UA/", 0);
    space.add_namespace("urn:test", 1);

    let var = VariableBuilder::new(&node_id, "UdpTempSensor", "UdpTempSensor")
        .data_type(opcua::types::DataTypeId::Double)
        .value(20.0f64)
        .build();
    space.insert(var, None::<&[(_, &NodeId, _)]>);

    let address_space = Arc::new(RwLock::new(space));
    let udp_publisher = Arc::new(UdpPublisher::new(address_space.clone()));

    let connection_config = PubSubConnectionConfig {
        reader_groups: Vec::new(),
        connection_id: "UdpPublisher1".to_string(),
        name: "UdpPublisher".to_string(),
        address: format!("udp://{}", local_addr),
        writer_groups: vec![WriterGroupConfig {
            writer_group_id: 1,
            publishing_interval: 50,
            encoding: MessageEncoding::Uadp,
            dataset_writers: vec![DataSetWriterConfig {
                dataset_writer_id: 101,
                dataset_name: "UdpDataset".to_string(),
                published_dataset: PublishedDataSetConfig {
                    published_variables: vec![node_id.clone()],
                    configuration_version: Default::default(),
                },
            }],
        }],
    };

    let bridge = PubSubBridge::new(
        address_space.clone(),
        connection_config.clone(),
        None,
        Some(udp_publisher),
    );

    let cancel_token = CancellationToken::new();
    let _bridge_handle = bridge.start(cancel_token.clone());

    // Wait for the cyclic publishing loop to start and query the initial value
    tokio::time::sleep(Duration::from_millis(150)).await;

    // Change value in Address Space to trigger bridge.
    // The bridge checks for changes every 50ms and publishes immediately when a change is detected.
    {
        let space_lock = address_space.read();
        let mut node_opt = space_lock.find_mut(&node_id);
        if let Some(ref mut node_guard) = node_opt {
            if let NodeType::Variable(ref mut var) = **node_guard {
                var.set_data_value(DataValue::value_only(Variant::from(25.5f64)));
            }
        }
    }

    // Receive the UDP multicast datagram
    let mut buf = [0u8; 4096];
    let (len, _) =
        tokio::time::timeout(Duration::from_secs(3), receiver_socket.recv_from(&mut buf))
            .await
            .expect("Timeout waiting for UDP multicast packet")
            .expect("Failed to receive UDP multicast packet");

    // Decode UADP Network Message
    let ctx_owned = opcua::types::ContextOwned::default();
    let ctx = ctx_owned.context();
    let decoded_msg = UadpNetworkMessage::decode(&mut &buf[..len], &ctx)
        .expect("Failed to decode UADP Network Message");

    assert_eq!(decoded_msg.writer_group_id, 1);
    assert_eq!(decoded_msg.dataset_messages.len(), 1);
    let ds_msg = &decoded_msg.dataset_messages[0];
    assert_eq!(ds_msg.dataset_writer_id, 101);
    assert_eq!(ds_msg.fields.len(), 1);

    let val = ds_msg.fields[0]
        .clone()
        .try_cast_to::<f64>()
        .expect("Value is not f64");
    assert_eq!(val, 25.5f64);

    cancel_token.cancel();
}

async fn test_mqtt_broker() {
    println!("Running MQTT PubSub test...");

    // Find an unused TCP port for the mock MQTT broker
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    let cancel_token = CancellationToken::new();
    let broker_cancel = cancel_token.clone();

    // Start mock MQTT broker
    let broker_handle = tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{}", port))
            .await
            .unwrap();
        let mut received_bytes = Vec::new();
        tokio::select! {
            _ = broker_cancel.cancelled() => {}
            res = listener.accept() => {
                if let Ok((mut stream, _)) = res {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut buf = [0u8; 1024];
                    // Read CONNECT
                    if let Ok(n) = stream.read(&mut buf).await {
                        if n > 0 {
                            // Send CONNACK
                            let connack = [0x20, 0x02, 0x00, 0x00];
                            let _ = stream.write_all(&connack).await;
                            // Read subsequent PUBLISH packets
                            loop {
                                let mut p_buf = [0u8; 1024];
                                tokio::select! {
                                    _ = broker_cancel.cancelled() => break,
                                    res_read = stream.read(&mut p_buf) => {
                                        if let Ok(m) = res_read {
                                            if m == 0 { break; }
                                            received_bytes.extend_from_slice(&p_buf[..m]);
                                            if received_bytes.len() > 10 {
                                                // We got some telemetry publish data, we can finish
                                                break;
                                            }
                                        } else {
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        received_bytes
    });

    let node_id = NodeId::new(1, "MqttTempSensor");
    let mut space = AddressSpace::new();
    space.add_namespace("http://opcfoundation.org/UA/", 0);
    space.add_namespace("urn:test", 1);

    let var = VariableBuilder::new(&node_id, "MqttTempSensor", "MqttTempSensor")
        .data_type(opcua::types::DataTypeId::Double)
        .value(10.0f64)
        .build();
    space.insert(var, None::<&[(_, &NodeId, _)]>);

    let address_space = Arc::new(RwLock::new(space));
    let mqtt_publisher = Arc::new(MqttPublisher::new(address_space.clone()));

    let connection_config = PubSubConnectionConfig {
        reader_groups: Vec::new(),
        connection_id: "MqttPublisher1".to_string(),
        name: "MqttPublisher".to_string(),
        address: format!("mqtt://127.0.0.1:{}", port),
        writer_groups: vec![WriterGroupConfig {
            writer_group_id: 2,
            publishing_interval: 50,
            encoding: MessageEncoding::Json,
            dataset_writers: vec![DataSetWriterConfig {
                dataset_writer_id: 102,
                dataset_name: "MqttDataset".to_string(),
                published_dataset: PublishedDataSetConfig {
                    published_variables: vec![node_id.clone()],
                    configuration_version: Default::default(),
                },
            }],
        }],
    };

    // Start publishing via MqttPublisher
    let publisher_handle = mqtt_publisher
        .start_publishing(connection_config, cancel_token.clone())
        .unwrap();

    // Wait for client to connect and cyclic publish
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Shutdown/cancel tasks
    cancel_token.cancel();

    let _ = publisher_handle.await;
    let received_data = broker_handle.await.unwrap();

    // Verify we received data containing some MQTT publish info
    assert!(
        !received_data.is_empty(),
        "Mock MQTT broker did not receive any publish data"
    );
    println!(
        "Mock MQTT broker received {} bytes of publish data",
        received_data.len()
    );
}
