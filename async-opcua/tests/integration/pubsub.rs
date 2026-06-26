use opcua::core::sync::RwLock;
use opcua::server::address_space::{AddressSpace, NodeType, VariableBuilder};
use opcua::types::{BinaryDecodable, DataValue, NodeId, Variant};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

use opcua_pubsub::{
    DataSetWriterConfig, MessageEncoding, MqttPublisher, PubSubBridge, PubSubConnectionConfig,
    PubSubPublisher, PublishedDataSetConfig, UadpNetworkMessage, UdpPublisher, WriterGroupConfig,
};

#[tokio::test]
async fn test_udp_multicast_pubsub() {
    println!("Running UDP Multicast PubSub test...");

    // Find an unused local UDP port
    let receiver_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let local_addr = receiver_socket.local_addr().unwrap();
    println!("UDP receiver socket bound to: {}", local_addr);

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
                println!("Changed value in Address Space to 25.5");
            }
        }
    }

    // Receive the UDP multicast datagram (first packet = 20.0)
    let mut buf = [0u8; 4096];
    let (len, from_addr) =
        tokio::time::timeout(Duration::from_secs(3), receiver_socket.recv_from(&mut buf))
            .await
            .expect("Timeout waiting for first UDP multicast packet")
            .expect("Failed to receive first UDP multicast packet");

    println!(
        "Received first UDP packet of len {} from {}: {:?}",
        len,
        from_addr,
        &buf[..len]
    );

    // Decode UADP Network Message
    let ctx_owned = opcua::types::ContextOwned::default();
    let ctx = ctx_owned.context();
    let decoded_msg1 = UadpNetworkMessage::decode(&mut &buf[..len], &ctx)
        .expect("Failed to decode first UADP Network Message");

    println!("Decoded first message: {:?}", decoded_msg1);
    assert_eq!(decoded_msg1.writer_group_id, 1);
    assert_eq!(decoded_msg1.dataset_messages.len(), 1);
    assert_eq!(decoded_msg1.dataset_messages[0].dataset_writer_id, 101);
    assert_eq!(decoded_msg1.dataset_messages[0].fields.len(), 1);
    let val1 = decoded_msg1.dataset_messages[0].fields[0]
        .clone()
        .try_cast_to::<f64>()
        .expect("Value is not f64");
    assert_eq!(val1, 20.0f64);

    // Receive the UDP multicast datagram (second packet = 25.5)
    let mut buf2 = [0u8; 4096];
    let (len2, from_addr2) =
        tokio::time::timeout(Duration::from_secs(3), receiver_socket.recv_from(&mut buf2))
            .await
            .expect("Timeout waiting for second UDP multicast packet")
            .expect("Failed to receive second UDP multicast packet");

    println!(
        "Received second UDP packet of len {} from {}: {:?}",
        len2,
        from_addr2,
        &buf2[..len2]
    );

    let decoded_msg = UadpNetworkMessage::decode(&mut &buf2[..len2], &ctx)
        .expect("Failed to decode second UADP Network Message");

    println!("Decoded second message structure: {:?}", decoded_msg);

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

#[tokio::test]
async fn test_mqtt_broker_pubsub() {
    println!("Running MQTT PubSub test...");

    // Find an unused TCP port for the mock MQTT broker
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    println!("Mock MQTT broker will bind to port: {}", port);

    let cancel_token = CancellationToken::new();
    let broker_cancel = cancel_token.clone();

    // Start mock MQTT broker
    let broker_handle = tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{}", port))
            .await
            .unwrap();
        println!("Broker listening on 127.0.0.1:{}", port);
        let mut received_bytes = Vec::new();
        tokio::select! {
            _ = broker_cancel.cancelled() => {
                println!("Broker cancelled before connection accepted");
            }
            res = listener.accept() => {
                if let Ok((mut stream, addr)) = res {
                    println!("Broker: accepted connection from {}", addr);
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut buf = [0u8; 1024];
                    // Read CONNECT
                    match stream.read(&mut buf).await {
                        Ok(n) if n > 0 => {
                            println!("Broker: read {} bytes for CONNECT: {:?}", n, &buf[..n]);
                            // Send CONNACK
                            let connack = [0x20, 0x02, 0x00, 0x00];
                            if let Err(e) = stream.write_all(&connack).await {
                                println!("Broker: failed to write CONNACK: {:?}", e);
                                return received_bytes;
                            }
                            println!("Broker: sent CONNACK");
                            // Read subsequent PUBLISH packets
                            loop {
                                let mut p_buf = [0u8; 1024];
                                tokio::select! {
                                    _ = broker_cancel.cancelled() => {
                                        println!("Broker loop cancelled");
                                        break;
                                    }
                                    res_read = stream.read(&mut p_buf) => {
                                        match res_read {
                                            Ok(m) if m > 0 => {
                                                println!("Broker: read {} bytes: {:?}", m, &p_buf[..m]);
                                                received_bytes.extend_from_slice(&p_buf[..m]);
                                                if received_bytes.len() > 10 {
                                                    break;
                                                }
                                            }
                                            Ok(_) => {
                                                println!("Broker: EOF reached");
                                                break;
                                            }
                                            Err(e) => {
                                                println!("Broker: read error: {:?}", e);
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        Ok(_) => {
                            println!("Broker: empty read on CONNECT");
                        }
                        Err(e) => {
                            println!("Broker: read CONNECT error: {:?}", e);
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

/// Part 14 §9.1.4: the PublishSubscribe object's AddConnection / RemoveConnection Methods make the
/// PubSub configuration writable over the address space.
#[tokio::test]
async fn pubsub_add_remove_connection_methods() {
    use crate::utils::setup;
    use opcua::core::sync::Mutex;
    use opcua::server::node_manager::memory::CoreNodeManager;
    use opcua::types::{
        CallMethodRequest, ExtensionObject, MethodId, ObjectId, PubSubConnectionDataType,
        StatusCode,
    };
    use opcua_pubsub::{register_pubsub_config_methods, PubSubConfigManager};

    let (tester, _nm, session) = setup().await;
    let core_nm = tester
        .handle
        .node_managers()
        .get_of_type::<CoreNodeManager>()
        .expect("CoreNodeManager");

    // Register the writable-config Methods on the PublishSubscribe object (ns0). The PubSub objects
    // are materialized in a server namespace, which the operator must register first.
    let pubsub_ns = 50;
    core_nm
        .address_space()
        .write()
        .add_namespace("urn:pubsub-config-test", pubsub_ns);
    let manager = Arc::new(Mutex::new(PubSubConfigManager::new(pubsub_ns)));
    register_pubsub_config_methods(&core_nm, core_nm.address_space().clone(), manager.clone());

    // AddConnection: pass a PubSubConnectionDataType, get back the new connection NodeId.
    let conn = PubSubConnectionDataType {
        name: "WritableConn".into(),
        transport_profile_uri: "udp://239.0.0.1:4840".into(),
        ..Default::default()
    };
    let add = session
        .call_one(CallMethodRequest {
            object_id: ObjectId::PublishSubscribe.into(),
            method_id: MethodId::PublishSubscribe_AddConnection.into(),
            input_arguments: Some(vec![Variant::from(ExtensionObject::from_message(conn))]),
        })
        .await
        .unwrap();
    assert_eq!(add.status_code, StatusCode::Good);
    let outputs = add.output_arguments.unwrap_or_default();
    let new_id = match &outputs[0] {
        Variant::NodeId(id) => (**id).clone(),
        other => panic!("AddConnection must return a NodeId, got {other:?}"),
    };
    assert!(!new_id.is_null());
    {
        let m = manager.lock();
        assert_eq!(m.connections.len(), 1);
        assert_eq!(m.connections[0].name, "WritableConn");
    }
    // The connection object now exists in the address space.
    assert!(core_nm.address_space().read().node_exists(&new_id));

    // RemoveConnection: pass the NodeId, the connection is gone.
    let remove = session
        .call_one(CallMethodRequest {
            object_id: ObjectId::PublishSubscribe.into(),
            method_id: MethodId::PublishSubscribe_RemoveConnection.into(),
            input_arguments: Some(vec![Variant::from(new_id.clone())]),
        })
        .await
        .unwrap();
    assert_eq!(remove.status_code, StatusCode::Good);
    assert!(manager.lock().connections.is_empty());
    assert!(!core_nm.address_space().read().node_exists(&new_id));
}

/// Part 14 §9.1.4: the per-instance connection / group Methods make the nested PubSub configuration
/// (writer groups, reader groups, and their dataset writers/readers) writable over the address space.
#[tokio::test]
async fn pubsub_add_remove_group_methods() {
    use crate::utils::setup;
    use opcua::core::sync::Mutex;
    use opcua::server::node_manager::memory::CoreNodeManager;
    use opcua::types::{
        CallMethodRequest, DataSetReaderDataType, DataSetWriterDataType, ExtensionObject, MethodId,
        ObjectId, PubSubConnectionDataType, ReaderGroupDataType, StatusCode, WriterGroupDataType,
    };
    use opcua_pubsub::{register_pubsub_config_methods, PubSubConfigManager};

    let (tester, _nm, session) = setup().await;
    let core_nm = tester
        .handle
        .node_managers()
        .get_of_type::<CoreNodeManager>()
        .expect("CoreNodeManager");

    let pubsub_ns = 51;
    core_nm
        .address_space()
        .write()
        .add_namespace("urn:pubsub-group-test", pubsub_ns);
    let manager = Arc::new(Mutex::new(PubSubConfigManager::new(pubsub_ns)));
    register_pubsub_config_methods(&core_nm, core_nm.address_space().clone(), manager.clone());

    let call = |object_id: NodeId, method_id: MethodId, arg: Variant| {
        let session = &session;
        async move {
            session
                .call_one(CallMethodRequest {
                    object_id,
                    method_id: method_id.into(),
                    input_arguments: Some(vec![arg]),
                })
                .await
                .unwrap()
        }
    };
    let node_out = |result: &opcua::types::CallMethodResult| -> NodeId {
        match &result.output_arguments.as_ref().unwrap()[0] {
            Variant::NodeId(id) => (**id).clone(),
            other => panic!("expected a NodeId output, got {other:?}"),
        }
    };

    // A connection to hang the groups off.
    let conn = PubSubConnectionDataType {
        name: "GroupConn".into(),
        transport_profile_uri: "udp://239.0.0.1:4840".into(),
        ..Default::default()
    };
    let add_conn = call(
        ObjectId::PublishSubscribe.into(),
        MethodId::PublishSubscribe_AddConnection,
        Variant::from(ExtensionObject::from_message(conn)),
    )
    .await;
    assert_eq!(add_conn.status_code, StatusCode::Good);
    let conn_id = node_out(&add_conn);

    // AddWriterGroup on the connection.
    let wg = WriterGroupDataType {
        name: "WG".into(),
        publishing_interval: 100.0,
        ..Default::default()
    };
    let add_wg = call(
        conn_id.clone(),
        MethodId::PubSubConnectionType_AddWriterGroup,
        Variant::from(ExtensionObject::from_message(wg)),
    )
    .await;
    assert_eq!(add_wg.status_code, StatusCode::Good);
    let wg_id = node_out(&add_wg);
    assert!(core_nm.address_space().read().node_exists(&wg_id));

    // AddDataSetWriter on the writer group.
    let dsw = DataSetWriterDataType {
        name: "DSW".into(),
        data_set_name: "DS".into(),
        ..Default::default()
    };
    let add_dsw = call(
        wg_id.clone(),
        MethodId::WriterGroupType_AddDataSetWriter,
        Variant::from(ExtensionObject::from_message(dsw)),
    )
    .await;
    assert_eq!(add_dsw.status_code, StatusCode::Good);
    let dsw_id = node_out(&add_dsw);
    assert!(core_nm.address_space().read().node_exists(&dsw_id));

    // AddReaderGroup + AddDataSetReader.
    let rg = ReaderGroupDataType {
        name: "RG".into(),
        ..Default::default()
    };
    let add_rg = call(
        conn_id.clone(),
        MethodId::PubSubConnectionType_AddReaderGroup,
        Variant::from(ExtensionObject::from_message(rg)),
    )
    .await;
    assert_eq!(add_rg.status_code, StatusCode::Good);
    let rg_id = node_out(&add_rg);
    assert!(core_nm.address_space().read().node_exists(&rg_id));

    let dsr = DataSetReaderDataType {
        name: "DSR".into(),
        ..Default::default()
    };
    let add_dsr = call(
        rg_id.clone(),
        MethodId::ReaderGroupType_AddDataSetReader,
        Variant::from(ExtensionObject::from_message(dsr)),
    )
    .await;
    assert_eq!(add_dsr.status_code, StatusCode::Good);
    let dsr_id = node_out(&add_dsr);
    assert!(core_nm.address_space().read().node_exists(&dsr_id));

    // The live config now has the full nested shape.
    {
        let m = manager.lock();
        let c = &m.connections[0];
        assert_eq!(c.writer_groups.len(), 1);
        assert_eq!(c.writer_groups[0].dataset_writers.len(), 1);
        assert_eq!(c.reader_groups.len(), 1);
        assert_eq!(c.reader_groups[0].dataset_readers.len(), 1);
    }

    // RemoveGroup on the writer group prunes the writer subtree (group + dataset writer).
    let remove_wg = call(
        conn_id.clone(),
        MethodId::PubSubConnectionType_RemoveGroup,
        Variant::from(wg_id.clone()),
    )
    .await;
    assert_eq!(remove_wg.status_code, StatusCode::Good);
    {
        let space = core_nm.address_space().read();
        assert!(!space.node_exists(&wg_id));
        assert!(
            !space.node_exists(&dsw_id),
            "dataset writer must be pruned too"
        );
    }
    assert!(manager.lock().connections[0].writer_groups.is_empty());

    // RemoveDataSetReader leaves the reader group but drops the reader.
    let remove_dsr = call(
        rg_id.clone(),
        MethodId::ReaderGroupType_RemoveDataSetReader,
        Variant::from(dsr_id.clone()),
    )
    .await;
    assert_eq!(remove_dsr.status_code, StatusCode::Good);
    assert!(!core_nm.address_space().read().node_exists(&dsr_id));
    assert!(manager.lock().connections[0].reader_groups[0]
        .dataset_readers
        .is_empty());

    // Removing the connection prunes everything that is left (reader group included).
    let remove_conn = call(
        ObjectId::PublishSubscribe.into(),
        MethodId::PublishSubscribe_RemoveConnection,
        Variant::from(conn_id.clone()),
    )
    .await;
    assert_eq!(remove_conn.status_code, StatusCode::Good);
    {
        let space = core_nm.address_space().read();
        assert!(!space.node_exists(&conn_id));
        assert!(
            !space.node_exists(&rg_id),
            "reader group must be pruned with its connection"
        );
    }
    assert!(manager.lock().connections.is_empty());
}
