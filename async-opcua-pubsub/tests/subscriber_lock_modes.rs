//! Subscriber address-space lock mode regression tests.

use std::{
    sync::{mpsc, Arc},
    thread,
    time::Duration,
};

use opcua_core::sync::RwLock;
use opcua_pubsub::{
    DataSetReaderConfig, FieldTargetConfig, PubSubConnectionConfig, PublisherId, ReaderGroupConfig,
    SubscriberRuntime, UadpDataSetMessage, UadpNetworkMessage,
};
use opcua_server::address_space::AddressSpace;
use opcua_types::{NodeId, Variant};

const VALIDATION_LOCK_TIMEOUT: Duration = Duration::from_millis(250);

fn dataset_msg(fields: Vec<Variant>) -> UadpDataSetMessage {
    UadpDataSetMessage {
        dataset_writer_id: 42,
        sequence_number: 1,
        timestamp: None,
        status: None,
        fields,
    }
}

fn network_msg(message: UadpDataSetMessage) -> UadpNetworkMessage {
    UadpNetworkMessage {
        publisher_id: PublisherId::UInt16(11),
        writer_group_id: 7,
        network_message_number: 3,
        sequence_number: message.sequence_number,
        dataset_messages: vec![message],
    }
}

fn reader(target: NodeId) -> DataSetReaderConfig {
    DataSetReaderConfig {
        name: Some("reader-a".to_string()),
        dataset_reader_id: 1,
        dataset_writer_id: 42,
        publisher_id: Some(PublisherId::UInt16(11)),
        writer_group_id: Some(7),
        network_message_number: Some(3),
        target_variables: vec![FieldTargetConfig::value(0, target)],
        ..DataSetReaderConfig::default()
    }
}

fn connection(reader: DataSetReaderConfig) -> PubSubConnectionConfig {
    PubSubConnectionConfig {
        connection_id: "conn".to_string(),
        name: "conn".to_string(),
        address: "udp://127.0.0.1:4840".to_string(),
        writer_groups: Vec::new(),
        reader_groups: vec![ReaderGroupConfig {
            reader_group_id: 1,
            dataset_readers: vec![reader],
            ..ReaderGroupConfig::default()
        }],
    }
}

#[test]
fn pubsub_subscriber_validation_uses_read_access_before_mutation() {
    let address_space = Arc::new(RwLock::new(AddressSpace::new()));
    let missing_target = NodeId::new(1, "MissingTarget");
    let message = network_msg(dataset_msg(vec![Variant::Double(12.0)]));
    let read_guard = address_space.read();
    let (result_tx, result_rx) = mpsc::channel();

    let worker = thread::spawn({
        let address_space = address_space.clone();
        move || {
            let mut runtime = SubscriberRuntime::with_connections(
                address_space,
                vec![connection(reader(missing_target))],
            )
            .expect("subscriber fixture must validate");
            let result = runtime.process_network_message(&message);
            let _ = result_tx.send(result.map(|outcome| outcome.applied_readers));
        }
    });

    let result = result_rx.recv_timeout(VALIDATION_LOCK_TIMEOUT);
    drop(read_guard);
    worker.join().expect("subscriber worker must not panic");

    // OPC-10000-14 5.4.1.2 and 6.3.2.1.1 require subscriber routing and
    // DataSetReader target checks to preserve configuration semantics. A
    // missing target is detected during validation, before any target mutation.
    assert_eq!(
        result.expect("subscriber validation should not wait for address-space write access"),
        Ok(0)
    );
}
