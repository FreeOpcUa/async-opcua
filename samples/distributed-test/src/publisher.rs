use opcua::core::sync::RwLock;
use opcua::server::address_space::{AddressSpace, VariableBuilder};
use opcua::types::{NodeId, Variant};
use opcua_pubsub::{
    DataSetWriterConfig, MessageEncoding, PubSubConnectionConfig, PubSubPublisher,
    PublishedDataSetConfig, UdpPublisher, WriterGroupConfig,
};
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

#[tokio::main]
async fn main() {
    println!("Starting PLC Publisher on PLC01...");
    let node_id = NodeId::new(1, "TemperatureSensor");
    let mut space = AddressSpace::new();
    space.add_namespace("http://opcfoundation.org/UA/", 0);
    space.add_namespace("urn:test", 1);

    let var = VariableBuilder::new(&node_id, "TemperatureSensor", "TemperatureSensor")
        .data_type(opcua::types::DataTypeId::Double)
        .value(20.0f64)
        .build();
    space.insert(var, None::<&[(_, &NodeId, _)]>);

    let address_space = Arc::new(RwLock::new(space));
    let udp_publisher = Arc::new(UdpPublisher::new(address_space.clone()));

    let connection_config = PubSubConnectionConfig {
        connection_id: "UdpPublisher1".to_string(),
        name: "UdpPublisher".to_string(),
        address: "opc.udp://192.168.150.203:4840".to_string(), // Send to PLC02 WG IP
        writer_groups: vec![WriterGroupConfig {
            writer_group_id: 1,
            publishing_interval: 1000,
            encoding: MessageEncoding::Uadp,
            dataset_writers: vec![DataSetWriterConfig {
                dataset_writer_id: 101,
                dataset_name: "TemperatureDataset".to_string(),
                published_dataset: PublishedDataSetConfig {
                    published_variables: vec![node_id.clone()],
                },
            }],
        }],
    };

    let cancel_token = CancellationToken::new();
    let publisher_handle = udp_publisher
        .start_publishing(connection_config, cancel_token.clone())
        .unwrap();

    println!("Publisher started. Sending data to 192.168.150.203...");
    tokio::time::sleep(std::time::Duration::from_secs(60)).await;
    cancel_token.cancel();
    let _ = publisher_handle.await;
}
