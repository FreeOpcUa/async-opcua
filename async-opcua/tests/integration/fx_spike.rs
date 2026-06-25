//! OPC UA FX spike (spec: docs/superpowers/specs/2026-06-24-fx-spike-design.md).
//! Proves async-opcua can host the FX information model and exchange one value AC1->AC2 over UADP.

use std::path::PathBuf;
use std::sync::Arc;

use opcua::core::sync::RwLock;
use opcua::nodes::DefaultTypeTree;
use opcua::server::address_space::{AddressSpace, VariableBuilder};
use opcua::server::nodeset_loader::NodeSetLoader;
use opcua::types::{BinaryDecodable, DataTypeId, NodeClass, NodeId};
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

use opcua_pubsub::{
    DataSetWriterConfig, MessageEncoding, PubSubBridge, PubSubConnectionConfig,
    PublishedDataSetConfig, UadpNetworkMessage, UdpPublisher, WriterGroupConfig,
};

fn nodeset(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/integration/fx/nodesets")
        .join(name)
}

/// Load the full FX nodeset chain into a fresh AddressSpace and return it with its type tree.
fn load_fx_address_space() -> (AddressSpace, DefaultTypeTree) {
    let loaded = NodeSetLoader::new("en")
        .load_files([
            nodeset("Opc.Ua.Di.NodeSet2.xml"),
            nodeset("opc.ua.fx.data.nodeset2.xml"),
            nodeset("opc.ua.fx.ac.nodeset2.xml"),
            nodeset("opc.ua.fx.cm.nodeset2.xml"),
        ])
        .expect("FX nodeset chain must load");

    let mut address_space = AddressSpace::new();
    let mut type_tree = DefaultTypeTree::new();
    address_space.import_node_set(
        &opcua::server::address_space::CoreNamespace,
        type_tree.namespaces_mut(),
    );
    for import in loaded.imports() {
        address_space.import_node_set(import.as_ref(), type_tree.namespaces_mut());
    }
    (address_space, type_tree)
}

#[test]
fn fx_information_model_loads_and_resolves() {
    let (address_space, _type_tree) = load_fx_address_space();

    let fx_ac_ns = address_space
        .namespace_index("http://opcfoundation.org/UA/FX/AC/")
        .expect("FX/AC namespace must be registered");

    // FX/AC type NodeIds (from opc.ua.fx.ac.nodeset2.xml): AutomationComponentType=2,
    // FunctionalEntityType=4, AcDescriptorType=1027 — all ObjectType.
    for (id, name) in [
        (2u32, "AutomationComponentType"),
        (4, "FunctionalEntityType"),
        (1027, "AcDescriptorType"),
    ] {
        let node = NodeId::new(fx_ac_ns, id);
        assert_eq!(
            address_space.find(&node).map(|n| n.node_class()),
            Some(NodeClass::ObjectType),
            "{name} (ns={fx_ac_ns};i={id}) must resolve as an ObjectType"
        );
    }
}

#[tokio::test]
async fn fx_c2c_process_value_flows_ac1_to_ac2() {
    // AC1: an FX-model address space exposing one process value to publish.
    let (mut space, _type_tree) = load_fx_address_space();
    // The FX nodeset chain already registered several namespaces at the low
    // indices; register AC1's own namespace at a high, guaranteed-free index so
    // the published variable's NodeId is valid and consistent with
    // `published_variables` (and does not clobber an FX namespace).
    let ac1_ns: u16 = 100;
    space.add_namespace("urn:async-opcua:fx:ac1", ac1_ns);
    let value_node = NodeId::new(ac1_ns, "Fx.ProcessValue");
    space.insert(
        VariableBuilder::new(&value_node, "ProcessValue", "ProcessValue")
            .data_type(DataTypeId::Double)
            .value(42.0f64)
            .build(),
        None::<&[(_, &NodeId, _)]>,
    );
    let address_space = Arc::new(RwLock::new(space));

    // AC2: the receiving side — a UDP socket that decodes the UADP NetworkMessage.
    let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let local_addr = receiver.local_addr().unwrap();

    let connection_config = PubSubConnectionConfig {
        reader_groups: Vec::new(),
        connection_id: "Ac1Publisher".to_string(),
        name: "Ac1Publisher".to_string(),
        address: format!("udp://{local_addr}"),
        writer_groups: vec![WriterGroupConfig {
            writer_group_id: 1,
            publishing_interval: 50,
            encoding: MessageEncoding::Uadp,
            dataset_writers: vec![DataSetWriterConfig {
                dataset_writer_id: 101,
                dataset_name: "FxDataset".to_string(),
                published_dataset: PublishedDataSetConfig {
                    published_variables: vec![value_node.clone()],
                    configuration_version: Default::default(),
                },
            }],
        }],
    };

    let publisher = Arc::new(UdpPublisher::new(address_space.clone()));
    let bridge = PubSubBridge::new(
        address_space.clone(),
        connection_config,
        None,
        Some(publisher),
    );
    let cancel = CancellationToken::new();
    let _handle = bridge.start(cancel.clone());

    let mut buf = [0u8; 4096];
    let (len, _from) = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        receiver.recv_from(&mut buf),
    )
    .await
    .expect("timed out waiting for the FX C2C UADP message")
    .expect("recv_from failed");

    let ctx_owned = opcua::types::ContextOwned::default();
    let decoded = UadpNetworkMessage::decode(&mut &buf[..len], &ctx_owned.context())
        .expect("decode UADP NetworkMessage");
    cancel.cancel();

    assert_eq!(decoded.writer_group_id, 1);
    assert_eq!(decoded.dataset_messages.len(), 1);
    assert_eq!(decoded.dataset_messages[0].dataset_writer_id, 101);
    let received = decoded.dataset_messages[0].fields[0]
        .clone()
        .try_cast_to::<f64>()
        .expect("field is f64");
    assert_eq!(
        received, 42.0f64,
        "AC2 must receive the value AC1 published"
    );
}
