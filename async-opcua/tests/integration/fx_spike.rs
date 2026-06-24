//! OPC UA FX spike (spec: docs/superpowers/specs/2026-06-24-fx-spike-design.md).
//! Proves async-opcua can host the FX information model and exchange one value AC1->AC2 over UADP.

use std::path::PathBuf;

use opcua::nodes::DefaultTypeTree;
use opcua::server::address_space::AddressSpace;
use opcua::server::nodeset_loader::NodeSetLoader;
use opcua::types::{NodeClass, NodeId};

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
