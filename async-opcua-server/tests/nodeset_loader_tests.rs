//! Integration tests for runtime NodeSet2 loading.

use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use opcua_nodes::DefaultTypeTree;
use opcua_server::{address_space::AddressSpace, nodeset_loader::NodeSetLoader};
use opcua_types::{BrowseDirection, NodeClass, NodeId, ReferenceTypeId};

const BASE_NODESET: &str = r#"
<UANodeSet xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
           xmlns:xsd="http://www.w3.org/2001/XMLSchema"
           xmlns="http://opcfoundation.org/UA/2011/03/UANodeSet.xsd">
  <NamespaceUris>
    <Uri>urn:async-opcua:test:base</Uri>
  </NamespaceUris>
  <Aliases>
    <Alias Alias="HasSubtype">i=45</Alias>
  </Aliases>
  <UAObjectType NodeId="ns=1;i=1001" BrowseName="1:BaseMachineType">
    <DisplayName>BaseMachineType</DisplayName>
    <References>
      <Reference ReferenceType="HasSubtype" IsForward="false">i=58</Reference>
    </References>
  </UAObjectType>
</UANodeSet>
"#;

const COMPANION_NODESET: &str = r#"
<UANodeSet xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
           xmlns:xsd="http://www.w3.org/2001/XMLSchema"
           xmlns="http://opcfoundation.org/UA/2011/03/UANodeSet.xsd">
  <NamespaceUris>
    <Uri>urn:async-opcua:test:base</Uri>
    <Uri>urn:async-opcua:test:companion</Uri>
  </NamespaceUris>
  <Aliases>
    <Alias Alias="HasSubtype">i=45</Alias>
    <Alias Alias="HasTypeDefinition">i=40</Alias>
    <Alias Alias="HasComponent">i=47</Alias>
    <Alias Alias="String">i=12</Alias>
  </Aliases>
  <UAObjectType NodeId="ns=2;i=2001" BrowseName="2:CompanionMachineType">
    <DisplayName>CompanionMachineType</DisplayName>
    <References>
      <Reference ReferenceType="HasSubtype" IsForward="false">ns=1;i=1001</Reference>
    </References>
  </UAObjectType>
  <UAObject NodeId="ns=2;s=Machine1" BrowseName="2:Machine1">
    <DisplayName>Machine1</DisplayName>
    <References>
      <Reference ReferenceType="HasTypeDefinition">ns=2;i=2001</Reference>
    </References>
  </UAObject>
  <UAVariable NodeId="ns=2;s=Machine1.SerialNumber" BrowseName="2:SerialNumber" DataType="String">
    <DisplayName>SerialNumber</DisplayName>
    <References>
      <Reference ReferenceType="HasComponent" IsForward="false">ns=2;s=Machine1</Reference>
    </References>
    <Value>
      <String>SN-001</String>
    </Value>
  </UAVariable>
  <UAMethod NodeId="ns=2;s=Machine1.Reset" BrowseName="2:Reset">
    <DisplayName>Reset</DisplayName>
    <References>
      <Reference ReferenceType="HasComponent" IsForward="false">ns=2;s=Machine1</Reference>
    </References>
  </UAMethod>
</UANodeSet>
"#;

#[test]
fn loader_registers_namespaces_and_imports_cross_namespace_nodes(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = test_dir("nodeset-loader-cross-ns")?;
    let base_path = write_nodeset(&dir, "base.NodeSet2.xml", BASE_NODESET)?;
    let companion_path = write_nodeset(&dir, "companion.NodeSet2.xml", COMPANION_NODESET)?;

    let loaded = NodeSetLoader::new("en").load_files([&base_path, &companion_path])?;

    assert_eq!(
        loaded.namespace_uris(),
        &[
            "http://opcfoundation.org/UA/".to_string(),
            "urn:async-opcua:test:base".to_string(),
            "urn:async-opcua:test:companion".to_string()
        ]
    );

    let mut address_space = AddressSpace::new();
    let mut type_tree = DefaultTypeTree::new();
    for import in loaded.imports() {
        address_space.import_node_set(import.as_ref(), type_tree.namespaces_mut());
    }

    let base_ns = address_space
        .namespace_index("urn:async-opcua:test:base")
        .ok_or("base namespace missing")?;
    let companion_ns = address_space
        .namespace_index("urn:async-opcua:test:companion")
        .ok_or("companion namespace missing")?;

    let base_type = NodeId::new(base_ns, 1001);
    let companion_type = NodeId::new(companion_ns, 2001);
    let machine = NodeId::new(companion_ns, "Machine1");
    let serial = NodeId::new(companion_ns, "Machine1.SerialNumber");
    let reset = NodeId::new(companion_ns, "Machine1.Reset");

    assert_eq!(
        address_space
            .find(&companion_type)
            .map(|node| node.node_class()),
        Some(NodeClass::ObjectType)
    );
    assert_eq!(
        address_space.find(&serial).map(|node| node.node_class()),
        Some(NodeClass::Variable)
    );
    assert_eq!(
        address_space.find(&reset).map(|node| node.node_class()),
        Some(NodeClass::Method)
    );
    assert!(address_space.has_reference(&base_type, &companion_type, ReferenceTypeId::HasSubtype));
    assert!(address_space.has_reference(&machine, &serial, ReferenceTypeId::HasComponent));
    assert!(address_space.has_reference(&machine, &reset, ReferenceTypeId::HasComponent));

    let subtype_refs = address_space
        .find_references(
            &base_type,
            Some((ReferenceTypeId::HasSubtype, false)),
            &type_tree,
            BrowseDirection::Forward,
        )
        .count();
    assert_eq!(subtype_refs, 1);

    fs::remove_dir_all(dir)?;
    Ok(())
}

fn test_dir(name: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let unique = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let dir = std::env::temp_dir().join(format!("{name}-{unique}"));
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn write_nodeset(
    dir: &Path,
    file_name: &str,
    contents: &str,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let path = dir.join(file_name);
    fs::write(&path, contents)?;
    Ok(path)
}
