//! Integration tests for NodeSet import helpers and diagnostics.

use opcua_xml::dependency_sort::sort_nodesets;
use opcua_xml::diagnostics::generate_diagnostics;
use opcua_xml::schema::opc_ua_types::Variant;
use opcua_xml::schema::ua_node_set::{load_nodeset2_file, NodeSet2, UANode};
use opcua_xml::OpcUaXmlParser;

fn nodeset_with_model(model_uri: &str, required_model_uri: Option<&str>) -> String {
    let required_model = required_model_uri
        .map(|uri| format!(r#"<RequiredModel ModelUri="{uri}" />"#))
        .unwrap_or_default();

    format!(
        r#"<UANodeSet>
    <NamespaceUris>
        <Uri>{model_uri}</Uri>
    </NamespaceUris>
    <Models>
        <Model ModelUri="{model_uri}">
            {required_model}
        </Model>
    </Models>
    <UAObject NodeId="ns=1;i=1" BrowseName="1:Root" />
</UANodeSet>"#
    )
}

fn first_model_uri(nodeset: &NodeSet2) -> &str {
    &nodeset
        .node_set
        .as_ref()
        .expect("UANodeSet")
        .models
        .as_ref()
        .expect("Models")
        .models[0]
        .model_uri
}

#[test]
fn sort_nodesets_orders_models_before_dependents() {
    let autoid = load_nodeset2_file(&nodeset_with_model("urn:autoid", Some("urn:di"))).unwrap();
    let base = load_nodeset2_file(&nodeset_with_model("urn:base", None)).unwrap();
    let di = load_nodeset2_file(&nodeset_with_model("urn:di", Some("urn:base"))).unwrap();

    let sorted = sort_nodesets(vec![autoid, di, base]).unwrap();
    let model_uris = sorted.iter().map(first_model_uri).collect::<Vec<_>>();

    assert_eq!(model_uris, ["urn:base", "urn:di", "urn:autoid"]);
}

#[test]
fn diagnostics_report_unresolved_reference_targets() {
    let base = r#"<UANodeSet>
    <NamespaceUris>
        <Uri>urn:base</Uri>
    </NamespaceUris>
    <Models>
        <Model ModelUri="urn:base" />
    </Models>
    <UAObject NodeId="ns=1;i=100" BrowseName="1:Target" />
</UANodeSet>"#;
    let dependent = r#"<UANodeSet>
    <NamespaceUris>
        <Uri>urn:base</Uri>
        <Uri>urn:dependent</Uri>
    </NamespaceUris>
    <Models>
        <Model ModelUri="urn:dependent">
            <RequiredModel ModelUri="urn:base" />
        </Model>
    </Models>
    <UAObject NodeId="ns=2;i=200" BrowseName="2:Source">
        <References>
            <Reference ReferenceType="i=35">ns=1;i=100</Reference>
            <Reference ReferenceType="i=35">ns=1;i=999</Reference>
        </References>
    </UAObject>
</UANodeSet>"#;
    let collection = OpcUaXmlParser::parse_nodesets([base, dependent]).unwrap();

    let report = generate_diagnostics(&collection);

    assert_eq!(report.unresolved_references.len(), 1);
    let unresolved = &report.unresolved_references[0];
    assert_eq!(unresolved.source_node_set_index, 1);
    assert_eq!(unresolved.source_node_id, "ns=2;i=200");
    assert_eq!(unresolved.target_node_id, "ns=1;i=999");
    assert_eq!(unresolved.reference_type, "i=35");
    assert!(unresolved.is_forward);
}

#[test]
fn custom_value_tags_are_loaded_as_xml_elements() {
    let xml = r#"<UANodeSet>
    <NamespaceUris>
        <Uri>urn:autoid</Uri>
    </NamespaceUris>
    <Models>
        <Model ModelUri="urn:autoid" />
    </Models>
    <UAVariable NodeId="ns=1;i=1" BrowseName="1:Custom" DataType="ns=1;i=2">
        <Value>
            <AutoId:CustomValue xmlns:AutoId="urn:autoid" Foo="bar">
                <AutoId:Nested>123</AutoId:Nested>
            </AutoId:CustomValue>
        </Value>
    </UAVariable>
</UANodeSet>"#;

    let nodeset = OpcUaXmlParser::parse_nodeset(xml).unwrap();
    let variable = match &nodeset.node_set.as_ref().unwrap().nodes[0] {
        UANode::Variable(variable) => variable,
        other => panic!("expected variable, got {other:?}"),
    };

    match &variable.value.as_ref().unwrap().0 {
        Variant::XmlElement(elements) => {
            assert_eq!(elements.len(), 1);
            assert_eq!(elements[0].tag, "CustomValue");
            assert_eq!(
                elements[0].attributes.get("Foo").map(String::as_str),
                Some("bar")
            );
            assert_eq!(elements[0].child_content("Nested"), Some("123"));
        }
        other => panic!("expected XmlElement variant, got {other:?}"),
    }
}
