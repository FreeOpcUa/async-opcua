use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

pub fn base_ignored_types() -> HashSet<String> {
    [
        "ExtensionObject",
        "DataValue",
        "LocalizedText",
        "QualifiedName",
        "DiagnosticInfo",
        "Variant",
        "ExpandedNodeId",
        "NodeId",
        "ByteStringNodeId",
        "GuidNodeId",
        "StringNodeId",
        "NumericNodeId",
        "FourByteNodeId",
        "TwoByteNodeId",
        "XmlElement",
        "Union",
        "RequestHeader",
        "ResponseHeader",
        "Node",
        "InstanceNode",
        "TypeNode",
        "ObjectNode",
        "ObjectTypeNode",
        "VariableNode",
        "VariableTypeNode",
        "ReferenceTypeNode",
        "MethodNode",
        "ViewNode",
        "DataTypeNode",
        "ReferenceNode",
        "Enumeration",
    ]
    .into_iter()
    .map(|v| v.to_owned())
    .collect()
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ExternalIds {
    pub binary: Option<String>,
    pub xml: Option<String>,
    pub json: Option<String>,
    pub id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ExternalType {
    /// Relative path in the OPC-UA types library.
    pub path: String,
    /// Whether this type has a default implementation.
    pub has_default: Option<bool>,
    /// Base type, if any
    pub base_type: Option<String>,
    /// Add to type loader impl
    #[serde(default)]
    pub add_to_type_loader: bool,
    pub ids: Option<ExternalIds>,
}

impl ExternalType {
    pub fn new(path: &str, has_default: bool) -> Self {
        Self {
            path: path.to_owned(),
            has_default: Some(has_default),
            base_type: None,
            add_to_type_loader: false,
            ids: None,
        }
    }
}

pub fn basic_types_import_map() -> HashMap<String, ExternalType> {
    [
        ("UAString", ExternalType::new("string", true)),
        ("ByteString", ExternalType::new("byte_string", true)),
        ("XmlElement", ExternalType::new("string", true)),
        ("Variant", ExternalType::new("variant", true)),
        ("Guid", ExternalType::new("guid", true)),
        ("LocalizedText", ExternalType::new("localized_text", true)),
        ("QualifiedName", ExternalType::new("qualified_name", true)),
        ("DiagnosticInfo", ExternalType::new("diagnostic_info", true)),
        (
            "ExtensionObject",
            ExternalType::new("extension_object", true),
        ),
        ("Duration", ExternalType::new("data_types", true)),
        ("UtcTime", ExternalType::new("data_types", true)),
        ("RequestHeader", ExternalType::new("request_header", true)),
        ("ResponseHeader", ExternalType::new("response_header", true)),
        (
            "ExpandedNodeId",
            ExternalType::new("expanded_node_id", true),
        ),
        ("NodeId", ExternalType::new("node_id", true)),
        ("DataValue", ExternalType::new("data_value", true)),
        ("DateTime", ExternalType::new("date_time", true)),
        ("StatusCode", ExternalType::new("status_code", true)),
    ]
    .into_iter()
    .map(|(k, mut v)| {
        v.path = format!("opcua::types::{}", v.path);
        (k.to_owned(), v)
    })
    .collect()
}

pub fn base_native_type_mappings() -> HashMap<String, String> {
    [
        ("String", "UAString"),
        ("CharArray", "UAString"),
        ("Structure", "ExtensionObject"),
        ("BaseDataType", "Variant"),
        ("Boolean", "bool"),
        ("SByte", "i8"),
        ("Byte", "u8"),
        ("Int16", "i16"),
        ("UInt16", "u16"),
        ("Int32", "i32"),
        ("UInt32", "u32"),
        ("Int64", "i64"),
        ("UInt64", "u64"),
        ("Float", "f32"),
        ("Double", "f64"),
        ("Enumeration", "i32"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_owned(), v.to_owned()))
    .collect()
}
