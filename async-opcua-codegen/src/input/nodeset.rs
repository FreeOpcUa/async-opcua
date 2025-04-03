use std::{
    collections::{HashMap, HashSet},
    sync::OnceLock,
};

use opcua_xml::{
    load_nodeset2_file,
    schema::{
        opc_ua_types::Variant,
        ua_node_set::{DataTypeDefinition, UANode, UANodeSet},
    },
    XmlElement,
};
use tracing::{info, warn};

use crate::{
    utils::{split_qualified_name, ParsedNodeId},
    CodeGenError, BASE_NAMESPACE,
};

use super::SchemaCache;

#[derive(Debug, Clone, Default)]
pub struct RawEncodingIds {
    pub xml: Option<ParsedNodeId>,
    pub binary: Option<ParsedNodeId>,
    pub json: Option<ParsedNodeId>,
    pub data_type: Option<ParsedNodeId>,
}

#[derive(Debug, Clone)]
pub struct TypeInfo {
    pub name: String,
    pub is_abstract: bool,
    pub definition: Option<DataTypeDefinition>,
    pub encoding_ids: RawEncodingIds,
}

impl TypeInfo {
    pub fn has_encoding(&self) -> bool {
        self.encoding_ids.binary.is_some()
    }
}

pub struct NodeSetInput {
    pub xml: UANodeSet,
    pub aliases: HashMap<String, String>,
    pub uri: String,
    pub required_model_uris: Vec<String>,
    /// Map from numeric ID to documentation link.
    pub documentation: Option<HashMap<i64, String>>,
    pub referenced_xsd_schemas: HashSet<String>,
    pub path: String,
    pub namespaces: Vec<String>,
    // Index of the model URI in the namespace array.
    pub own_namespace_index: u16,
    // A little weird to store it as a result, but since it can fail it's actually the semantically
    // correct thing. It's a cached computation result.
    pub parent_type_ids: OnceLock<Result<HashMap<ParsedNodeId, ParsedNodeId>, CodeGenError>>,
    pub type_info: OnceLock<Result<HashMap<ParsedNodeId, TypeInfo>, CodeGenError>>,
}

#[derive(Debug, Clone, Copy)]
enum EncodingKind {
    Xml,
    Binary,
    Json,
}

impl NodeSetInput {
    fn find_referenced_xsd_schemas_rec(obj: &XmlElement, map: &mut HashSet<String>) {
        if let Some(attr) = obj.attributes.get("xmlns") {
            map.insert(attr.clone());
        }
        if let Some(attr) = obj.attributes.get("xmlns:uax") {
            map.insert(attr.clone());
        }
        for child in obj.children.values() {
            for child in child {
                Self::find_referenced_xsd_schemas_rec(child, map);
            }
        }
    }

    fn find_referenced_xsd_schemas_variant(variant: &Variant, map: &mut HashSet<String>) {
        match variant {
            opcua_xml::schema::opc_ua_types::Variant::ExtensionObject(obj) => {
                if let Some(body) = obj.body.as_ref().and_then(|b| b.data.as_ref()) {
                    Self::find_referenced_xsd_schemas_rec(body, map);
                }
            }
            opcua_xml::schema::opc_ua_types::Variant::ListOfExtensionObject(objs) => {
                for obj in objs {
                    if let Some(body) = obj.body.as_ref().and_then(|b| b.data.as_ref()) {
                        Self::find_referenced_xsd_schemas_rec(body, map);
                    }
                }
            }
            opcua_xml::schema::opc_ua_types::Variant::Variant(variant) => {
                Self::find_referenced_xsd_schemas_variant(variant, map);
            }
            _ => (),
        }
    }

    fn find_referenced_xsd_schemas(node_set: &UANodeSet) -> HashSet<String> {
        // Recursively look through all values to find which XSD schemas are referenced,
        // since this isn't reported anywhere centrally.
        let mut res = HashSet::new();
        for node in &node_set.nodes {
            let value = match node {
                opcua_xml::schema::ua_node_set::UANode::Variable(v) => v.value.as_ref(),
                opcua_xml::schema::ua_node_set::UANode::VariableType(v) => v.value.as_ref(),
                _ => continue,
            };
            let Some(value) = value else {
                continue;
            };
            Self::find_referenced_xsd_schemas_variant(&value.0, &mut res);
        }
        res
    }

    pub fn resolve_alias<'a>(&'a self, alias: &'a str) -> &'a str {
        self.aliases.get(alias).map(|s| s.as_str()).unwrap_or(alias)
    }

    pub fn parse(data: &str, path: &str, docs: Option<&str>) -> Result<Self, CodeGenError> {
        let nodeset = load_nodeset2_file(data)?;

        let Some(nodeset) = nodeset.node_set else {
            return Err(CodeGenError::missing_required_value("NodeSet"));
        };
        let aliases = nodeset.aliases.as_ref().map(|a| {
            a.aliases
                .iter()
                .map(|a| (a.alias.clone(), a.id.0.clone()))
                .collect::<HashMap<_, _>>()
        });
        let Some(models) = nodeset.models.as_ref() else {
            return Err(CodeGenError::missing_required_value("Models"));
        };

        if models.models.len() > 1 {
            warn!("Multiple models found in nodeset file, this is not supported, and only the first will be used.");
        }

        let Some(model) = models.models.first() else {
            return Err(CodeGenError::other("No model in model table"));
        };

        let required_model_uris = model
            .required_model
            .iter()
            .map(|v| v.model_uri.clone())
            .collect();

        info!(
            "Loaded nodeset {} with {} nodes",
            model.model_uri,
            nodeset.nodes.len(),
        );

        let documentation = if let Some(docs) = docs {
            let mut res = HashMap::new();
            for line in docs.lines() {
                let vals: Vec<_> = line.split(',').collect();
                if vals.len() >= 3 {
                    res.insert(vals[0].parse()?, vals[2].to_owned());
                } else {
                    return Err(CodeGenError::other(format!(
                        "CSV file is on incorrect format. Expected at least three columns, got {}",
                        vals.len()
                    )));
                }
            }
            Some(res)
        } else {
            None
        };

        let xsd_uris = Self::find_referenced_xsd_schemas(&nodeset);

        let mut namespaces = Vec::new();
        let mut own_namespace_index = 0;
        // Whether they define it or not, all nodesets depend on the base namespace.
        namespaces.push(BASE_NAMESPACE.to_owned());
        for namespace in nodeset.namespace_uris.iter().flat_map(|n| n.uris.iter()) {
            if namespace != BASE_NAMESPACE {
                if namespace == &model.model_uri {
                    own_namespace_index = namespaces.len() as u16;
                }
                namespaces.push(namespace.clone());
            }
        }

        Ok(Self {
            uri: model.model_uri.clone(),
            xml: nodeset,
            aliases: aliases.unwrap_or_default(),
            required_model_uris,
            documentation,
            referenced_xsd_schemas: xsd_uris,
            path: path.to_owned(),
            parent_type_ids: OnceLock::new(),
            namespaces,
            own_namespace_index,
            type_info: OnceLock::new(),
        })
    }

    pub fn load(
        root_path: &str,
        file_path: &str,
        docs_path: Option<&str>,
    ) -> Result<Self, CodeGenError> {
        let data = std::fs::read_to_string(format!("{}/{}", root_path, file_path))
            .map_err(|e| CodeGenError::io(&format!("Failed to read file {}", file_path), e))?;
        let docs = docs_path
            .map(|p| {
                std::fs::read_to_string(format!("{}/{}", root_path, p))
                    .map_err(|e| CodeGenError::io(&format!("Failed to read file {}", p), e))
            })
            .transpose()?;
        Self::parse(&data, file_path, docs.as_deref()).map_err(|e| e.in_file(file_path))
    }

    pub fn validate(&self, cache: &SchemaCache) -> Result<(), CodeGenError> {
        for uri in &self.required_model_uris {
            cache.get_nodeset(uri)?;
        }
        for uri in &self.referenced_xsd_schemas {
            cache.get_xml_schema(uri)?;
        }

        Ok(())
    }

    pub fn get_parent_type_ids(
        &self,
    ) -> Result<&HashMap<ParsedNodeId, ParsedNodeId>, CodeGenError> {
        self.parent_type_ids
            .get_or_init(|| {
                let mut res = HashMap::new();
                for node in &self.xml.nodes {
                    let UANode::DataType(d) = node else {
                        continue;
                    };

                    let id = ParsedNodeId::parse(self.resolve_alias(&d.base.base.node_id.0))?;

                    let subtype_refs = d
                        .base
                        .base
                        .references
                        .iter()
                        .flat_map(|r| r.references.iter())
                        .filter(|r| self.resolve_alias(&r.reference_type.0) == "i=45");

                    for r in subtype_refs {
                        if r.is_forward {
                            res.insert(
                                ParsedNodeId::parse(self.resolve_alias(&r.node_id.0))?,
                                id.clone(),
                            );
                        } else {
                            res.insert(
                                id.clone(),
                                ParsedNodeId::parse(self.resolve_alias(&r.node_id.0))?,
                            );
                        }
                    }
                }
                Ok(res)
            })
            .as_ref()
            .map_err(|e| e.clone())
    }

    pub fn get_type_names(&self) -> Result<&HashMap<ParsedNodeId, TypeInfo>, CodeGenError> {
        self.type_info
            .get_or_init(|| {
                let mut res = HashMap::new();
                let mut encoding_ids: HashMap<ParsedNodeId, RawEncodingIds> = HashMap::new();
                let mut known_encoding_nodes: HashMap<ParsedNodeId, EncodingKind> = HashMap::new();

                // First iterate through objects to find all encoding nodes.
                for object in self.xml.nodes.iter().filter_map(|n| match n {
                    UANode::Object(o) => Some(o),
                    _ => None,
                }) {
                    let (name, _) = split_qualified_name(&object.base.base.browse_name.0)?;
                    let kind = match name {
                        "Default Binary" => EncodingKind::Binary,
                        "Default JSON" => EncodingKind::Json,
                        "Default XML" => EncodingKind::Xml,
                        _ => continue,
                    };
                    let encodes = object
                        .base
                        .base
                        .references
                        .iter()
                        .flat_map(|r| r.references.iter())
                        .find(|r| {
                            !r.is_forward && self.resolve_alias(&r.reference_type.0) == "i=38"
                        });
                    let id = ParsedNodeId::parse(self.resolve_alias(&object.base.base.node_id.0))?;
                    known_encoding_nodes.insert(id.clone(), kind);
                    let Some(encodes) = encodes else {
                        warn!("{id:?} is missing an inverse encoding ref");
                        continue;
                    };

                    let encoded_id = ParsedNodeId::parse(self.resolve_alias(&encodes.node_id.0))?;
                    let entry = encoding_ids.entry(encoded_id).or_default();
                    match kind {
                        EncodingKind::Binary => entry.binary = Some(id),
                        EncodingKind::Json => entry.json = Some(id),
                        EncodingKind::Xml => entry.xml = Some(id),
                    }
                }

                // Next, iterate through data types to build type info.
                for data_type in self.xml.nodes.iter().filter_map(|n| match n {
                    UANode::DataType(o) => Some(o),
                    _ => None,
                }) {
                    let id =
                        ParsedNodeId::parse(self.resolve_alias(&data_type.base.base.node_id.0))?;

                    // Check if there are any forward encoding IDs. The inverse is most common, but some
                    // schemas use these.
                    for encoding in data_type
                        .base
                        .base
                        .references
                        .iter()
                        .flat_map(|r| r.references.iter())
                        .filter(|r| {
                            r.is_forward && self.resolve_alias(&r.reference_type.0) == "i=38"
                        })
                    {
                        let encoded_id =
                            ParsedNodeId::parse(self.resolve_alias(&encoding.node_id.0))?;
                        let Some(kind) = known_encoding_nodes.get(&encoded_id) else {
                            warn!("Unknown encoding node referenced {:?}", encoded_id);
                            continue;
                        };
                        let entry = encoding_ids.entry(id.clone()).or_default();
                        match kind {
                            EncodingKind::Binary => entry.binary = Some(encoded_id),
                            EncodingKind::Json => entry.json = Some(encoded_id),
                            EncodingKind::Xml => entry.xml = Some(encoded_id),
                        }
                    }

                    let name = data_type
                        .base
                        .base
                        .symbolic_name
                        .as_ref()
                        .and_then(|n| n.names.first())
                        .cloned()
                        .unwrap_or(
                            split_qualified_name(&data_type.base.base.browse_name.0)?
                                .0
                                .to_owned(),
                        );
                    let mut encoding_ids = encoding_ids.remove(&id).unwrap_or_default();
                    encoding_ids.data_type = Some(id.clone());
                    res.insert(
                        id,
                        TypeInfo {
                            name,
                            is_abstract: data_type.base.is_abstract,
                            definition: data_type.definition.clone(),
                            encoding_ids,
                        },
                    );
                }

                Ok(res)
            })
            .as_ref()
            .map_err(|e| e.clone())
    }
}
