use std::collections::{HashMap, HashSet};

use opcua_xml::{
    load_nodeset2_file,
    schema::{opc_ua_types::Variant, ua_node_set::UANodeSet},
    XmlElement,
};

use crate::CodeGenError;

use super::SchemaCache;

pub struct NodeSetInput {
    pub xml: UANodeSet,
    pub aliases: HashMap<String, String>,
    pub uri: String,
    pub required_model_uris: Vec<String>,
    /// Map from numeric ID to documentation link.
    pub documentation: Option<HashMap<i64, String>>,
    pub referenced_xsd_schemas: HashSet<String>,
    pub path: String,
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
            println!("Warning, multiple models found in nodeset file, this is not supported, and only the first will be used.");
        }

        let Some(model) = models.models.first() else {
            return Err(CodeGenError::other("No model in model table"));
        };

        let required_model_uris = model
            .required_model
            .iter()
            .map(|v| v.model_uri.clone())
            .collect();

        println!(
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

        Ok(Self {
            uri: model.model_uri.clone(),
            xml: nodeset,
            aliases: aliases.unwrap_or_default(),
            required_model_uris,
            documentation,
            referenced_xsd_schemas: xsd_uris,
            path: path.to_owned(),
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
}
