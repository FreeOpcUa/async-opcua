use serde::{Deserialize, Serialize};

use crate::{input::SchemaCache, CodeGenError};

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type")]
pub enum ExplicitCodeGenSource {
    #[serde(rename = "xml-schema")]
    /// XML schema file (XSD)
    Xml { path: String },
    #[serde(rename = "binary-schema")]
    /// Binary schema file (BSD). Note that this is deprecated.
    Binary { path: String },
    #[serde(rename = "node-set")]
    /// NodeSet2.xml files.
    NodeSet {
        path: String,
        documentation: Option<String>,
    },
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
/// Utility type for easily specifying code generation sources.
/// If the source is a string, we infer which type of source it is based on the file extension.
/// Directories are loaded recursively, xsd files are loaded as XML schemas,
/// xml files as NodeSets, and bsd files as binary schemas.
pub enum CodeGenSource {
    Implicit(String),
    Explicit(ExplicitCodeGenSource),
}

/// Try to load all referenced schemas from the specified sources,
/// returning the loaded schemas in a SchemaCache.
///
/// Finally, validate the schemas to ensure that all references are valid.
pub fn load_schemas(
    root_path: &str,
    sources: &[CodeGenSource],
) -> Result<SchemaCache, CodeGenError> {
    let mut cache = SchemaCache::new(root_path);
    for source in sources {
        match source {
            CodeGenSource::Implicit(path) => {
                cache.auto_load_schemas(path)?;
            }
            CodeGenSource::Explicit(explicit) => match explicit {
                ExplicitCodeGenSource::Xml { path } => {
                    cache.load_xml_schema(path)?;
                }
                ExplicitCodeGenSource::Binary { path } => {
                    cache.load_binary_schema(path)?;
                }
                ExplicitCodeGenSource::NodeSet {
                    path,
                    documentation,
                } => {
                    cache.load_nodeset(path, documentation.as_deref())?;
                }
            },
        }
    }
    cache.validate()?;

    Ok(cache)
}
