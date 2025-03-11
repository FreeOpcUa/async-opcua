use serde::{Deserialize, Serialize};

use crate::{input::SchemaCache, CodeGenError};

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type")]
pub enum ExplicitCodeGenSource {
    #[serde(rename = "xml-schema")]
    Xml { path: String },
    #[serde(rename = "binary-schema")]
    Binary { path: String },
    #[serde(rename = "node-set")]
    NodeSet {
        path: String,
        documentation: Option<String>,
    },
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
pub enum CodeGenSource {
    Implicit(String),
    Explicit(ExplicitCodeGenSource),
}

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
