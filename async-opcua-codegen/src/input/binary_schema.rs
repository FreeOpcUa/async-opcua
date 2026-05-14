use std::path::{Path, PathBuf};

use opcua_xml::{load_bsd_file, schema::opc_binary_schema::TypeDictionary};

use crate::CodeGenError;

/// A binary schema, meaning a schema file on the legacy .bsd format.
///
/// Note that this format is deprecated.
pub struct BinarySchemaInput {
    xml: TypeDictionary,
    namespace: String,
    path: PathBuf,
}

impl BinarySchemaInput {
    pub(super) fn parse(data: &str, path: &Path) -> Result<Self, CodeGenError> {
        let xml = load_bsd_file(data)?;
        Ok(Self {
            namespace: xml.target_namespace.clone(),
            xml,
            path: path.to_owned(),
        })
    }

    pub(super) fn load(root_path: &Path, file_path: &Path) -> Result<Self, CodeGenError> {
        let data = std::fs::read_to_string(root_path.join(file_path)).map_err(|e| {
            CodeGenError::io(&format!("Failed to read file {}", file_path.display()), e)
        })?;
        Self::parse(&data, file_path)
    }

    /// The parsed type dictionary XML.
    pub fn xml(&self) -> &TypeDictionary {
        &self.xml
    }

    /// The namespace this is generated for.
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// The original path the file was found on.
    pub fn path(&self) -> &Path {
        &self.path
    }
}
