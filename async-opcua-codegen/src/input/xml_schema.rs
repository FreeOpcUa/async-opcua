use std::path::{Path, PathBuf};

use opcua_xml::{load_xsd_schema, schema::xml_schema::XmlSchema};

use crate::CodeGenError;

/// Parsed XML schema (.xsd) file input.
pub struct XmlSchemaInput {
    xml: XmlSchema,
    namespace: String,
    path: PathBuf,
}

impl XmlSchemaInput {
    /// The parsed XML file.
    pub fn xml(&self) -> &XmlSchema {
        &self.xml
    }

    /// The namespace this XSD file targets.
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// Relative path to the file this was loaded from.
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub(super) fn parse(data: &str, path: &Path) -> Result<Self, CodeGenError> {
        let xml = load_xsd_schema(data)?;
        Ok(Self {
            namespace: xml
                .target_namespace
                .clone()
                .ok_or_else(|| CodeGenError::missing_required_value("targetNamespace"))?,
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
}
