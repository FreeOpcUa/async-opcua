use opcua_xml::{load_xsd_schema, schema::xml_schema::XmlSchema};

use crate::CodeGenError;

pub struct XmlSchemaInput {
    pub xml: XmlSchema,
    pub namespace: String,
    pub path: String,
}

impl XmlSchemaInput {
    pub fn parse(data: &str, path: &str) -> Result<Self, CodeGenError> {
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

    pub fn load(root_path: &str, file_path: &str) -> Result<Self, CodeGenError> {
        let data = std::fs::read_to_string(format!("{}/{}", root_path, file_path))
            .map_err(|e| CodeGenError::io(&format!("Failed to read file {}", file_path), e))?;
        Self::parse(&data, file_path)
    }
}
