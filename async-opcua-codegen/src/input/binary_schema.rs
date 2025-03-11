use opcua_xml::{load_bsd_file, schema::opc_binary_schema::TypeDictionary};

use crate::CodeGenError;

pub struct BinarySchemaInput {
    pub xml: TypeDictionary,
    pub namespace: String,
    pub path: String,
}

impl BinarySchemaInput {
    pub fn parse(data: &str, path: &str) -> Result<Self, CodeGenError> {
        let xml = load_bsd_file(data)?;
        Ok(Self {
            namespace: xml.target_namespace.clone(),
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
