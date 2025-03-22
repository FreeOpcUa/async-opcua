use crate::{input::RawEncodingIds, utils::ParsedNodeId};

#[derive(Debug)]
pub enum StructureFieldType {
    Field(FieldType),
    Array(FieldType),
}

#[derive(Debug)]
pub struct StructureField {
    pub name: String,
    pub original_name: String,
    pub typ: StructureFieldType,
    pub documentation: Option<String>,
}

#[derive(Debug, Clone)]
pub enum FieldType {
    Abstract(String),
    ExtensionObject(Option<RawEncodingIds>),
    Normal(String),
}

impl FieldType {
    pub fn as_type_str(&self) -> &str {
        match self {
            FieldType::Abstract(_) | FieldType::ExtensionObject(_) => "ExtensionObject",
            FieldType::Normal(s) => s,
        }
    }
}

#[derive(Debug)]
pub struct StructuredType {
    pub name: String,
    pub id: Option<ParsedNodeId>,
    pub fields: Vec<StructureField>,
    pub hidden_fields: Vec<String>,
    pub documentation: Option<String>,
    pub base_type: Option<FieldType>,
    pub is_union: bool,
}

impl StructuredType {
    pub fn visible_fields(&self) -> impl Iterator<Item = &StructureField> {
        self.fields
            .iter()
            .filter(|f| !self.hidden_fields.contains(&f.name))
    }
}
