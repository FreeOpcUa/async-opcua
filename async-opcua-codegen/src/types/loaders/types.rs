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

#[derive(serde::Serialize, Debug)]
pub struct EnumValue {
    pub name: String,
    pub value: i64,
    pub documentation: Option<String>,
}

#[derive(serde::Serialize, Debug)]
#[allow(non_camel_case_types)]
pub enum EnumReprType {
    u8,
    i16,
    i32,
    i64,
}

impl std::fmt::Display for EnumReprType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EnumReprType::u8 => write!(f, "u8"),
            EnumReprType::i16 => write!(f, "i16"),
            EnumReprType::i32 => write!(f, "i32"),
            EnumReprType::i64 => write!(f, "i64"),
        }
    }
}

#[derive(serde::Serialize, Debug)]
pub struct EnumType {
    pub name: String,
    pub values: Vec<EnumValue>,
    pub documentation: Option<String>,
    pub typ: EnumReprType,
    pub size: u64,
    pub option: bool,
    pub default_value: Option<String>,
}
