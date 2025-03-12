#[derive(serde::Serialize, Debug)]
pub enum StructureFieldType {
    Field(FieldType),
    Array(FieldType),
}

#[derive(serde::Serialize, Debug)]
pub struct StructureField {
    pub name: String,
    pub original_name: String,
    pub typ: StructureFieldType,
}

#[derive(serde::Serialize, Debug, Clone)]
pub enum FieldType {
    Abstract(String),
    ExtensionObject,
    Normal(String),
}

impl FieldType {
    pub fn as_type_str(&self) -> &str {
        match self {
            FieldType::Abstract(_) | FieldType::ExtensionObject => "ExtensionObject",
            FieldType::Normal(s) => s,
        }
    }
}

#[derive(serde::Serialize, Debug)]
pub struct StructuredType {
    pub name: String,
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
