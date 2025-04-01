mod binary_schema;
mod nodeset;
mod types;

pub use binary_schema::BsdTypeLoader;
pub use nodeset::NodeSetTypeLoader;
pub use types::{EnumReprType, EnumType, FieldType, StructureFieldType, StructuredType};

#[derive(Debug)]
pub struct LoadedTypes {
    pub structures: Vec<StructuredType>,
    pub enums: Vec<EnumType>,
}

#[derive(Debug)]
pub enum LoadedType {
    Struct(StructuredType),
    Enum(EnumType),
}

impl LoadedType {
    pub fn name(&self) -> &str {
        match self {
            LoadedType::Struct(s) => &s.name,
            LoadedType::Enum(s) => &s.name,
        }
    }
}
