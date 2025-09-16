//! Loaders for different type definition formats.
//! Currently we support NodeSet2 XML files and legacy Binary Schema (BSD) files.
//! The loaders convert the types into a common format that can then be used
//! for code generation.

mod binary_schema;
mod nodeset;
mod types;

pub use binary_schema::BsdTypeLoader;
pub use nodeset::NodeSetTypeLoader;
pub use types::{EnumReprType, EnumType, FieldType, StructureFieldType, StructuredType};

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
