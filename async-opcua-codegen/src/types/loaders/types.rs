use syn::{parse_quote, Lit};

use crate::{input::RawEncodingIds, utils::ParsedNodeId, CodeGenError};

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
    Abstract(#[allow(unused)] String),
    ExtensionObject(Option<RawEncodingIds>),
    Normal {
        name: String,
        namespace: Option<String>,
    },
}

impl FieldType {
    pub fn as_type_str(&self) -> &str {
        match self {
            FieldType::Abstract(_) | FieldType::ExtensionObject(_) => "ExtensionObject",
            FieldType::Normal { name, .. } => name,
        }
    }

    pub fn namespace(&self) -> Option<&str> {
        match self {
            FieldType::Normal { namespace, .. } => namespace.as_deref(),
            _ => None,
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
    i8,
    u8,
    u16,
    i16,
    u32,
    i32,
    u64,
    i64,
}

impl std::fmt::Display for EnumReprType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EnumReprType::i8 => write!(f, "i8"),
            EnumReprType::u8 => write!(f, "u8"),
            EnumReprType::u16 => write!(f, "u16"),
            EnumReprType::i16 => write!(f, "i16"),
            EnumReprType::u32 => write!(f, "u32"),
            EnumReprType::i32 => write!(f, "i32"),
            EnumReprType::u64 => write!(f, "u64"),
            EnumReprType::i64 => write!(f, "i64"),
        }
    }
}

impl EnumReprType {
    pub fn render(&self, value: i64) -> Result<Lit, CodeGenError> {
        Ok(match self {
            EnumReprType::u8 => {
                let value: u8 = value.try_into().map_err(|_| {
                    CodeGenError::other(format!(
                        "Unexpected error converting to u8, {value} is out of range"
                    ))
                })?;
                parse_quote! { #value }
            }
            EnumReprType::i8 => {
                let value: i8 = value.try_into().map_err(|_| {
                    CodeGenError::other(format!(
                        "Unexpected error converting to i8, {value} is out of range"
                    ))
                })?;
                parse_quote! { #value }
            }
            EnumReprType::u16 => {
                let value: u16 = value.try_into().map_err(|_| {
                    CodeGenError::other(format!(
                        "Unexpected error converting to u16, {value} is out of range"
                    ))
                })?;
                parse_quote! { #value }
            }
            EnumReprType::i16 => {
                let value: i16 = value.try_into().map_err(|_| {
                    CodeGenError::other(format!(
                        "Unexpected error converting to i16, {value} is out of range"
                    ))
                })?;
                parse_quote! { #value }
            }
            EnumReprType::u32 => {
                let value: u32 = value.try_into().map_err(|_| {
                    CodeGenError::other(format!(
                        "Unexpected error converting to u32, {value} is out of range"
                    ))
                })?;
                parse_quote! { #value }
            }
            EnumReprType::i32 => {
                let value: i32 = value.try_into().map_err(|_| {
                    CodeGenError::other(format!(
                        "Unexpected error converting to i32, {value} is out of range"
                    ))
                })?;
                parse_quote! { #value }
            }
            EnumReprType::u64 => {
                let value: u64 = value.try_into().map_err(|_| {
                    CodeGenError::other(format!(
                        "Unexpected error converting to u64, {value} is out of range"
                    ))
                })?;
                parse_quote! { #value }
            }
            EnumReprType::i64 => {
                parse_quote! { #value }
            }
        })
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
