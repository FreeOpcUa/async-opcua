use std::collections::{HashMap, HashSet};

use opcua_xml::schema::opc_binary_schema::{EnumeratedType, TypeDictionary};

use crate::{error::CodeGenError, utils::to_snake_case};

use super::{
    types::{
        EnumReprType, EnumType, EnumValue, FieldType, StructureField, StructureFieldType,
        StructuredType,
    },
    LoadedType,
};

pub struct BsdTypeLoader<'a> {
    ignored: HashSet<String>,
    native_type_mappings: HashMap<String, String>,
    xml: &'a TypeDictionary,
}

fn strip_first_segment<'a>(val: &'a str, sep: &'static str) -> Result<&'a str, CodeGenError> {
    val.split_once(sep)
        .ok_or_else(|| CodeGenError::wrong_format(format!("A{sep}B.."), val))
        .map(|v| v.1)
}

impl<'a> BsdTypeLoader<'a> {
    pub fn new(
        ignored: HashSet<String>,
        native_type_mappings: HashMap<String, String>,
        data: &'a TypeDictionary,
    ) -> Result<Self, CodeGenError> {
        Ok(Self {
            ignored,
            native_type_mappings,
            xml: data,
        })
    }

    fn massage_type_name(&self, name: &str) -> String {
        self.native_type_mappings
            .get(name)
            .cloned()
            .unwrap_or_else(|| name.to_owned())
    }

    fn get_field_type(field: &str) -> FieldType {
        match field {
            "ExtensionObject" | "OptionSet" => FieldType::ExtensionObject(None),
            _ => FieldType::Normal(field.to_owned()),
        }
    }

    fn load_structure(
        &self,
        item: &opcua_xml::schema::opc_binary_schema::StructuredType,
    ) -> Result<StructuredType, CodeGenError> {
        let mut fields_to_add = Vec::new();
        let mut fields_to_hide = Vec::new();

        for field in &item.fields {
            let field_name = to_snake_case(&field.name);
            let typ = field
                .type_name
                .as_ref()
                .ok_or(CodeGenError::missing_required_value("TypeName"))
                .and_then(|r| Ok(self.massage_type_name(strip_first_segment(r, ":")?)))
                .map_err(|e| {
                    e.with_context(format!(
                        "while loading field {} in struct {}",
                        field_name, item.description.name
                    ))
                })?;

            if let Some(length_field) = &field.length_field {
                fields_to_add.push(StructureField {
                    name: field_name,
                    original_name: field.name.clone(),
                    typ: StructureFieldType::Array(Self::get_field_type(&typ)),
                    documentation: field
                        .documentation
                        .as_ref()
                        .and_then(|d| d.contents.clone()),
                });
                fields_to_hide.push(to_snake_case(length_field))
            } else {
                fields_to_add.push(StructureField {
                    name: field_name,
                    original_name: field.name.clone(),
                    typ: StructureFieldType::Field(Self::get_field_type(&typ)),
                    documentation: field
                        .documentation
                        .as_ref()
                        .and_then(|d| d.contents.clone()),
                });
            }
        }

        Ok(StructuredType {
            name: item.description.name.clone(),
            fields: fields_to_add,
            hidden_fields: fields_to_hide,
            id: None,
            documentation: item
                .description
                .documentation
                .as_ref()
                .and_then(|d| d.contents.clone()),
            base_type: match item.base_type.as_deref() {
                Some("ua:ExtensionObject" | "ua:OptionSet") => {
                    Some(FieldType::ExtensionObject(None))
                }
                Some(base) => Some(FieldType::Normal(self.massage_type_name(base))),
                None => None,
            },
            is_union: false,
        })
    }

    fn load_enum(&self, item: &EnumeratedType) -> Result<EnumType, CodeGenError> {
        let Some(len) = item.opaque.length_in_bits else {
            return Err(
                CodeGenError::missing_required_value("LengthInBits").with_context(format!(
                    "while loading enum {}",
                    item.opaque.description.name
                )),
            );
        };

        let len_bytes = ((len as f64) / 8.0).ceil() as u64;
        let ty = match len_bytes {
            1 => EnumReprType::u8,
            2 => EnumReprType::i16,
            4 => EnumReprType::i32,
            8 => EnumReprType::i64,
            r => {
                return Err(CodeGenError::other(format!(
                    "Unexpected enum length. {r} bytes for {}",
                    item.opaque.description.name
                ))
                .with_context(format!(
                    "while loading enum {}",
                    item.opaque.description.name
                )))
            }
        };
        let mut variants = Vec::new();
        for val in &item.variants {
            let Some(value) = val.value else {
                return Err(
                    CodeGenError::missing_required_value("Value").with_context(format!(
                        "while loading enum {}",
                        item.opaque.description.name
                    )),
                );
            };
            let Some(name) = &val.name else {
                return Err(
                    CodeGenError::missing_required_value("Name").with_context(format!(
                        "while loading enum {}",
                        item.opaque.description.name
                    )),
                );
            };

            variants.push(EnumValue {
                name: name.clone(),
                value,
                documentation: val.documentation.as_ref().and_then(|d| d.contents.clone()),
            });
        }

        Ok(EnumType {
            name: item.opaque.description.name.clone(),
            values: variants,
            documentation: item
                .opaque
                .description
                .documentation
                .as_ref()
                .and_then(|d| d.contents.clone()),
            option: item.is_option_set,
            typ: ty,
            size: len_bytes,
            default_value: None,
        })
    }

    pub fn target_namespace(&self) -> String {
        self.xml.target_namespace.clone()
    }

    pub fn from_bsd(self) -> Result<Vec<LoadedType>, CodeGenError> {
        let mut types = Vec::new();
        for node in &self.xml.elements {
            match node {
                // Ignore opaque types for now, should these be mapped to structs with raw binary data?
                opcua_xml::schema::opc_binary_schema::TypeDictionaryItem::Opaque(_) => continue,
                opcua_xml::schema::opc_binary_schema::TypeDictionaryItem::Enumerated(e) => {
                    if self.ignored.contains(&e.opaque.description.name) {
                        continue;
                    }
                    types.push(LoadedType::Enum(self.load_enum(e)?));
                }
                opcua_xml::schema::opc_binary_schema::TypeDictionaryItem::Structured(s) => {
                    if self.ignored.contains(&s.description.name) {
                        continue;
                    }
                    types.push(LoadedType::Struct(self.load_structure(s)?));
                }
            }
        }

        Ok(types)
    }
}
