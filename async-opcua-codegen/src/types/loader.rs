use std::collections::{HashMap, HashSet};

use convert_case::{Case, Casing};
use opcua_xml::schema::opc_binary_schema::{EnumeratedType, TypeDictionary};

use crate::{error::CodeGenError, StructureField, StructureFieldType, StructuredType};

use super::{enum_type::EnumReprType, structure::FieldType, EnumType, EnumValue};

pub fn to_snake_case(v: &str) -> String {
    v.to_case(Case::Snake)
}

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

#[derive(serde::Serialize, Debug)]
pub struct LoadedTypes {
    pub structures: Vec<StructuredType>,
    pub enums: Vec<EnumType>,
}

#[derive(serde::Serialize)]
#[serde(untagged)]
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
            "ExtensionObject" | "OptionSet" => FieldType::ExtensionObject,
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
            documentation: item
                .description
                .documentation
                .as_ref()
                .and_then(|d| d.contents.clone()),
            base_type: match item.base_type.as_deref() {
                Some("ua:ExtensionObject" | "ua:OptionSet") => Some(FieldType::ExtensionObject),
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

    /* pub fn from_nodeset(&self) -> Result<Vec<LoadedType>, CodeGenError> {
        let mut types = Vec::new();

        let mut type_names: HashMap<_, _> = [
            ("i=1", "bool"),
            ("i=2", "i8"),
            ("i=3", "u8"),
            ("i=4", "i16"),
            ("i=5", "u16"),
            ("i=6", "i32"),
            ("i=7", "u32"),
            ("i=8", "i64"),
            ("i=9", "u64"),
            ("i=10", "f32"),
            ("i=11", "f64"),
            ("i=12", "String"),
            ("i=13", "time.Time"),
            ("i=14", "*GUID"),
            ("i=15", "[u8]"),
            ("i=16", "XMLElement"),
            ("i=17", "NodeID"),
            ("i=18", "ExpandedNodeID"),
            ("i=19", "StatusCode"),
            ("i=20", "QualifiedName"),
            ("i=21", "LocalizedText"),
            ("i=22", "ExtensionObject"),
            ("i=23", "DataValue"),
            ("i=24", "Variant"),
            ("i=25", "DiagnosticInfo"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();

        // Load type names first
        let node_set = self.xml.root().first_child_with_name("UANodeSet")?;
        for data_type in node_set.with_name("UADataType") {
            type_names.insert(
                data_type.try_attribute("NodeId")?.to_owned(),
                data_type.try_child_contents("DisplayName")?.to_owned(),
            );
        }

        for data_type in node_set.with_name("UADataType") {
            let name = data_type.try_child_contents("DisplayName")?;
            if self.ignored.contains(name) {
                continue;
            }

            let Ok(definition) = data_type.first_child_with_name("Definition") else {
                continue;
            };

            let fields: Vec<_> = definition.with_name("Field").collect();
            let is_enum = fields.iter().any(|f| f.attribute("Value").is_some());

            if is_enum {
                let mut enum_fields = Vec::new();
                for field in fields {
                    let value = field.try_attribute("Value")?;
                    let value = value
                        .parse()
                        .map_err(|e| CodeGenError::ParseInt(value.to_owned(), e))?;
                    enum_fields.push(EnumValue {
                        name: field.try_attribute("Name")?.to_owned(),
                        value,
                    })
                }

                types.push(LoadedType::Enum(EnumType {
                    name: name.to_owned(),
                    values: enum_fields,
                    documentation: data_type
                        .child_contents("Documentation")
                        .map(|v| v.to_owned()),
                    typ: EnumReprType::i32,
                    size: 4,
                    option: definition.child_contents("IsOptionSet") == Some("true"),
                    default_value: None,
                }));
            } else {
                let mut fields_to_add = Vec::new();

                for field in fields {
                    let field_name = field.try_attribute("Name")?;

                    let raw_typ = field.try_attribute("DataType")?;
                    let typ = if let Ok(r) = strip_first_segment(raw_typ, ":") {
                        r
                    } else {
                        raw_typ
                    };
                    let typ = type_names
                        .get(typ)
                        .ok_or_else(|| CodeGenError::other(format!("Unknown type: {typ}")))?;

                    let value_rank: Option<i32> =
                        field.attribute("ValueRank").and_then(|v| v.parse().ok());
                    let is_array = value_rank.is_some_and(|v| v != 0);
                    if is_array {
                        fields_to_add.push(StructureField {
                            name: field_name.to_owned(),
                            typ: StructureFieldType::Array(typ.to_owned()),
                        });
                    } else {
                        fields_to_add.push(StructureField {
                            name: field_name.to_owned(),
                            typ: StructureFieldType::Field(typ.to_owned()),
                        });
                    }
                }

                let base_type_node = data_type
                    .first_child_with_name("References")?
                    .with_name("Reference")
                    .find(|r| {
                        r.attribute("ReferenceType") == Some("HasSubtype")
                            && r.attribute("IsForward") == Some("true")
                    });
                let base_type = base_type_node
                    .and_then(|n| n.text())
                    .and_then(|v| type_names.get(v));

                types.push(LoadedType::Struct(StructuredType {
                    name: name.to_owned(),
                    fields: fields_to_add,
                    hidden_fields: Vec::new(),
                    documentation: data_type
                        .child_contents("Documentation")
                        .map(|v| v.to_owned()),
                    base_type: base_type.cloned(),
                    is_union: definition.attribute("IsUnion") == Some("true"),
                }))
            }
        }

        Ok(types)
    } */
}
