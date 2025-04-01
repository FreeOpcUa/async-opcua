use std::collections::{HashMap, HashSet};

use opcua_xml::schema::ua_node_set::{DataTypeField, LocalizedText, UADataType, UANode};

use crate::{
    input::{NodeSetInput, SchemaCache, TypeInfo},
    utils::{split_qualified_name, to_snake_case, NodeIdVariant, ParsedNodeId},
    CodeGenError,
};

use super::{
    types::{EnumReprType, EnumValue, FieldType, StructureField, StructureFieldType},
    EnumType, LoadedType, StructuredType,
};

pub struct NodeSetTypeLoader<'a> {
    ignored: HashSet<String>,
    native_type_mappings: HashMap<String, String>,
    input: &'a NodeSetInput,
    preferred_locale: String,
}

/// These are types that custom types are allowed to descend from.
/// If it's Enumeration, the type is an enum, if it's an integer type
/// it must be an option set, and if it's a structure, it must be a struct.
/// Any other type is not currently allowed, as it's not clear what that would even mean.
enum BuiltInTypeVariant {
    Enumeration,
    Byte,
    UInt16,
    UInt32,
    UInt64,
    Structure,
}

impl<'a> NodeSetTypeLoader<'a> {
    pub fn new(
        ignored: HashSet<String>,
        native_type_mappings: HashMap<String, String>,
        input: &'a NodeSetInput,
        preferred_locale: &str,
    ) -> Self {
        Self {
            ignored,
            native_type_mappings,
            input,
            preferred_locale: preferred_locale.to_owned(),
        }
    }

    fn get_from_localized_text(&self, options: &[LocalizedText]) -> Option<String> {
        options
            .iter()
            .find(|f| f.locale.0 == self.preferred_locale)
            .or_else(|| options.first())
            .map(|v| v.text.clone())
    }

    fn field_type_for_info(info: TypeInfo) -> FieldType {
        if info.is_abstract {
            FieldType::Abstract(info.name)
        } else if info.name == "Structure" || info.name == "OptionSet" {
            FieldType::ExtensionObject(Some(info.encoding_ids))
        } else {
            FieldType::Normal(info.name)
        }
    }

    fn load_data_type(
        &self,
        node: &UADataType,
        cache: &SchemaCache,
    ) -> Result<Option<LoadedType>, CodeGenError> {
        if node.base.is_abstract {
            return Ok(None);
        }

        // Data types without definition are generally abstract or built-in.
        let Some(definition) = &node.definition else {
            return Ok(None);
        };

        let name = definition
            .symbolic_name
            .names
            .first()
            .cloned()
            .unwrap_or(split_qualified_name(&definition.name.0)?.0.to_owned());

        if self.ignored.contains(&name) {
            return Ok(None);
        }

        let id = ParsedNodeId::parse(self.input.resolve_alias(&node.base.base.node_id.0))?;
        let variant = Self::find_builtin_type_variant(&id, &id, self.input, cache)?;

        let fields = self.collect_fields(&id, cache)?;

        match variant {
            BuiltInTypeVariant::Byte
            | BuiltInTypeVariant::UInt16
            | BuiltInTypeVariant::UInt32
            | BuiltInTypeVariant::UInt64
            | BuiltInTypeVariant::Enumeration => {
                let ty = EnumType {
                    name,
                    values: fields
                        .iter()
                        .map(|f| EnumValue {
                            name: f.name.clone(),
                            value: if definition.is_option_set {
                                // In option sets, the value is the bit position.
                                1 << f.value
                            } else {
                                f.value
                            },
                            documentation: self.get_from_localized_text(&f.descriptions),
                        })
                        .collect(),
                    documentation: node.base.base.documentation.clone(),
                    typ: match variant {
                        BuiltInTypeVariant::Byte => EnumReprType::u8,
                        BuiltInTypeVariant::UInt16 => EnumReprType::i16,
                        BuiltInTypeVariant::UInt32 => EnumReprType::i32,
                        BuiltInTypeVariant::UInt64 => EnumReprType::i64,
                        BuiltInTypeVariant::Enumeration => EnumReprType::i32,
                        _ => unreachable!(),
                    },
                    size: match variant {
                        BuiltInTypeVariant::Byte => 1,
                        BuiltInTypeVariant::UInt16 => 2,
                        BuiltInTypeVariant::UInt32 => 4,
                        BuiltInTypeVariant::UInt64 => 8,
                        BuiltInTypeVariant::Enumeration => 4,
                        _ => unreachable!(),
                    },
                    option: definition.is_option_set,
                    default_value: None,
                };
                Ok(Some(LoadedType::Enum(ty)))
            }
            BuiltInTypeVariant::Structure => {
                let type_info = self.resolve_type_info(&id, cache)?;
                let ty = StructuredType {
                    name,
                    id: Some(id),
                    fields: fields
                        .iter()
                        .map(|f| {
                            Ok::<StructureField, CodeGenError>(StructureField {
                                name: to_snake_case(&f.name),
                                original_name: f
                                    .symbolic_name
                                    .as_ref()
                                    .and_then(|n| n.names.first())
                                    .unwrap_or(&f.name)
                                    .clone(),
                                typ: {
                                    let type_info = self.resolve_type_info(
                                        &ParsedNodeId::parse(
                                            self.input.resolve_alias(&f.data_type.0),
                                        )?,
                                        cache,
                                    )?;
                                    let ty = Self::field_type_for_info(type_info);
                                    if f.value_rank.0 > 0 {
                                        StructureFieldType::Array(ty)
                                    } else {
                                        StructureFieldType::Field(ty)
                                    }
                                },
                                documentation: self.get_from_localized_text(&f.descriptions),
                            })
                        })
                        .collect::<Result<Vec<_>, _>>()?,
                    hidden_fields: Vec::new(),
                    documentation: node.base.base.documentation.clone(),
                    // We inherit from structure, so this must be an extension object type,
                    // but if it doesn't have an encoding, just set the base type to None.
                    base_type: if type_info.has_encoding() {
                        Some(FieldType::ExtensionObject(Some(type_info.encoding_ids)))
                    } else {
                        None
                    },
                    is_union: definition.is_union,
                };
                Ok(Some(LoadedType::Struct(ty)))
            }
        }
    }

    fn collect_fields(
        &self,
        id: &ParsedNodeId,
        cache: &SchemaCache,
    ) -> Result<Vec<DataTypeField>, CodeGenError> {
        let mut current = id;
        // Note that field order is significant.
        // We write the fields in reverse order, then reverse the vector at the end.
        let mut res = Vec::new();
        loop {
            // TODO: Special treatment for OptionSets. They are something really weird
            // that isn't used in the core namespace. They could probably be
            // represented with a neat generic type or something.
            // For now hard-code that option sets only contain their two fields.

            let info = self.resolve_type_info(current, cache)?;
            if current.namespace == 0 && current.value == NodeIdVariant::Numeric(12755) {
                return Ok(info.definition.map(|d| d.fields).unwrap_or_default());
            }

            if let Some(def) = info.definition {
                res.extend(def.fields.into_iter().rev());
            }
            if let Some(parent) = self.input.get_parent_type_ids()?.get(current) {
                current = parent;
                if parent.namespace == 0
                    && matches!(parent.value, NodeIdVariant::Numeric(n ) if n <= 22)
                {
                    break;
                }
            } else {
                break;
            }
        }

        res.reverse();
        Ok(res)
    }

    fn resolve_type_info(
        &self,
        id: &ParsedNodeId,
        cache: &SchemaCache,
    ) -> Result<TypeInfo, CodeGenError> {
        let r = if id.namespace == self.input.own_namespace_index {
            self.input
                .get_type_names()?
                .get(id)
                .cloned()
                .ok_or_else(|| {
                    CodeGenError::other(format!("Did not find type name for data type {}", id))
                })?
        } else {
            let ns = self
                .input
                .namespaces
                .get(id.namespace as usize)
                .ok_or_else(|| {
                    CodeGenError::other(format!(
                        "Namespace {} not found in schema {}",
                        id.namespace, self.input.uri
                    ))
                })?;

            let schema = cache.get_nodeset(ns)?;
            let next_id = ParsedNodeId {
                value: id.value.clone(),
                namespace: schema.own_namespace_index,
            };
            schema
                .get_type_names()?
                .get(&next_id)
                .cloned()
                .ok_or_else(|| {
                    CodeGenError::other(format!("Did not find type name for data type {}", id))
                })?
        };
        if let Some(native) = self.native_type_mappings.get(&r.name) {
            Ok(TypeInfo {
                name: native.to_owned(),
                is_abstract: false,
                definition: None,
                encoding_ids: Default::default(),
            })
        } else {
            Ok(r)
        }
    }

    fn find_builtin_type_variant(
        orig: &ParsedNodeId,
        id: &ParsedNodeId,
        schema: &NodeSetInput,
        cache: &SchemaCache,
    ) -> Result<BuiltInTypeVariant, CodeGenError> {
        if id.namespace == 0 {
            match id.value {
                NodeIdVariant::Numeric(3) => return Ok(BuiltInTypeVariant::Byte),
                NodeIdVariant::Numeric(5) => return Ok(BuiltInTypeVariant::UInt16),
                NodeIdVariant::Numeric(7) => return Ok(BuiltInTypeVariant::UInt32),
                NodeIdVariant::Numeric(9) => return Ok(BuiltInTypeVariant::UInt64),
                NodeIdVariant::Numeric(29) => return Ok(BuiltInTypeVariant::Enumeration),
                NodeIdVariant::Numeric(22) => return Ok(BuiltInTypeVariant::Structure),
                _ => (),
            }
        }

        if id.namespace == schema.own_namespace_index {
            let Some(parent) = schema.get_parent_type_ids()?.get(id) else {
                return Err(CodeGenError::other(format!(
                    "Did not find parent of data type {}. Last known parent is {}",
                    orig, id
                )));
            };
            Self::find_builtin_type_variant(orig, parent, schema, cache)
        } else {
            let ns = schema
                .namespaces
                .get(id.namespace as usize)
                .ok_or_else(|| {
                    CodeGenError::other(format!(
                        "Namespace {} not found in schema {}",
                        id.namespace, schema.uri
                    ))
                })?;

            let schema = cache.get_nodeset(ns)?;
            let next_id = ParsedNodeId {
                value: id.value.clone(),
                namespace: schema.own_namespace_index,
            };
            let Some(parent) = schema.get_parent_type_ids()?.get(&next_id) else {
                return Err(CodeGenError::other(format!(
                    "Did not find parent of data type {}",
                    id
                )));
            };

            Self::find_builtin_type_variant(orig, parent, schema, cache)
        }
    }

    pub fn load_types(self, cache: &SchemaCache) -> Result<Vec<LoadedType>, CodeGenError> {
        let mut res = Vec::new();
        for node in &self.input.xml.nodes {
            let UANode::DataType(d) = node else {
                continue;
            };
            if let Some(r) = self.load_data_type(d, cache)? {
                res.push(r);
            }
        }
        Ok(res)
    }
}
