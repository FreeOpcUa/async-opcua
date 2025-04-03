use std::collections::{HashMap, HashSet};

use convert_case::{Case, Casing};
use proc_macro2::Span;
use syn::{
    parse_quote, parse_str, punctuated::Punctuated, FieldsNamed, File, Generics, Item, ItemEnum,
    ItemMacro, ItemStruct, Lit, LitByte, Path, Token, Type, Visibility,
};
use tracing::warn;

use crate::{
    error::CodeGenError,
    utils::{safe_ident, RenderExpr},
    GeneratedOutput, BASE_NAMESPACE,
};

use super::{
    encoding_ids::EncodingIds,
    loaders::{EnumReprType, EnumType, FieldType, StructureFieldType, StructuredType},
    ExternalType, LoadedType,
};
use quote::quote;

pub enum ItemDefinition {
    Struct(ItemStruct),
    Enum(ItemEnum),
    BitField(ItemMacro),
}

pub struct GeneratedItem {
    pub item: ItemDefinition,
    pub impls: Vec<Item>,
    pub module: String,
    pub name: String,
    pub encoding_ids: Option<EncodingIds>,
}

impl GeneratedOutput for GeneratedItem {
    fn to_file(self) -> File {
        let mut items = Vec::new();
        match self.item {
            ItemDefinition::Struct(v) => items.push(Item::Struct(v)),
            ItemDefinition::Enum(v) => items.push(Item::Enum(v)),
            ItemDefinition::BitField(v) => items.push(Item::Macro(v)),
        }
        for imp in self.impls {
            items.push(imp);
        }

        File {
            shebang: None,
            attrs: Vec::new(),
            items,
        }
    }

    fn module(&self) -> &str {
        &self.module
    }

    fn name(&self) -> &str {
        &self.name
    }
}

pub struct CodeGenItemConfig {
    pub enums_single_file: bool,
    pub structs_single_file: bool,
    pub node_ids_from_nodeset: bool,
}

pub struct ImportType {
    path: String,
    has_default: Option<bool>,
    base_type: Option<FieldType>,
    is_defined: bool,
}

pub struct CodeGenerator {
    import_map: HashMap<String, ImportType>,
    input: HashMap<String, LoadedType>,
    default_excluded: HashSet<String>,
    config: CodeGenItemConfig,
    target_namespace: String,
    native_types: HashSet<String>,
    id_path: String,
}

impl CodeGenerator {
    pub fn new(
        external_import_map: HashMap<String, ExternalType>,
        native_types: HashSet<String>,
        input: Vec<LoadedType>,
        default_excluded: HashSet<String>,
        config: CodeGenItemConfig,
        target_namespace: String,
        id_path: String,
    ) -> Self {
        Self {
            import_map: external_import_map
                .into_iter()
                .map(|(k, v)| {
                    (
                        k,
                        ImportType {
                            has_default: v.has_default,
                            base_type: match v.base_type.as_deref() {
                                Some("ExtensionObject" | "OptionSet") => {
                                    Some(FieldType::ExtensionObject(None))
                                }
                                Some(t) => Some(FieldType::Normal(t.to_owned())),
                                None => None,
                            },
                            path: v.path,
                            is_defined: true,
                        },
                    )
                })
                .collect(),
            input: input
                .into_iter()
                .map(|v| (v.name().to_owned(), v))
                .collect(),
            config,
            default_excluded,
            target_namespace,
            native_types,
            id_path,
        }
    }

    fn is_base_namespace(&self) -> bool {
        self.target_namespace == BASE_NAMESPACE
    }

    fn is_default_recursive(&self, name: &str) -> bool {
        if self.default_excluded.contains(name) {
            return true;
        }

        let Some(it) = self.import_map.get(name) else {
            // Not in the import map means it's a builtin, we assume these have defaults for now.
            return true;
        };

        if let Some(def) = it.has_default {
            return def;
        }

        let Some(input) = self.input.get(name) else {
            return false;
        };

        match input {
            LoadedType::Struct(s) => {
                for k in &s.fields {
                    let has_default = match &k.typ {
                        StructureFieldType::Field(FieldType::Normal(f)) => {
                            self.is_default_recursive(f)
                        }
                        StructureFieldType::Array(_) | StructureFieldType::Field(_) => true,
                    };
                    if !has_default {
                        return false;
                    }
                }
                true
            }
            LoadedType::Enum(e) => {
                e.option || e.default_value.is_some() || e.values.iter().any(|v| v.value == 0)
            }
        }
    }

    pub fn generate_types(mut self) -> Result<Vec<GeneratedItem>, CodeGenError> {
        let mut generated = Vec::new();

        for item in self.input.values() {
            if self.import_map.contains_key(item.name()) {
                continue;
            }
            let name = match item {
                LoadedType::Struct(s) => {
                    if self.config.structs_single_file {
                        "structs".to_owned()
                    } else {
                        s.name.to_case(Case::Snake)
                    }
                }
                LoadedType::Enum(s) => {
                    if self.config.enums_single_file {
                        "enums".to_owned()
                    } else {
                        s.name.to_case(Case::Snake)
                    }
                }
            };

            self.import_map.insert(
                item.name().to_owned(),
                ImportType {
                    path: format!("super::{}", name),
                    // Determined later
                    has_default: None,
                    base_type: match &item {
                        LoadedType::Struct(v) => v.base_type.clone(),
                        LoadedType::Enum(_) => None,
                    },
                    is_defined: false,
                },
            );
        }
        for key in self.import_map.keys().cloned().collect::<Vec<_>>() {
            let has_default = self.is_default_recursive(&key);
            if let Some(it) = self.import_map.get_mut(&key) {
                it.has_default = Some(has_default);
            }
        }

        let input = std::mem::take(&mut self.input);

        for item in input.into_values() {
            if self
                .import_map
                .get(item.name())
                .is_some_and(|v| v.is_defined)
            {
                continue;
            }

            match item {
                LoadedType::Struct(v) => generated.push(self.generate_struct(v)?),
                LoadedType::Enum(v) => generated.push(self.generate_enum(v)?),
            }
        }

        Ok(generated)
    }

    fn get_type_path(&self, name: &str) -> String {
        // Type is known, use the external path.
        if let Some(ext) = self.import_map.get(name) {
            return format!("{}::{}", ext.path, name);
        }
        // Is it a native type?
        if self.native_types.contains(name) {
            return name.to_owned();
        }
        // Assume the type is a builtin.
        format!("opcua::types::{}", name)
    }

    fn has_default(&self, name: &str) -> bool {
        self.import_map
            .get(name)
            .is_some_and(|v| v.has_default.is_some_and(|v| v))
    }

    fn generate_bitfield(&self, item: EnumType) -> Result<GeneratedItem, CodeGenError> {
        let mut body = quote! {};
        let ty: Type = syn::parse_str(&item.typ.to_string())?;
        let doc_tokens = if let Some(doc) = item.documentation {
            quote! {
                #[doc = #doc]
            }
        } else {
            quote! {}
        };

        let mut variants = quote! {};

        for field in &item.values {
            let (name, _) = safe_ident(&field.name);
            let value = field.value;
            let value_token = match item.typ {
                EnumReprType::u8 => {
                    let value: u8 = value.try_into().map_err(|_| {
                        CodeGenError::other(format!(
                            "Unexpected error converting to u8, {} is out of range",
                            value
                        ))
                    })?;
                    Lit::Byte(LitByte::new(value, Span::call_site()))
                }
                EnumReprType::i16 => {
                    let value: i16 = value.try_into().map_err(|_| {
                        CodeGenError::other(format!(
                            "Unexpected error converting to i16, {} is out of range",
                            value
                        ))
                    })?;
                    parse_quote! { #value }
                }
                EnumReprType::i32 => {
                    let value: i32 = value.try_into().map_err(|_| {
                        CodeGenError::other(format!(
                            "Unexpected error converting to i32, {} is out of range",
                            value
                        ))
                    })?;
                    parse_quote! { #value }
                }
                EnumReprType::i64 => {
                    parse_quote! { #value }
                }
            };
            let mut attrs = quote! {};
            if let Some(doc) = &field.documentation {
                attrs.extend(quote! {
                    #[doc = #doc]
                });
            }
            variants.extend(quote! {
                #attrs
                const #name = #value_token;
            });
        }
        let (enum_ident, _) = safe_ident(&item.name);

        body.extend(quote! {
            bitflags::bitflags! {
                #[derive(Debug, Copy, Clone, PartialEq)]
                #doc_tokens
                pub struct #enum_ident: #ty {
                    #variants
                }
            }
        });

        let mut impls = Vec::new();

        impls.push(parse_quote! {
            impl opcua::types::UaNullable for #enum_ident {
                fn is_ua_null(&self) -> bool {
                    self.is_empty()
                }
            }
        });
        impls.push(parse_quote! {
            opcua::types::impl_encoded_as!(
                #enum_ident,
                |v| Ok(#enum_ident::from_bits_truncate(v)),
                |v: &#enum_ident| Ok::<_, opcua::types::Error>(v.bits()),
                |v: &#enum_ident| v.bits().byte_len()
            );
        });

        impls.push(parse_quote! {
            impl Default for #enum_ident {
                fn default() -> Self {
                    Self::empty()
                }
            }
        });

        impls.push(parse_quote! {
            impl opcua::types::IntoVariant for #enum_ident {
                fn into_variant(self) -> opcua::types::Variant {
                    self.bits().into_variant()
                }
            }
        });

        let name = &item.name;
        impls.push(parse_quote! {
            #[cfg(feature = "xml")]
            impl opcua::types::xml::XmlType for #enum_ident {
                const TAG: &'static str = #name;
            }
        });

        Ok(GeneratedItem {
            item: ItemDefinition::BitField(parse_quote! {
                #body
            }),
            impls,
            module: if self.config.enums_single_file {
                "enums".to_owned()
            } else {
                item.name.to_case(Case::Snake)
            },
            name: item.name.clone(),
            encoding_ids: None,
        })
    }

    fn generate_enum(&self, item: EnumType) -> Result<GeneratedItem, CodeGenError> {
        if item.option {
            return self.generate_bitfield(item);
        }

        let mut attrs = Vec::new();
        let mut variants = Punctuated::new();

        attrs.push(parse_quote! {
            #[opcua::types::ua_encodable]
        });
        if let Some(doc) = item.documentation {
            attrs.push(parse_quote! {
                #[doc = #doc]
            });
        }
        attrs.push(parse_quote! {
            #[derive(Debug, Copy, Clone, PartialEq, Eq)]
        });
        let ty: Type = syn::parse_str(&item.typ.to_string())?;
        attrs.push(parse_quote! {
            #[repr(#ty)]
        });

        for field in &item.values {
            let (name, renamed) = safe_ident(&field.name);
            let value = field.value;
            let is_default = if let Some(default_name) = &item.default_value {
                &name.to_string() == default_name
            } else {
                value == 0
            };

            let value_token = match item.typ {
                EnumReprType::u8 => {
                    let value: u8 = value.try_into().map_err(|_| {
                        CodeGenError::other(format!(
                            "Unexpected error converting to u8, {} is out of range",
                            value
                        ))
                    })?;
                    Lit::Byte(LitByte::new(value, Span::call_site()))
                }
                EnumReprType::i16 => {
                    let value: i16 = value.try_into().map_err(|_| {
                        CodeGenError::other(format!(
                            "Unexpected error converting to i16, {} is out of range",
                            value
                        ))
                    })?;
                    parse_quote! { #value }
                }
                EnumReprType::i32 => {
                    let value: i32 = value.try_into().map_err(|_| {
                        CodeGenError::other(format!(
                            "Unexpected error converting to i32, {} is out of range",
                            value
                        ))
                    })?;
                    parse_quote! { #value }
                }
                EnumReprType::i64 => {
                    parse_quote! { #value }
                }
            };

            let mut attrs = quote! {};
            if is_default {
                attrs.extend(quote! {
                    #[opcua(default)]
                });
            }
            if let Some(doc) = &field.documentation {
                attrs.extend(quote! {
                    #[doc = #doc]
                });
            }
            if renamed {
                let orig = &field.name;
                attrs.extend(quote! {
                    #[opcua(rename = #orig)]
                });
            }
            variants.push(parse_quote! {
                #attrs
                #name = #value_token
            })
        }

        let (enum_ident, renamed) = safe_ident(&item.name);
        if renamed {
            let name = &item.name;
            attrs.push(parse_quote! {
                #[opcua(rename = #name)]
            });
        }

        let res = ItemEnum {
            attrs,
            vis: Visibility::Public(Token![pub](Span::call_site())),
            enum_token: Token![enum](Span::call_site()),
            ident: enum_ident,
            generics: Generics::default(),
            brace_token: syn::token::Brace(Span::call_site()),
            variants,
        };

        Ok(GeneratedItem {
            item: ItemDefinition::Enum(res),
            impls: Vec::new(),
            module: if self.config.enums_single_file {
                "enums".to_owned()
            } else {
                item.name.to_case(Case::Snake)
            },
            name: item.name.clone(),
            encoding_ids: None,
        })
    }

    fn is_extension_object(&self, typ: Option<&FieldType>) -> bool {
        let name = match &typ {
            Some(FieldType::Abstract(_)) | Some(FieldType::ExtensionObject(_)) => return true,
            Some(FieldType::Normal(s)) => s,
            None => return false,
        };
        let name = match name.split_once(":") {
            Some((_, n)) => n,
            None => name,
        };

        let Some(parent) = self.import_map.get(name) else {
            return false;
        };

        self.is_extension_object(parent.base_type.as_ref())
    }

    fn generate_struct(&self, item: StructuredType) -> Result<GeneratedItem, CodeGenError> {
        let mut attrs = Vec::new();
        let mut fields = Punctuated::new();

        attrs.push(parse_quote! {
            #[opcua::types::ua_encodable]
        });
        if let Some(doc) = &item.documentation {
            attrs.push(parse_quote! {
                #[doc = #doc]
            });
        }
        attrs.push(parse_quote! {
            #[derive(Debug, Clone, PartialEq)]
        });

        if self.has_default(&item.name) && !self.default_excluded.contains(&item.name) {
            attrs.push(parse_quote! {
                #[derive(Default)]
            });
        }

        let mut impls = Vec::new();
        let (struct_ident, renamed) = safe_ident(&item.name);
        if renamed {
            let name = &item.name;
            attrs.push(parse_quote! {
                #[opcua(rename = #name)]
            });
        }

        for field in item.visible_fields() {
            let typ: Type = match &field.typ {
                StructureFieldType::Field(f) => {
                    syn::parse_str(&self.get_type_path(f.as_type_str())).map_err(|e| {
                        CodeGenError::from(e)
                            .with_context(format!("Generating path for {}", f.as_type_str()))
                    })?
                }
                StructureFieldType::Array(f) => {
                    let path: Path =
                        syn::parse_str(&self.get_type_path(f.as_type_str())).map_err(|e| {
                            CodeGenError::from(e)
                                .with_context(format!("Generating path for {}", f.as_type_str()))
                        })?;
                    parse_quote! { Option<Vec<#path>> }
                }
            };
            let (ident, changed) = safe_ident(&field.name);
            let mut attrs = quote! {};
            if changed {
                let orig = &field.original_name;
                attrs = quote! {
                    #[opcua(rename = #orig)]
                };
            }
            if let Some(doc) = &field.documentation {
                attrs.extend(quote! {
                    #[doc = #doc]
                });
            }
            fields.push(parse_quote! {
                #attrs
                pub #ident: #typ
            });
        }

        let mut encoding_ids = None;
        // Generate impls
        // Has message info
        if self.is_extension_object(item.base_type.as_ref()) {
            if self.config.node_ids_from_nodeset {
                // To allow supporting the other encodings and not just panicing, use the data type id as fallback
                // if the encoding type isn't set.
                if let Some(ids) = item.base_type.and_then(|t| match t {
                    FieldType::ExtensionObject(n) => n,
                    _ => None,
                }) {
                    // Should not be null here, since ID is always set when generating from nodeset.
                    // Ugly, but too much of a pain to work around. We don't have IDs at all when working
                    // with BSDs.
                    let id = item
                        .id
                        .as_ref()
                        .ok_or_else(|| CodeGenError::other("Missing data type ID"))?;
                    let binary_expr = ids.binary.as_ref().unwrap_or(id).value.render()?;
                    let xml_expr = ids.xml.as_ref().unwrap_or(id).value.render()?;
                    let json_expr = ids.json.as_ref().unwrap_or(id).value.render()?;
                    let type_expr = id.value.render()?;
                    let namespace = self.target_namespace.as_str();
                    impls.push(parse_quote! {
                        impl opcua::types::ExpandedMessageInfo for #struct_ident {
                            fn full_type_id(&self) -> opcua::types::ExpandedNodeId {
                                opcua::types::ExpandedNodeId::from((#binary_expr, #namespace))
                            }
                            fn full_json_type_id(&self) -> opcua::types::ExpandedNodeId {
                                opcua::types::ExpandedNodeId::from((#json_expr, #namespace))
                            }
                            fn full_xml_type_id(&self) -> opcua::types::ExpandedNodeId {
                                opcua::types::ExpandedNodeId::from((#xml_expr, #namespace))
                            }
                            fn full_data_type_id(&self) -> opcua::types::ExpandedNodeId {
                                opcua::types::ExpandedNodeId::from((#type_expr, #namespace))
                            }
                        }
                    });
                    encoding_ids = Some(EncodingIds::new_raw(&ids)?);
                } else {
                    warn!(
                        "Type {} should be extension object but is missing encoding IDs, skipping",
                        item.name
                    )
                }
            } else {
                let (encoding_ident, _) =
                    safe_ident(&format!("{}_Encoding_DefaultBinary", item.name));
                let (json_encoding_ident, _) =
                    safe_ident(&format!("{}_Encoding_DefaultJson", item.name));
                let (xml_encoding_ident, _) =
                    safe_ident(&format!("{}_Encoding_DefaultXml", item.name));
                let (data_type_ident, _) = safe_ident(&item.name);
                let id_path: Path = parse_str(&self.id_path)?;
                if self.is_base_namespace() {
                    impls.push(parse_quote! {
                        impl opcua::types::MessageInfo for #struct_ident {
                            fn type_id(&self) -> opcua::types::ObjectId {
                                opcua::types::ObjectId::#encoding_ident
                            }
                            fn json_type_id(&self) -> opcua::types::ObjectId {
                                opcua::types::ObjectId::#json_encoding_ident
                            }
                            fn xml_type_id(&self) -> opcua::types::ObjectId {
                                opcua::types::ObjectId::#xml_encoding_ident
                            }
                            fn data_type_id(&self) -> opcua::types::DataTypeId {
                                opcua::types::DataTypeId::#data_type_ident
                            }
                        }
                    });
                } else {
                    let namespace = self.target_namespace.as_str();
                    impls.push(parse_quote! {
                        impl opcua::types::ExpandedMessageInfo for #struct_ident {
                            fn full_type_id(&self) -> opcua::types::ExpandedNodeId {
                                let id: opcua::types::NodeId = #id_path::ObjectId::#encoding_ident.into();
                                opcua::types::ExpandedNodeId::from((id, #namespace))
                            }
                            fn full_json_type_id(&self) -> opcua::types::ExpandedNodeId {
                                let id: opcua::types::NodeId = #id_path::ObjectId::#json_encoding_ident.into();
                                opcua::types::ExpandedNodeId::from((id, #namespace))
                            }
                            fn full_xml_type_id(&self) -> opcua::types::ExpandedNodeId {
                                let id: opcua::types::NodeId = #id_path::ObjectId::#xml_encoding_ident.into();
                                opcua::types::ExpandedNodeId::from((id, #namespace))
                            }
                            fn full_data_type_id(&self) -> opcua::types::ExpandedNodeId {
                                let id: opcua::types::NodeId = #id_path::DataTypeId::#data_type_ident.into();
                                opcua::types::ExpandedNodeId::from((id, #namespace))
                            }
                        }
                    });
                }
                encoding_ids = Some(EncodingIds::new(id_path, &item.name)?);
            }
        }

        let res = ItemStruct {
            attrs,
            vis: Visibility::Public(Token![pub](Span::call_site())),
            struct_token: Token![struct](Span::call_site()),
            ident: struct_ident,
            generics: Generics::default(),
            fields: syn::Fields::Named(FieldsNamed {
                brace_token: syn::token::Brace(Span::call_site()),
                named: fields,
            }),
            semi_token: None,
        };

        Ok(GeneratedItem {
            item: ItemDefinition::Struct(res),
            impls,
            module: if self.config.structs_single_file {
                "structs".to_owned()
            } else {
                item.name.to_case(Case::Snake)
            },
            name: item.name.clone(),
            encoding_ids,
        })
    }
}
