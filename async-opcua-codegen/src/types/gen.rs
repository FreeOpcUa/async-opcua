use std::collections::{HashMap, HashSet};

use convert_case::{Case, Casing};
use proc_macro2::Span;
use syn::{
    parse_quote, punctuated::Punctuated, FieldsNamed, File, Generics, Ident, Item, ItemEnum,
    ItemImpl, ItemMacro, ItemStruct, Lit, LitByte, Path, Token, Type, Visibility,
};

use crate::{
    error::CodeGenError, utils::safe_ident, GeneratedOutput, StructuredType, BASE_NAMESPACE,
};

use super::{enum_type::EnumReprType, loader::LoadedType, EnumType, ExternalType};
use quote::quote;

pub enum ItemDefinition {
    Struct(ItemStruct),
    Enum(ItemEnum),
    BitField(ItemMacro),
}

#[derive(Clone)]
pub struct EncodingIds {
    pub data_type: Ident,
    pub xml: Ident,
    pub json: Ident,
    pub binary: Ident,
}

impl EncodingIds {
    pub fn new(root: &str) -> Self {
        Self {
            data_type: Ident::new(root, Span::call_site()),
            xml: Ident::new(&format!("{}_Encoding_DefaultXml", root), Span::call_site()),
            json: Ident::new(&format!("{}_Encoding_DefaultJson", root), Span::call_site()),
            binary: Ident::new(
                &format!("{}_Encoding_DefaultBinary", root),
                Span::call_site(),
            ),
        }
    }
}

pub struct GeneratedItem {
    pub item: ItemDefinition,
    pub impls: Vec<ItemImpl>,
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
            items.push(Item::Impl(imp));
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
}

pub struct ImportType {
    path: String,
    has_default: Option<bool>,
    base_type: Option<String>,
    is_defined: bool,
}

pub struct CodeGenerator {
    import_map: HashMap<String, ImportType>,
    input: HashMap<String, LoadedType>,
    default_excluded: HashSet<String>,
    config: CodeGenItemConfig,
    target_namespace: String,
    native_types: HashSet<String>,
}

impl CodeGenerator {
    pub fn new(
        external_import_map: HashMap<String, ExternalType>,
        native_types: HashSet<String>,
        input: Vec<LoadedType>,
        default_excluded: HashSet<String>,
        config: CodeGenItemConfig,
        target_namespace: String,
    ) -> Self {
        Self {
            import_map: external_import_map
                .into_iter()
                .map(|(k, v)| {
                    (
                        k,
                        ImportType {
                            path: v.path,
                            has_default: v.has_default,
                            base_type: v.base_type,
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
                        crate::StructureFieldType::Field(f) => self.is_default_recursive(f),
                        crate::StructureFieldType::Array(_) => true,
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
        if let Some(doc) = item.documentation {
            body.extend(quote! {
                #[doc = #doc]
            });
        }
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
            variants.extend(quote! {
                const #name = #value_token;
            });
        }
        let (enum_ident, _) = safe_ident(&item.name);

        body.extend(quote! {
            bitflags::bitflags! {
                #[derive(Debug, Copy, Clone, PartialEq)]
                pub struct #enum_ident: #ty {
                    #variants
                }
            }
        });

        let mut impls = Vec::new();
        let size: usize = item.size.try_into().map_err(|_| {
            CodeGenError::other(format!("Value {} does not fit in a usize", item.size))
        })?;
        let write_method = Ident::new(&format!("write_{}", item.typ), Span::call_site());

        impls.push(parse_quote! {
            impl opcua::types::UaNullable for #enum_ident {
                fn is_ua_null(&self) -> bool {
                    self.is_empty()
                }
            }
        });

        impls.push(parse_quote! {
            impl opcua::types::BinaryEncodable for #enum_ident {
                fn byte_len(&self, _ctx: &opcua::types::Context<'_>) -> usize {
                    #size
                }

                fn encode<S: std::io::Write + ?Sized>(&self, stream: &mut S, _ctx: &opcua::types::Context<'_>) -> opcua::types::EncodingResult<()> {
                    opcua::types::#write_method(stream, self.bits())
                }
            }
        });

        impls.push(parse_quote! {
            impl opcua::types::BinaryDecodable for #enum_ident {
                fn decode<S: std::io::Read + ?Sized>(stream: &mut S, ctx: &opcua::types::Context<'_>) -> opcua::types::EncodingResult<Self> {
                    Ok(Self::from_bits_truncate(#ty::decode(stream, ctx)?))
                }
            }
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

        impls.push(parse_quote! {
            #[cfg(feature = "xml")]
            impl opcua::types::xml::XmlDecodable for #enum_ident {
                fn decode(
                    stream: &mut opcua::types::xml::XmlStreamReader<&mut dyn std::io::Read>,
                    ctx: &opcua::types::Context<'_>,
                ) -> opcua::types::EncodingResult<Self> {
                    Ok(Self::from_bits_truncate(#ty::decode(stream, ctx)?))
                }
            }
        });

        impls.push(parse_quote! {
            #[cfg(feature = "xml")]
            impl opcua::types::xml::XmlEncodable for #enum_ident {
                fn encode(
                    &self,
                    stream: &mut opcua::types::xml::XmlStreamWriter<&mut dyn std::io::Write>,
                    ctx: &opcua::types::Context<'_>,
                ) -> opcua::types::EncodingResult<()> {
                    self.bits().encode(stream, ctx)
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

        impls.push(parse_quote! {
            #[cfg(feature = "json")]
            impl opcua::types::json::JsonDecodable for #enum_ident {
                fn decode(
                    stream: &mut opcua::types::json::JsonStreamReader<&mut dyn std::io::Read>,
                    _ctx: &opcua::types::Context<'_>,
                ) -> opcua::types::EncodingResult<Self> {
                    use opcua::types::json::JsonReader;
                    Ok(Self::from_bits_truncate(stream.next_number()??))
                }
            }
        });

        impls.push(parse_quote! {
            #[cfg(feature = "json")]
            impl opcua::types::json::JsonEncodable for #enum_ident {
                fn encode(
                    &self,
                    stream: &mut opcua::types::json::JsonStreamWriter<&mut dyn std::io::Write>,
                    _ctx: &opcua::types::Context<'_>,
                ) -> opcua::types::EncodingResult<()> {
                    use opcua::types::json::JsonWriter;
                    stream.number_value(self.bits())?;
                    Ok(())
                }
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
            let (name, _) = safe_ident(&field.name);
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

            if is_default {
                variants.push(parse_quote! {
                    #[opcua(default)]
                    #name = #value_token
                })
            } else {
                variants.push(parse_quote! {
                    #name = #value_token
                })
            }
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

    fn is_extension_object(&self, typ: &str) -> bool {
        if typ == "ua:ExtensionObject" || typ == "ua:OptionSet" {
            return true;
        }

        let name = match typ.split_once(":") {
            Some((_, n)) => n,
            None => typ,
        };

        let Some(parent) = self.import_map.get(name) else {
            return false;
        };
        if let Some(p) = &parent.base_type {
            self.is_extension_object(p)
        } else {
            false
        }
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
                crate::StructureFieldType::Field(f) => syn::parse_str(&self.get_type_path(f))?,
                crate::StructureFieldType::Array(f) => {
                    let path: Path = syn::parse_str(&self.get_type_path(f))?;
                    parse_quote! { Option<Vec<#path>> }
                }
            };
            let (ident, changed) = safe_ident(&field.name);
            let mut attrs = quote! {};
            if changed {
                let orig = &field.original_name;
                attrs = quote! {
                    #[cfg_attr(any(feature = "json", feature = "xml"), opcua(rename = #orig))]
                };
            }
            fields.push(parse_quote! {
                #attrs
                pub #ident: #typ
            });
        }

        let mut encoding_ids = None;
        // Generate impls
        // Has message info
        if item
            .base_type
            .as_ref()
            .is_some_and(|v| self.is_extension_object(v))
        {
            let (encoding_ident, _) = safe_ident(&format!("{}_Encoding_DefaultBinary", item.name));
            let (json_encoding_ident, _) =
                safe_ident(&format!("{}_Encoding_DefaultJson", item.name));
            let (xml_encoding_ident, _) = safe_ident(&format!("{}_Encoding_DefaultXml", item.name));
            let (data_type_ident, _) = safe_ident(&item.name);
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
                            let id: opcua::types::NodeId = crate::ObjectId::#encoding_ident.into();
                            opcua::types::ExpandedNodeId::from((id, #namespace))
                        }
                        fn full_json_type_id(&self) -> opcua::types::ExpandedNodeId {
                            let id: opcua::types::NodeId = crate::ObjectId::#json_encoding_ident.into();
                            opcua::types::ExpandedNodeId::from((id, #namespace))
                        }
                        fn full_xml_type_id(&self) -> opcua::types::ExpandedNodeId {
                            let id: opcua::types::NodeId = crate::ObjectId::#xml_encoding_ident.into();
                            opcua::types::ExpandedNodeId::from((id, #namespace))
                        }
                        fn full_data_type_id(&self) -> opcua::types::ExpandedNodeId {
                            let id: opcua::types::NodeId = crate::DataTypeId::#data_type_ident.into();
                            opcua::types::ExpandedNodeId::from((id, #namespace))
                        }
                    }
                });
            }

            encoding_ids = Some(EncodingIds::new(&item.name));
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
