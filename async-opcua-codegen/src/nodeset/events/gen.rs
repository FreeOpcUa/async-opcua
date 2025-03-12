use std::collections::HashMap;

use convert_case::{Case, Casing};
use proc_macro2::{Span, TokenStream};
use quote::quote;
use syn::{parse_quote, Ident, ItemStruct, Path};

use crate::{
    utils::{safe_ident, ParsedNodeId},
    CodeGenError,
};

use super::collector::{CollectedType, FieldKind, TypeKind};

pub struct EventGenerator<'a> {
    types: HashMap<&'a str, CollectedType<'a>>,
    namespaces: &'a [String],
    type_mappings: HashMap<String, String>,
    nodeset_index: usize,
}

pub struct EventItem {
    pub def: ItemStruct,
    pub name: String,
}

impl<'a> EventGenerator<'a> {
    pub fn new(
        types: HashMap<&'a str, CollectedType<'a>>,
        namespaces: &'a [String],
        type_mappings: HashMap<String, String>,
        nodeset_index: usize,
    ) -> Self {
        Self {
            types,
            namespaces,
            type_mappings,
            nodeset_index,
        }
    }

    pub fn render(&self) -> Result<Vec<EventItem>, CodeGenError> {
        let mut collected = HashMap::new();
        for (ty, _) in self.types.iter().filter(|t| {
            matches!(t.1.kind, TypeKind::EventType) && t.1.nodeset_index == self.nodeset_index
        }) {
            self.add_type_to_render(ty, &mut collected);
        }

        let mut items = Vec::new();
        for (k, v) in collected {
            items.push(self.render_type(v, k)?);
        }

        Ok(items)
    }

    fn is_simple(&self, ty: &'a str) -> bool {
        let typ = self.types.get(ty).unwrap();
        if matches!(typ.kind, TypeKind::EventType) {
            return false;
        }
        typ.fields.is_empty()
            && (typ.parent.is_none() || typ.parent.is_some_and(|t| self.is_simple(t)))
    }

    fn add_type_to_render(&self, ty: &'a str, collected: &mut HashMap<&'a str, CollectedType<'a>>) {
        if collected.contains_key(ty) {
            return;
        }

        // Don't render the base event type.
        if ty == "i=2041" {
            return;
        }
        // Don't render simple types.
        if self.is_simple(ty) {
            return;
        }

        let typ = self.types.get(ty).unwrap();

        if typ.nodeset_index != self.nodeset_index {
            return;
        }

        collected.insert(ty, typ.clone());
        for field in typ.fields.values() {
            match field.type_id {
                FieldKind::Object(r) | FieldKind::Variable(r) => {
                    self.add_type_to_render(r, collected);
                }
                FieldKind::Method => (),
            }
        }

        if let Some(parent) = typ.parent {
            self.add_type_to_render(parent, collected);
        }
    }

    fn render_type(&self, ty: CollectedType<'a>, id: &'a str) -> Result<EventItem, CodeGenError> {
        match &ty.kind {
            TypeKind::EventType => self.render_event(&ty, id),
            TypeKind::ObjectType => self.render_object_type(&ty),
            TypeKind::VariableType => self.render_variable_type(&ty),
            r => Err(CodeGenError::other(format!(
                "Got unexpected type kind to render: {r:?}"
            ))),
        }
        .map_err(|e| e.with_context(format!("rendering type {}", ty.name)))
    }

    fn get_data_type(&self, data_type_id: &str) -> Result<TokenStream, CodeGenError> {
        let Some(data_type) = self.types.get(data_type_id) else {
            return Err(CodeGenError::other(format!(
                "Data type {data_type_id} not found for variable"
            )));
        };
        if data_type.is_abstract {
            Ok(quote! {
                opcua::types::ExtensionObject
            })
        } else if data_type_id == "i=24" {
            let ident = Ident::new("Variant", Span::call_site());
            Ok(quote! {
                types::#ident
            })
        } else if let Some(mapped) = self.type_mappings.get(data_type.name) {
            if mapped == "UAString" {
                Ok(quote! {
                    opcua::types::UAString
                })
            } else {
                let ident = Ident::new(mapped, Span::call_site());
                Ok(quote! {
                    #ident
                })
            }
        } else {
            let ident = Ident::new(data_type.name, Span::call_site());
            Ok(quote! {
                types::#ident
            })
        }
    }

    fn render_fields(
        &self,
        ty: &CollectedType<'a>,
        fields: &mut TokenStream,
    ) -> Result<(), CodeGenError> {
        let mut item_fields: Vec<_> = ty.fields.iter().collect();
        item_fields.sort_by(|a, b| a.0.cmp(b.0));
        for (key, field) in item_fields {
            let typ = match field.type_id {
                FieldKind::Object(v) => {
                    let typ = self.types.get(v).unwrap();
                    let typ_ident = safe_ident(typ.name).0;
                    syn::parse_str(&format!("{}{}", typ.import_path, typ_ident))?
                }
                FieldKind::Variable(v) => {
                    let typ = self.types.get(v).unwrap();
                    if self.is_simple(v) {
                        let data_type_id = field.data_type_id.ok_or_else(|| {
                            CodeGenError::other(format!("Missing valid data type for variable {v}"))
                        })?;

                        self.get_data_type(data_type_id)?
                    } else {
                        let typ_ident = safe_ident(typ.name).0;
                        syn::parse_str(&format!("{}{}", typ.import_path, typ_ident))?
                    }
                }
                FieldKind::Method => {
                    quote! {
                        opcua::nodes::MethodEventField
                    }
                }
            };

            let (name, renamed) = if field.placeholder {
                // Sanitize placeholder name.
                let key = format!(
                    "{}s",
                    key.trim_start_matches('<')
                        .trim_end_matches(">")
                        .to_case(Case::Snake)
                );
                safe_ident(&key)
            } else {
                safe_ident(&key.to_case(Case::Snake))
            };

            if field.placeholder {
                fields.extend(quote! {
                    #[opcua(placeholder)]
                    pub #name: opcua::types::PlaceholderEventField<#typ>,
                });
            } else {
                if renamed {
                    fields.extend(quote! {
                        #[opcua(rename = #key)]
                    });
                }
                fields.extend(quote! {
                    pub #name: #typ,
                });
            }
        }

        Ok(())
    }

    fn render_object_type(&self, ty: &CollectedType<'a>) -> Result<EventItem, CodeGenError> {
        let mut fields = quote! {};
        if let Some(parent) = ty.parent {
            if !self.is_simple(parent) {
                let parent_typ = self.types.get(parent).unwrap();
                let parent_ident = safe_ident(parent_typ.name).0;
                let parent_path: Path =
                    syn::parse_str(&format!("{}{}", parent_typ.import_path, parent_ident))?;

                fields.extend(quote! {
                    pub base: #parent_path,
                });
            }
        }

        fields.extend(quote! {
            pub node_id: opcua::types::NodeId,
        });
        self.render_fields(ty, &mut fields)?;

        let ident = Ident::new(ty.name, Span::call_site());

        Ok(EventItem {
            def: parse_quote! {
                #[derive(Debug, opcua::EventField, Default)]
                pub struct #ident {
                    #fields
                }
            },
            name: ty.name.to_owned(),
        })
    }

    fn render_variable_type(&self, ty: &CollectedType<'a>) -> Result<EventItem, CodeGenError> {
        let mut fields = quote! {};
        let mut value_in_parent = false;
        if let Some(parent) = ty.parent {
            if !self.is_simple(parent) {
                let parent_typ = self.types.get(parent).unwrap();
                let parent_ident = safe_ident(parent_typ.name).0;
                let parent_path: Path =
                    syn::parse_str(&format!("{}{}", parent_typ.import_path, parent_ident))?;
                fields.extend(quote! {
                    pub base: #parent_path,
                });
                value_in_parent = true;
            }
        }
        fields.extend(quote! {
            pub node_id: opcua::types::NodeId,
        });

        let ident = Ident::new(ty.name, Span::call_site());

        if !value_in_parent {
            let data_type_id = ty.data_type_id.ok_or_else(|| {
                CodeGenError::other(format!(
                    "Missing valid data type for variable type {}",
                    ty.name
                ))
            })?;
            let data_type_ident = self.get_data_type(data_type_id)?;

            fields.extend(quote! {
                pub value: #data_type_ident,
            })
        }

        self.render_fields(ty, &mut fields)?;

        Ok(EventItem {
            def: parse_quote! {
                #[derive(Debug, opcua::EventField, Default)]
                pub struct #ident {
                    #fields
                }
            },
            name: ty.name.to_owned(),
        })
    }

    fn render_event(&self, ty: &CollectedType<'a>, id: &'a str) -> Result<EventItem, CodeGenError> {
        let mut fields = quote! {};
        // Events always have a parent.
        let parent = ty.parent.unwrap();
        if parent == "i=2041" {
            fields.extend(quote! {
                pub base: opcua::nodes::BaseEventType,
            });
        } else {
            let parent_typ = self.types.get(parent).unwrap();
            let parent_ident = safe_ident(parent_typ.name).0;
            let parent_path: Path =
                syn::parse_str(&format!("{}{}", parent_typ.import_path, parent_ident))?;
            fields.extend(quote! {
                pub base: #parent_path,
            });
        }

        let parsed = ParsedNodeId::parse(id)?;
        let identifier = parsed.value.to_string();
        let opcua_attr = if parsed.namespace > 0 {
            let namespace_uri =
                self.namespaces
                    .get(parsed.namespace as usize)
                    .ok_or_else(|| {
                        CodeGenError::other(format!(
                            "Namespace index {} is out of range of provided namespace table",
                            parsed.namespace
                        ))
                    })?;
            fields.extend(quote! {
                pub own_namespace_index: u16,
            });
            quote! {
                #[opcua(identifier = #identifier, namespace = #namespace_uri)]
            }
        } else {
            quote! {
                #[opcua(identifier = #identifier)]
            }
        };
        self.render_fields(ty, &mut fields)?;

        let ident = Ident::new(ty.name, Span::call_site());

        Ok(EventItem {
            def: parse_quote! {
                #[derive(Debug, opcua::Event)]
                #opcua_attr
                pub struct #ident {
                    #fields
                }
            },
            name: ty.name.to_owned(),
        })
    }
}
