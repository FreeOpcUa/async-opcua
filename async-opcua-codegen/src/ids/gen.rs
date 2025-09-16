use std::{
    collections::HashMap,
    fs::File,
    io::{BufRead, BufReader},
};

use proc_macro2::Span;
use quote::quote;
use syn::{parse_quote, Ident, Item};

use crate::{utils::safe_ident, CodeGenError};

pub struct IdItem {
    pub name: String,
    pub variants: Vec<(u32, String)>,
}

impl IdItem {
    pub fn new(it: &str) -> Self {
        Self {
            name: it.to_owned(),
            variants: Vec::new(),
        }
    }
}

/// Parse a node ID CSV file. The file can have either two or three columns,
/// with values [name, id] or [name, id, type].
/// If it has two columns, the type name must be provided externally as a fallback.
pub fn parse(
    file: File,
    file_name: &str,
    type_name: Option<&str>,
) -> Result<HashMap<String, IdItem>, CodeGenError> {
    let mut types = HashMap::new();
    for line in BufReader::new(file).lines() {
        let line = line.map_err(|e| CodeGenError::io("Failed to read lines from file", e))?;
        let vals: Vec<_> = line.split(",").collect();
        if vals.len() == 2 {
            let Some(type_name) = type_name else {
                return Err(CodeGenError::other(format!("CSV file {file_name} has only two columns, but no type name fallback was specified")));
            };
            types
                .entry(type_name.to_owned())
                .or_insert_with(|| IdItem::new(type_name))
                .variants
                .push((vals[1].parse()?, vals[0].to_owned()));
        } else if vals.len() == 3 {
            let type_name = vals[2].to_owned();
            types
                .entry(type_name.clone())
                .or_insert_with(|| IdItem::new(&type_name))
                .variants
                .push((vals[1].parse()?, vals[0].to_owned()));
        } else {
            return Err(CodeGenError::other(format!(
                "CSV file {file_name} is on incorrect format. Expected two or three columns, got {}",
                vals.len()
            )));
        }
    }

    Ok(types)
}

/// Render a node ID enum from an IdItem.
pub fn render(item: IdItem) -> Result<Vec<Item>, CodeGenError> {
    let mut items = Vec::new();
    let mut vs = quote! {};
    let mut from_arms = quote! {};
    for (val, key) in item.variants {
        let (idt, _) = safe_ident(&key);
        vs.extend(quote! { #idt = #val, });
        from_arms.extend(quote! { #val => Self::#idt, });
    }

    let name = Ident::new(&format!("{}Id", item.name), Span::call_site());

    items.push(Item::Enum(parse_quote! {
        #[allow(non_camel_case_types, clippy::enum_variant_names)]
        #[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
        #[repr(u32)]
        pub enum #name {
            #vs
        }
    }));

    items.push(Item::Impl(parse_quote! {
        impl<'a> From<&'a #name> for opcua::types::NodeId {
            fn from(r: &'a #name) -> Self {
                opcua::types::NodeId::new(0, *r as u32)
            }
        }
    }));

    items.push(Item::Impl(parse_quote! {
        impl From<#name> for opcua::types::NodeId {
            fn from(r: #name) -> Self {
                opcua::types::NodeId::new(0, r as u32)
            }
        }
    }));

    items.push(Item::Impl(parse_quote! {
        impl From<#name> for opcua::types::ExpandedNodeId {
            fn from(r: #name) -> Self {
                Self {
                    node_id: opcua::types::NodeId::new(0, r as u32),
                    namespace_uri: Default::default(),
                    server_index: 0,
                }
            }
        }
    }));

    items.push(Item::Impl(parse_quote! {
        impl TryFrom<u32> for #name {
            type Error = ();

            fn try_from(value: u32) -> Result<Self, Self::Error> {
                Ok(match value {
                    #from_arms
                    _ => return Err(()),
                })
            }
        }
    }));

    Ok(items)
}
