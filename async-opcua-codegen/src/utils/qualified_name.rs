use std::sync::LazyLock;

use proc_macro2::TokenStream;
use regex::Regex;

use crate::CodeGenError;

use quote::quote;

use super::RenderExpr;

static QUALIFIED_NAME_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^((?P<ns>[0-9]+):)?(?P<name>.*)$").unwrap());

pub fn split_qualified_name(name: &str) -> Result<(&str, u16), CodeGenError> {
    let captures = QUALIFIED_NAME_REGEX
        .captures(name)
        .ok_or_else(|| CodeGenError::other(format!("Invalid qualifiedname: {}", name)))?;

    let namespace = if let Some(ns) = captures.name("ns") {
        ns.as_str()
            .parse::<u16>()
            .map_err(|_| CodeGenError::other(format!("Invalid nodeId: {}", name)))?
    } else {
        0
    };

    Ok((captures.name("name").unwrap().as_str(), namespace))
}

impl RenderExpr for opcua_xml::schema::ua_node_set::QualifiedName {
    fn render(&self) -> Result<TokenStream, CodeGenError> {
        let name = &self.0;
        let (name, namespace) = split_qualified_name(name)?;

        let ns_item = if namespace == 0 {
            quote! { 0u16 }
        } else {
            quote! {
                ns_map.get_index(#namespace).unwrap()
            }
        };

        Ok(quote! {
            opcua::types::QualifiedName::new(#ns_item, #name)
        })
    }
}
