use opcua_xml::schema::ua_node_set::{LocalizedText, NodeId, QualifiedName};
use proc_macro2::TokenStream;
use quote::quote;
use syn::{parse_quote, Expr};

use crate::{
    utils::{split_qualified_name, NodeIdVariant, ParsedNodeId, RenderExpr},
    CodeGenError,
};

impl RenderExpr for LocalizedText {
    fn render(&self) -> Result<TokenStream, CodeGenError> {
        let locale = &self.locale.0;
        let text = &self.text;
        Ok(quote! {
            opcua::types::LocalizedText::new(#locale, #text)
        })
    }
}

impl RenderExpr for NodeId {
    fn render(&self) -> Result<TokenStream, CodeGenError> {
        let id = &self.0;
        let ParsedNodeId { value, namespace } = ParsedNodeId::parse(id)?;

        // Do as much parsing as possible here, to optimize performance and get the errors as early as possible.
        let id_item: Expr = match value {
            NodeIdVariant::Numeric(i) => parse_quote! { #i },
            NodeIdVariant::String(s) => parse_quote! { #s },
            NodeIdVariant::ByteString(b) => {
                parse_quote! { opcua::types::ByteString::from(vec![#(#b)*,]) }
            }
            NodeIdVariant::Guid(g) => {
                let bytes = g.as_bytes();
                parse_quote! { opcua::types::Guid::from_slice(&[#(#bytes)*,]).unwrap() }
            }
        };

        let ns_item = if namespace == 0 {
            quote! { 0u16 }
        } else {
            quote! {
                ns_map.get_index(#namespace).unwrap()
            }
        };

        Ok(quote! {
            opcua::types::NodeId::new(#ns_item, #id_item)
        })
    }
}

impl RenderExpr for QualifiedName {
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

impl RenderExpr for Vec<u32> {
    fn render(&self) -> Result<TokenStream, CodeGenError> {
        let r = self;
        Ok(quote! {
            vec![#(#r),*]
        })
    }
}

impl RenderExpr for f64 {
    fn render(&self) -> Result<TokenStream, CodeGenError> {
        let r = self;
        Ok(quote! {
            #r
        })
    }
}
