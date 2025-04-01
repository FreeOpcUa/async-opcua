use std::{fmt::Display, sync::LazyLock};

use base64::Engine;
use proc_macro2::TokenStream;
use quote::quote;
use regex::Regex;
use uuid::Uuid;

use crate::CodeGenError;

use super::RenderExpr;

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub enum NodeIdVariant {
    Numeric(u32),
    String(String),
    Guid(Uuid),
    ByteString(Vec<u8>),
}

impl Display for NodeIdVariant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NodeIdVariant::Numeric(i) => write!(f, "i={}", i),
            NodeIdVariant::String(s) => write!(f, "s={}", s),
            NodeIdVariant::Guid(g) => write!(f, "g={}", g),
            NodeIdVariant::ByteString(b) => {
                let b64 = base64::engine::general_purpose::STANDARD.encode(b);
                write!(f, "b={}", b64)
            }
        }
    }
}

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct ParsedNodeId {
    pub value: NodeIdVariant,
    pub namespace: u16,
}

impl Display for ParsedNodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.namespace != 0 {
            write!(f, "ns={};", self.namespace)?;
        }
        write!(f, "{}", self.value)
    }
}

static NODEID_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(ns=(?P<ns>[0-9]+);)?(?P<t>[isgb]=.+)$").unwrap());

impl ParsedNodeId {
    pub fn parse(id: &str) -> Result<Self, CodeGenError> {
        let captures = NODEID_REGEX
            .captures(id)
            .ok_or_else(|| CodeGenError::other(format!("Invalid nodeId: {}", id)))?;
        let namespace = if let Some(ns) = captures.name("ns") {
            ns.as_str()
                .parse::<u16>()
                .map_err(|_| CodeGenError::other(format!("Invalid nodeId: {}", id)))?
        } else {
            0
        };

        let t = captures.name("t").unwrap();
        let idf = t.as_str();
        if idf.len() < 2 {
            Err(CodeGenError::other(format!("Invalid nodeId: {}", id)))?;
        }
        let k = &idf[..2];
        let v = &idf[2..];

        let variant = match k {
            "i=" => {
                let i = v
                    .parse::<u32>()
                    .map_err(|_| CodeGenError::other(format!("Invalid nodeId: {}", id)))?;
                NodeIdVariant::Numeric(i)
            }
            "s=" => NodeIdVariant::String(v.to_owned()),
            "g=" => {
                let uuid = Uuid::parse_str(v)
                    .map_err(|e| CodeGenError::other(format!("Invalid nodeId: {}, {e}", id)))?;
                NodeIdVariant::Guid(uuid)
            }
            "b=" => {
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(v)
                    .map_err(|e| CodeGenError::other(format!("Invalid nodeId: {}, {e}", id)))?;
                NodeIdVariant::ByteString(bytes)
            }
            _ => return Err(CodeGenError::other(format!("Invalid nodeId: {}", id)))?,
        };
        Ok(Self {
            value: variant,
            namespace,
        })
    }
}

impl RenderExpr for opcua_xml::schema::ua_node_set::NodeId {
    fn render(&self) -> Result<TokenStream, CodeGenError> {
        let id = &self.0;
        let ParsedNodeId { value, namespace } = ParsedNodeId::parse(id)?;

        // Do as much parsing as possible here, to optimize performance and get the errors as early as possible.
        let id_item = value.render()?;

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

impl RenderExpr for NodeIdVariant {
    fn render(&self) -> Result<TokenStream, CodeGenError> {
        Ok(match self {
            NodeIdVariant::Numeric(i) => quote! { #i },
            NodeIdVariant::String(s) => quote! { #s },
            NodeIdVariant::ByteString(b) => {
                quote! { opcua::types::ByteString::from(vec![#(#b)*,]) }
            }
            NodeIdVariant::Guid(g) => {
                let bytes = g.as_bytes();
                quote! { opcua::types::Guid::from_slice(&[#(#bytes)*,]).unwrap() }
            }
        })
    }
}
