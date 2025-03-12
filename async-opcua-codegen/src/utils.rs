use std::{fmt::Display, sync::OnceLock};

use base64::Engine;
use proc_macro2::{Span, TokenStream};
use regex::Regex;
use syn::{parse_quote, File, Ident};
use uuid::Uuid;

use crate::CodeGenError;

pub fn create_module_file(modules: Vec<String>) -> File {
    let mut items = Vec::new();
    for md in modules {
        let ident = Ident::new(&md, Span::call_site());
        items.push(parse_quote! {
            pub mod #ident;
        });
        items.push(parse_quote! {
            pub use #ident::*;
        });
    }

    File {
        shebang: None,
        attrs: Vec::new(),
        items,
    }
}

pub trait GeneratedOutput {
    fn to_file(self) -> File;

    fn module(&self) -> &str;

    fn name(&self) -> &str;
}

pub trait RenderExpr {
    fn render(&self) -> Result<TokenStream, CodeGenError>;
}

impl<T> RenderExpr for Option<&T>
where
    T: RenderExpr,
{
    fn render(&self) -> Result<TokenStream, CodeGenError> {
        Ok(match self {
            Some(t) => {
                let rendered = t.render()?;
                parse_quote! {
                    Some(#rendered)
                }
            }
            None => parse_quote! { None },
        })
    }
}

pub fn safe_ident(val: &str) -> (Ident, bool) {
    let mut val = val.to_string();
    let mut changed = false;
    if val.starts_with(['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']) || val == "type" {
        val = format!("__{val}");
        changed = true;
    }

    (Ident::new(&val, Span::call_site()), changed)
}

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

static NODEID_REGEX: OnceLock<Regex> = OnceLock::new();

fn nodeid_regex() -> &'static Regex {
    NODEID_REGEX.get_or_init(|| Regex::new(r"^(ns=(?P<ns>[0-9]+);)?(?P<t>[isgb]=.+)$").unwrap())
}

impl ParsedNodeId {
    pub fn parse(id: &str) -> Result<Self, CodeGenError> {
        let captures = nodeid_regex()
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

static QUALIFIED_NAME_REGEX: OnceLock<Regex> = OnceLock::new();

fn qualified_name_regex() -> &'static Regex {
    QUALIFIED_NAME_REGEX.get_or_init(|| Regex::new(r"^((?P<ns>[0-9]+):)?(?P<name>.*)$").unwrap())
}

pub fn split_qualified_name(name: &str) -> Result<(&str, u16), CodeGenError> {
    let captures = qualified_name_regex()
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
