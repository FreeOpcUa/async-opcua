use std::str::FromStr;

use base64::Engine;
use syn::{parse::Parse, DeriveInput, Ident, LitStr, Token, Type};
use uuid::Uuid;

use crate::utils::{expect_struct, ItemAttr, StructItem};

#[derive(Default, Debug)]
pub(super) struct EventFieldAttribute {
    pub ignore: bool,
    pub rename: Option<String>,
    pub placeholder: bool,
}

impl Parse for EventFieldAttribute {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        let mut slf = Self::default();
        loop {
            let ident: Ident = input.parse()?;
            match ident.to_string().as_str() {
                "ignore" => slf.ignore = true,
                "rename" => {
                    input.parse::<Token![=]>()?;
                    let val: LitStr = input.parse()?;
                    slf.rename = Some(val.value());
                }
                "placeholder" => slf.placeholder = true,
                _ => return Err(syn::Error::new_spanned(ident, "Unknown attribute value")),
            }
            if !input.peek(Token![,]) {
                break;
            }
            input.parse::<Token![,]>()?;
        }
        Ok(slf)
    }
}

impl ItemAttr for EventFieldAttribute {
    fn combine(&mut self, other: Self) {
        self.ignore |= other.ignore;
        self.placeholder |= other.placeholder;
        if other.rename.is_some() {
            self.rename = other.rename.clone();
        }
    }
}

pub(super) enum Identifier {
    Number(u32),
    String(String),
    Guid(Uuid),
    ByteString(Vec<u8>),
}

impl FromStr for Identifier {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() < 3 {
            return Err("Identifier not on form i=..., s=..., g=..., or o=...".to_owned());
        }

        let start = &s[0..2];
        let rest = &s[2..];
        Ok(match start {
            "i=" => Identifier::Number(
                rest.parse()
                    .map_err(|e| format!("Invalid identifier: {e}"))?,
            ),
            "s=" => Identifier::String(rest.to_owned()),
            "g=" => Identifier::Guid(
                uuid::Uuid::parse_str(rest).map_err(|e| format!("Invalid identfier: {e}"))?,
            ),
            "o=" => Identifier::ByteString(
                base64::engine::general_purpose::STANDARD
                    .decode(rest)
                    .map_err(|e| format!("Invalid identfier: {e}"))?,
            ),
            _ => return Err("Identifier not on form i=..., s=..., g=..., or o=...".to_owned()),
        })
    }
}

#[derive(Default)]
pub(super) struct EventAttribute {
    pub identifier: Option<Identifier>,
    pub namespace: Option<String>,
    pub base_type: Option<Type>,
}

impl Parse for EventAttribute {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        let mut idf: Option<Identifier> = None;
        let mut namespace: Option<String> = None;

        loop {
            let ident: Ident = input.parse()?;
            match ident.to_string().as_str() {
                "identifier" => {
                    input.parse::<Token![=]>()?;
                    let lit: LitStr = input.parse()?;
                    idf = Some(
                        Identifier::from_str(&lit.value())
                            .map_err(|e| syn::Error::new_spanned(lit, e))?,
                    );
                }
                "namespace" => {
                    input.parse::<Token![=]>()?;
                    let lit: LitStr = input.parse()?;
                    namespace = Some(lit.value().to_string())
                }
                _ => return Err(syn::Error::new_spanned(ident, "Unknown attribute value")),
            }
            if !input.peek(Token![,]) {
                break;
            }
            input.parse::<Token![,]>()?;
        }

        Ok(Self {
            identifier: idf,
            namespace,
            base_type: None,
        })
    }
}

impl ItemAttr for EventAttribute {
    fn combine(&mut self, other: Self) {
        self.identifier = other.identifier;
        self.namespace = other.namespace;
    }
}

pub(crate) type EventStruct = StructItem<EventFieldAttribute, EventAttribute>;

pub(crate) fn parse_event_struct(input: DeriveInput) -> syn::Result<EventStruct> {
    let mut parsed = EventStruct::from_input(expect_struct(input.data)?, input.attrs, input.ident)?;

    let mut filtered_fields = Vec::with_capacity(parsed.fields.len());

    let mut has_base = false;
    let mut has_own_idx = false;
    for field in parsed.fields.drain(..) {
        let name = field.ident.to_string();
        if name == "base" {
            has_base = true;
            parsed.attribute.base_type = Some(field.typ);
            continue;
        }
        if name == "own_namespace_index" {
            has_own_idx = true;
            continue;
        }
        filtered_fields.push(field);
    }

    parsed.fields = filtered_fields;

    if !has_base {
        return Err(syn::Error::new_spanned(
            parsed.ident,
            "Event must contain a field `base` that implements `Event`",
        ));
    }
    if !has_own_idx && parsed.attribute.namespace.is_some() {
        return Err(syn::Error::new_spanned(
            parsed.ident,
            "Event must contain a field `own_namespace_index` of type `u16`",
        ));
    }
    if has_own_idx && parsed.attribute.namespace.is_none() {
        return Err(syn::Error::new_spanned(
            parsed.ident,
        "Event must have an attribute #[opcua(namespace = ...)] to set a namespace other than 0")
        );
    }

    Ok(parsed)
}
