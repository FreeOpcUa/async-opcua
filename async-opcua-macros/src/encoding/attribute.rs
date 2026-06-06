use syn::{parse::Parse, Ident, LitStr, Token};

use crate::utils::ItemAttr;

#[derive(Debug, Default)]
pub(crate) struct EncodingFieldAttribute {
    pub rename: Option<String>,
    pub ignore: bool,
    pub no_default: bool,
    pub optional: bool,
}

impl Parse for EncodingFieldAttribute {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        let mut slf = Self::default();

        loop {
            let ident: Ident = input.parse()?;
            match ident.to_string().as_str() {
                "rename" => {
                    input.parse::<Token![=]>()?;
                    let val: LitStr = input.parse()?;
                    slf.rename = Some(val.value());
                }
                "ignore" => {
                    slf.ignore = true;
                }
                "no_default" => {
                    slf.no_default = true;
                }
                "optional" => {
                    slf.optional = true;
                }
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

impl ItemAttr for EncodingFieldAttribute {
    fn combine(&mut self, other: Self) {
        self.rename = other.rename;
        self.ignore |= other.ignore;
        self.no_default |= other.no_default;
        self.optional |= other.optional;
    }
}

#[derive(Debug, Default)]
pub(crate) struct EncodingVariantAttribute {
    pub rename: Option<String>,
    pub default: bool,
}

impl ItemAttr for EncodingVariantAttribute {
    fn combine(&mut self, other: Self) {
        self.rename = other.rename;
        self.default |= other.default;
    }
}

impl Parse for EncodingVariantAttribute {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        let mut slf = Self::default();

        loop {
            let ident: Ident = input.parse()?;
            match ident.to_string().as_str() {
                "rename" => {
                    input.parse::<Token![=]>()?;
                    let val: LitStr = input.parse()?;
                    slf.rename = Some(val.value());
                }
                "default" => {
                    slf.default = true;
                }
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

#[derive(Debug, Default)]
pub(crate) struct EncodingItemAttribute {
    #[allow(unused)]
    pub(crate) rename: Option<String>,
}

impl ItemAttr for EncodingItemAttribute {
    fn combine(&mut self, other: Self) {
        self.rename = other.rename;
    }
}

impl Parse for EncodingItemAttribute {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        let mut slf = Self::default();

        loop {
            let ident: Ident = input.parse()?;
            match ident.to_string().as_str() {
                "rename" => {
                    input.parse::<Token![=]>()?;
                    let val: LitStr = input.parse()?;
                    slf.rename = Some(val.value());
                }
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
