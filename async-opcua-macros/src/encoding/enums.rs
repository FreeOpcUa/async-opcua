use proc_macro2::TokenStream;
use syn::{Attribute, DataEnum, Ident, LitInt, Type, Variant};

use crate::utils::ItemAttr;
use quote::{quote, ToTokens};

use super::attribute::{EncodingItemAttribute, EncodingVariantAttribute};

pub struct SimpleEnumVariant {
    pub value: LitInt,
    pub name: Ident,
    pub attr: EncodingVariantAttribute,
}

pub struct SimpleEnum {
    pub repr: Type,
    pub variants: Vec<SimpleEnumVariant>,
    pub ident: Ident,
    #[allow(unused)]
    pub attr: EncodingItemAttribute,
}

impl SimpleEnumVariant {
    pub fn from_variant(variant: Variant) -> syn::Result<Self> {
        let Some((_, value)) = variant.discriminant else {
            return Err(syn::Error::new_spanned(
                variant,
                "Enum variant must have explicit discriminant",
            ));
        };
        let value = syn::parse2(value.into_token_stream())?;
        if !variant.fields.is_empty() {
            return Err(syn::Error::new_spanned(
                variant.fields,
                "Macro not applicable to enums with content",
            ));
        }
        let mut final_attr = EncodingVariantAttribute::default();
        for attr in variant.attrs {
            if attr.path().segments.len() == 1
                && attr
                    .path()
                    .segments
                    .first()
                    .is_some_and(|s| s.ident == "opcua")
            {
                let data: EncodingVariantAttribute = attr.parse_args()?;
                final_attr.combine(data);
            }
        }
        Ok(Self {
            value,
            name: variant.ident,
            attr: final_attr,
        })
    }
}

impl SimpleEnum {
    pub fn from_input(
        input: DataEnum,
        attributes: Vec<Attribute>,
        ident: Ident,
    ) -> syn::Result<Self> {
        let variants = input
            .variants
            .into_iter()
            .map(SimpleEnumVariant::from_variant)
            .collect::<Result<Vec<_>, _>>()?;

        let mut repr: Option<Type> = None;
        let mut final_attr = EncodingItemAttribute::default();
        for attr in attributes {
            if attr.path().segments.len() != 1 {
                continue;
            }
            let seg = attr.path().segments.first();
            if seg.is_some_and(|s| s.ident == "repr") {
                repr = Some(attr.parse_args()?);
            }
            if seg.is_some_and(|s| s.ident == "opcua") {
                let data: EncodingItemAttribute = attr.parse_args()?;
                final_attr.combine(data);
            }
        }

        let Some(repr) = repr else {
            return Err(syn::Error::new_spanned(
                ident,
                "Enum must be annotated with an explicit #[repr(...)] attribute",
            ));
        };

        Ok(Self {
            repr,
            variants,
            ident,
            attr: final_attr,
        })
    }
}

pub fn derive_ua_enum_impl(en: SimpleEnum) -> syn::Result<TokenStream> {
    let ident = en.ident;
    let repr = en.repr;

    let mut try_from_arms = quote! {};
    let mut as_str_arms = quote! {};
    let mut from_str_arms = quote! {};
    let mut default_ident: Option<Ident> = None;

    for variant in en.variants {
        if variant.attr.default {
            if default_ident.is_some() {
                return Err(syn::Error::new_spanned(
                    variant.name,
                    "Enum may only have one default variant",
                ));
            }

            default_ident = Some(variant.name.clone());
        }

        let val = variant.value;
        let name = variant.name;
        let name_str = if let Some(rename) = variant.attr.rename {
            format!("{}_{}", rename, val.base10_digits())
        } else {
            format!("{}_{}", name, val.base10_digits())
        };
        try_from_arms.extend(quote! {
            #val => Self::#name,
        });
        as_str_arms.extend(quote! {
            Self::#name => #name_str,
        });
        from_str_arms.extend(quote! {
            #name_str => Self::#name,
        });
    }

    let error_msg = format!("Got unexpected value for enum {}: {{}}", ident);

    let default_impl = if let Some(default_ident) = default_ident {
        quote! {
            impl Default for #ident {
                fn default() -> Self {
                    Self::#default_ident
                }
            }
        }
    } else {
        quote! {}
    };

    Ok(quote! {
        impl From<#ident> for #repr {
            fn from(value: #ident) -> #repr {
                value as #repr
            }
        }

        #default_impl

        impl opcua::types::IntoVariant for #ident {
            fn into_variant(self) -> opcua::types::Variant {
                (self as #repr).into_variant()
            }
        }

        impl TryFrom<#repr> for #ident {
            type Error = opcua::types::Error;
            fn try_from(value: #repr) -> Result<Self, opcua::types::Error> {
                Ok(match value {
                    #try_from_arms
                    r => {
                        return Err(opcua::types::Error::decoding(format!(
                            #error_msg, r
                        )))
                    }
                })
            }
        }

        impl opcua::types::UaEnum for #ident {
            type Repr = #repr;

            fn from_repr(repr: Self::Repr) -> Result<Self, opcua::types::Error> {
                Self::try_from(repr)
            }

            fn into_repr(self) -> Self::Repr {
                self.into()
            }

            fn as_str(&self) -> &'static str {
                match self {
                    #as_str_arms
                }
            }

            fn from_str(val: &str) -> Result<Self, opcua::types::Error> {
                Ok(match val {
                    #from_str_arms
                    r => {
                        return Err(opcua::types::Error::decoding(format!(
                            #error_msg, r
                        )))
                    }
                })
            }
        }
    })
}
