use syn::{Ident, Variant};

use crate::utils::ItemAttr;

use super::attribute::{EncodingItemAttribute, EncodingVariantAttribute};

pub struct AdvancedEnumVariant {
    pub name: Ident,
    #[allow(unused)]
    pub attr: EncodingVariantAttribute,
    pub is_null: bool,
}

pub struct AdvancedEnum {
    pub variants: Vec<AdvancedEnumVariant>,
    pub ident: Ident,
    pub null_variant: Option<Ident>,
    #[allow(unused)]
    pub attr: EncodingItemAttribute,
}

impl AdvancedEnumVariant {
    pub fn from_variant(variant: Variant) -> syn::Result<Self> {
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
        if variant.fields.len() > 1 {
            return Err(syn::Error::new_spanned(
                variant.fields,
                "Macro only applicable to enums with a single field in each variant",
            ));
        }

        let is_null = variant.fields.is_empty();

        Ok(Self {
            name: variant.ident,
            attr: final_attr,
            is_null,
        })
    }
}

impl AdvancedEnum {
    pub fn from_input(
        input: syn::DataEnum,
        attributes: Vec<syn::Attribute>,
        ident: Ident,
    ) -> syn::Result<Self> {
        let variants = input
            .variants
            .into_iter()
            .map(AdvancedEnumVariant::from_variant)
            .collect::<syn::Result<Vec<_>>>()?;

        let mut final_attr: EncodingItemAttribute = EncodingItemAttribute::default();
        for attr in attributes {
            if attr.path().segments.len() == 1
                && attr
                    .path()
                    .segments
                    .first()
                    .is_some_and(|s| s.ident == "opcua")
            {
                let data: EncodingItemAttribute = attr.parse_args()?;
                final_attr.combine(data);
            }
        }

        let mut null_variant = None;
        for vrt in &variants {
            if vrt.is_null {
                if null_variant.is_some() {
                    return Err(syn::Error::new_spanned(
                        &vrt.name,
                        "Unions may only have one null variant",
                    ));
                }
                null_variant = Some(vrt.name.clone());
            }
        }
        Ok(Self {
            variants,
            ident,
            null_variant,
            attr: final_attr,
        })
    }
}
