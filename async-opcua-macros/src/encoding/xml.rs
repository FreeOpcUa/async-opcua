use convert_case::{Case, Casing};
use proc_macro2::TokenStream;

use quote::quote;

use super::{enums::SimpleEnum, EncodingStruct};

pub fn generate_xml_impl(strct: EncodingStruct) -> syn::Result<TokenStream> {
    let ident = strct.ident;
    let mut body = quote! {};
    let mut build = quote! {};
    for field in strct.fields {
        let name = field
            .attr
            .rename
            .unwrap_or_else(|| field.ident.to_string().to_case(Case::Pascal));
        let ident = field.ident;
        body.extend(quote! {
            let #ident = opcua::types::xml::XmlField::get_xml_field(element, #name, ctx)?;
        });
        build.extend(quote! {
            #ident,
        });
    }
    Ok(quote! {
        impl opcua::types::xml::FromXml for #ident {
            fn from_xml<'a>(
                element: &opcua::types::xml::XmlElement,
                ctx: &opcua::types::Context<'a>
            ) -> Result<Self, opcua::types::Error> {
                #body
                Ok(Self {
                    #build
                })
            }
        }
    })
}

pub fn generate_simple_enum_xml_impl(en: SimpleEnum) -> syn::Result<TokenStream> {
    let ident = en.ident;
    let repr = en.repr;

    Ok(quote! {
        impl opcua::types::xml::FromXml for #ident {
            fn from_xml<'a>(
                element: &opcua::types::xml::XmlElement,
                ctx: &opcua::types::Context<'a>
            ) -> Result<Self, opcua::types::Error> {
                let val = #repr::from_xml(element, ctx)?;
                Self::try_from(val).map_err(opcua::types::Error::decoding)
            }
        }
    })
}
