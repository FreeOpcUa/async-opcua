use convert_case::{Case, Casing};
use proc_macro2::{Span, TokenStream};
use syn::Ident;

use quote::quote;

use super::{attribute::EncodingItemAttribute, enums::SimpleEnum, EncodingStruct};

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

pub fn generate_xml_encode_impl(strct: EncodingStruct) -> syn::Result<TokenStream> {
    let ident = strct.ident;
    let mut body = quote! {
        use opcua::types::xml::XmlWriteExt;
    };

    let any_optional = strct
        .fields
        .iter()
        .any(|f| f.attr.optional && !f.attr.ignore);

    if any_optional {
        let mut optional_index = 0;
        body.extend(quote! {
            let mut encoding_mask = 0u32;
        });
        for field in &strct.fields {
            if !field.attr.optional || field.attr.ignore {
                continue;
            }
            let ident = &field.ident;
            body.extend(quote! {
                if self.#ident.as_ref().is_some() {
                    encoding_mask |= 1 << #optional_index;
                }
            });
            optional_index += 1;
        }
        body.extend(quote! {
            stream.encode_child("EncodingMask", &encoding_mask, ctx)?;
        });
    }

    for field in strct.fields {
        if field.attr.ignore {
            continue;
        }

        let name = field
            .attr
            .rename
            .unwrap_or_else(|| field.ident.to_string().to_case(Case::Pascal));

        let ident = field.ident;
        if field.attr.optional {
            body.extend(quote! {
                if let Some(item) = &self.#ident {
                    stream.encode_child(#name, item, ctx)?;
                }
            });
        } else {
            body.extend(quote! {
                stream.encode_child(#name, &self.#ident, ctx)?;
            });
        }
    }

    Ok(quote! {
        impl opcua::types::xml::XmlEncodable for #ident {
            fn encode(
                &self,
                stream: &mut opcua::types::xml::XmlStreamWriter<&mut dyn std::io::Write>,
                ctx: &opcua::types::Context<'_>,
            ) -> opcua::types::EncodingResult<()> {
                #body
                Ok(())
            }
        }
    })
}

pub fn generate_xml_decode_impl(strct: EncodingStruct) -> syn::Result<TokenStream> {
    let ident = strct.ident;
    let mut items = quote! {};
    let mut items_match = quote! {};
    let mut build = quote! {};

    let has_header = strct.fields.iter().any(|i| {
        matches!(
            i.ident.to_string().as_str(),
            "request_header" | "response_header"
        )
    });

    if has_header {
        items.extend(quote! {
            let mut __request_handle = None;
        });
    }

    for field in strct.fields {
        if field.attr.ignore {
            let ident = field.ident;

            build.extend(quote! {
                #ident: Default::default(),
            });
            continue;
        }

        let name = field
            .attr
            .rename
            .unwrap_or_else(|| field.ident.to_string().to_case(Case::Pascal));
        let is_header = matches!(name.as_str(), "RequestHeader" | "ResponseHeader");

        let ident = field.ident;
        items.extend(quote! {
            let mut #ident = None;
        });
        if is_header {
            let ty = Ident::new(&name, Span::call_site());
            items_match.extend(quote! {
                #name => {
                    let __header: opcua::types::#ty = opcua::types::xml::XmlDecodable::decode(stream, ctx)?;
                    __request_handle = Some(__header.request_handle);
                }
            });
        } else if has_header {
            items_match.extend(quote! {
                #name => {
                    #ident = Some(opcua::types::xml::XmlDecodable::decode(stream, ctx)
                        .map_err(|e| e.maybe_with_request_handle(__request_handle))?);
                }
            });
        } else {
            items_match.extend(quote! {
                #name => {
                    #ident = Some(opcua::types::xml::XmlDecodable::decode(stream, ctx)?);
                }
            });
        }

        if field.attr.no_default {
            let err = format!("Missing required field {name}");
            let handle = if has_header {
                quote! {
                    .map_err(|e| e.maybe_with_request_handle(__request_handle))?
                }
            } else {
                quote! {}
            };
            build.extend(quote! {
                #ident: #ident.unwrap_or_else(|| {
                    opcua::types::Error::decoding(#err)#handle
                })?,
            });
        } else {
            build.extend(quote! {
                #ident: #ident.unwrap_or_default(),
            });
        }
    }

    Ok(quote! {
        impl opcua::types::xml::XmlDecodable for #ident {
            fn decode(
                stream: &mut opcua::types::xml::XmlStreamReader<&mut dyn std::io::Read>,
                ctx: &opcua::types::Context<'_>,
            ) -> opcua::types::EncodingResult<Self> {
                use opcua::types::xml::XmlReadExt;
                #items
                stream.iter_children(|__key, stream, ctx| {
                    match __key.as_str() {
                        #items_match
                        _ => {
                            stream.skip_value()?;
                        }
                    }
                    Ok(())
                }, ctx)?;

                Ok(Self {
                    #build
                })
            }
        }
    })
}

pub fn generate_simple_enum_xml_decode_impl(en: SimpleEnum) -> syn::Result<TokenStream> {
    let ident = en.ident;

    Ok(quote! {
        impl opcua::types::xml::XmlDecodable for #ident {
            fn decode(
                stream: &mut opcua::types::xml::XmlStreamReader<&mut dyn std::io::Read>,
                ctx: &opcua::types::Context<'_>,
            ) -> opcua::types::EncodingResult<Self> {
                use std::str::FromStr;
                let val = stream.consume_as_text()?;
                opcua::types::UaEnum::from_str(&val)
            }
        }
    })
}

pub fn generate_simple_enum_xml_encode_impl(en: SimpleEnum) -> syn::Result<TokenStream> {
    let ident = en.ident;

    Ok(quote! {
        impl opcua::types::xml::XmlEncodable for #ident {
            fn encode(
                &self,
                stream: &mut opcua::types::xml::XmlStreamWriter<&mut dyn std::io::Write>,
                _ctx: &opcua::types::Context<'_>,
            ) -> opcua::types::EncodingResult<()> {
                stream.write_text(opcua::types::UaEnum::as_str(self))?;
                Ok(())
            }
        }
    })
}

pub fn generate_xml_type_impl(idt: Ident, attr: EncodingItemAttribute) -> syn::Result<TokenStream> {
    let name = attr.rename.unwrap_or_else(|| idt.to_string());
    Ok(quote! {
        impl opcua::types::xml::XmlType for #idt {
            const TAG: &'static str = #name;
        }
    })
}
