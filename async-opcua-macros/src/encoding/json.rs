use convert_case::{Case, Casing};
use proc_macro2::{Span, TokenStream};
use syn::Ident;

use quote::quote;

use super::{enums::SimpleEnum, EncodingStruct};

pub fn generate_json_encode_impl(strct: EncodingStruct) -> syn::Result<TokenStream> {
    let ident = strct.ident;
    let mut body = quote! {};

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
            if !field.attr.optional {
                continue;
            }
            let ident = &field.ident;
            body.extend(quote! {
                if self.#ident.as_ref().is_some_and(|f| !f.is_null_json()) {
                    encoding_mask |= 1 << #optional_index;
                }
            });
            optional_index += 1;
        }
        body.extend(quote! {
            stream.name("EncodingMask")?;
            opcua::types::json::JsonEncodable::encode(&encoding_mask, stream, ctx)?;
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
                    if !item.is_null_json() {
                        stream.name(#name)?;
                        opcua::types::json::JsonEncodable::encode(item, stream, ctx)?;
                    }
                }
            });
        } else {
            body.extend(quote! {
                if !self.#ident.is_null_json() {
                    stream.name(#name)?;
                    opcua::types::json::JsonEncodable::encode(&self.#ident, stream, ctx)?;
                }
            });
        }
    }

    Ok(quote! {
        impl opcua::types::json::JsonEncodable for #ident {
            fn encode(
                &self,
                stream: &mut opcua::types::json::JsonStreamWriter<&mut dyn std::io::Write>,
                ctx: &opcua::types::Context<'_>
            ) -> opcua::types::EncodingResult<()> {
                use opcua::types::json::JsonWriter;

                stream.begin_object()?;
                #body
                stream.end_object()?;

                Ok(())
            }
        }
    })
}

pub fn generate_json_decode_impl(strct: EncodingStruct) -> syn::Result<TokenStream> {
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
                    let __v: opcua::types::#ty = opcua::types::json::JsonDecodable::decode(stream, ctx)?;
                    __request_handle = Some(__v.request_handle);
                    #ident = Some(__v);
                },
            });
        } else if has_header {
            items_match.extend(quote! {
                #name => #ident = Some(opcua::types::json::JsonDecodable::decode(stream, ctx)
                    .map_err(|e| e.maybe_with_request_handle(__request_handle))?
                ),
            });
        } else {
            items_match.extend(quote! {
                #name => #ident = Some(opcua::types::json::JsonDecodable::decode(stream, ctx)?),
            });
        }

        if field.attr.no_default {
            let err = format!("Missing required field {name}");
            build.extend(quote! {
                #ident: #ident.unwrap_or_else(|| {
                    log::warn!(#err);
                    opcua::types::Error::new(
                        opcua::types::StatusCode::BadDecodingError,
                        None,
                        __request_handle,
                    )
                })?,
            });
        } else {
            build.extend(quote! {
                #ident: #ident.unwrap_or_default(),
            });
        }
    }
    let body = quote! {
        stream.begin_object()?;
        #items
        while stream.has_next()? {
            match stream.next_name()? {
                #items_match
                _ => stream.skip_value()?,
            }
        }
        stream.end_object()?;
    };
    Ok(quote! {
        impl opcua::types::json::JsonDecodable for #ident {
            fn decode(
                stream: &mut opcua::types::json::JsonStreamReader<&mut dyn std::io::Read>,
                ctx: &opcua::types::Context<'_>,
            ) -> opcua::types::EncodingResult<Self> {
                use opcua::types::json::JsonReader;
                #body

                Ok(Self {
                    #build
                })
            }
        }
    })
}

pub fn generate_simple_enum_json_decode_impl(en: SimpleEnum) -> syn::Result<TokenStream> {
    let ident = en.ident;
    let repr = en.repr;

    Ok(quote! {
        impl opcua::types::json::JsonDecodable for #ident {
            fn decode(
                stream: &mut opcua::types::json::JsonStreamReader<&mut dyn std::io::Read>,
                ctx: &opcua::types::Context<'_>,
            ) -> opcua::types::EncodingResult<Self> {
                let val = #repr::decode(stream, ctx)?;
                Self::try_from(val)
            }
        }
    })
}

pub fn generate_simple_enum_json_encode_impl(en: SimpleEnum) -> syn::Result<TokenStream> {
    let ident = en.ident;
    let repr = en.repr;

    Ok(quote! {
        impl opcua::types::json::JsonEncodable for #ident {
            fn encode(
                &self,
                stream: &mut opcua::types::json::JsonStreamWriter<&mut dyn std::io::Write>,
                ctx: &opcua::types::Context<'_>
            ) -> opcua::types::EncodingResult<()> {
                (*self as #repr).encode(stream, ctx)
            }
        }
    })
}
