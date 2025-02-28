use convert_case::{Case, Casing};
use proc_macro2::{Span, TokenStream};
use syn::Ident;

use quote::quote;

use super::{enums::SimpleEnum, unions::AdvancedEnum, EncodingStruct};

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
                if self.#ident.as_ref().is_some_and(|f| !opcua::types::UaNullable::is_ua_null(f)) {
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
                    if !opcua::types::UaNullable::is_ua_null(item){
                        stream.name(#name)?;
                        opcua::types::json::JsonEncodable::encode(item, stream, ctx)?;
                    }
                }
            });
        } else {
            body.extend(quote! {
                if !opcua::types::UaNullable::is_ua_null(&self.#ident) {
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

pub fn generate_union_json_decode_impl(en: AdvancedEnum) -> syn::Result<TokenStream> {
    let ident = en.ident;

    let mut decode_arms = quote! {};

    for variant in en.variants {
        if variant.is_null {
            continue;
        }

        let name = variant
            .attr
            .rename
            .unwrap_or_else(|| variant.name.to_string());
        let var_idt = variant.name;

        decode_arms.extend(quote! {
            #name => value = Some(Self::#var_idt(opcua::types::json::JsonDecodable::decode(stream, ctx)?)),
        });
    }

    let fallback = if let Some(null_variant) = en.null_variant {
        quote! {
            Ok(Self::#null_variant)
        }
    } else {
        quote! {
            Err(opcua::types::Error::decoding(format!("Missing union value")))
        }
    };

    Ok(quote! {
        impl opcua::types::json::JsonDecodable for #ident {
            fn decode(
                stream: &mut opcua::types::json::JsonStreamReader<&mut dyn std::io::Read>,
                ctx: &opcua::types::Context<'_>,
            ) -> opcua::types::EncodingResult<Self> {
                use opcua::types::json::JsonReader;
                stream.begin_object()?;
                let mut value = None;
                while stream.has_next()? {
                    match stream.next_name()? {
                        #decode_arms
                        _ => stream.skip_value()?,
                    }
                }
                stream.end_object()?;

                let Some(value) = value else {
                    return #fallback;
                };

                Ok(value)
            }
        }
    })
}

pub fn generate_union_json_encode_impl(en: AdvancedEnum) -> syn::Result<TokenStream> {
    let ident = en.ident;

    let mut encode_arms = quote! {};

    let mut idx = 0u32;
    for variant in en.variants {
        let name = variant
            .attr
            .rename
            .unwrap_or_else(|| variant.name.to_string());
        let var_idt = variant.name;
        if variant.is_null {
            encode_arms.extend(quote! {
                Self::#var_idt => {
                    stream.name("SwitchField")?;
                    opcua::types::json::JsonEncodable::encode(&0u32, stream, ctx)?;
                }
            });
            continue;
        }

        idx += 1;

        encode_arms.extend(quote! {
            Self::#var_idt(inner) => {
                stream.name("SwitchField")?;
                opcua::types::json::JsonEncodable::encode(&#idx, stream, ctx)?;
                stream.name(#name)?;
                opcua::types::json::JsonEncodable::encode(inner, stream, ctx)?;
            },
        });
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
                match self {
                    #encode_arms
                }
                stream.end_object()?;

                Ok(())
            }
        }
    })
}
