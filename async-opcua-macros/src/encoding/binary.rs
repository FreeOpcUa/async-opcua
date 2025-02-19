use proc_macro2::TokenStream;
use quote::quote;

use super::{enums::SimpleEnum, unions::AdvancedEnum, EncodingStruct};

pub fn generate_binary_encode_impl(strct: EncodingStruct) -> syn::Result<TokenStream> {
    let mut byte_len_body = quote! {};
    let mut encode_body = quote! {};

    let any_optional = strct
        .fields
        .iter()
        .any(|f| f.attr.optional && !f.attr.ignore);

    if any_optional {
        let mut optional_index = 0;

        // Add 4 for the byte length of the 32-bit encoding mask.
        byte_len_body.extend(quote! {
            size += 4;
        });
        encode_body.extend(quote! {
            let mut encoding_mask = 0u32;
        });
        for field in &strct.fields {
            if !field.attr.optional {
                continue;
            }
            let ident = &field.ident;
            encode_body.extend(quote! {
                if self.#ident.is_some() {
                    encoding_mask |= 1 << #optional_index;
                }
            });
            optional_index += 1;
        }
        encode_body.extend(quote! {
            encoding_mask.encode(stream, ctx)?;
        });
    }

    for field in strct.fields {
        if field.attr.ignore {
            continue;
        }

        let ident = field.ident;
        if field.attr.optional {
            byte_len_body.extend(quote! {
                if let Some(item) = &self.#ident {
                    size += item.byte_len(ctx);
                }
            });
            encode_body.extend(quote! {
                if let Some(item) = &self.#ident {
                    item.encode(stream, ctx)?;
                }
            });
        } else {
            byte_len_body.extend(quote! {
                size += self.#ident.byte_len(ctx);
            });
            encode_body.extend(quote! {
                self.#ident.encode(stream, ctx)?;
            });
        }
    }
    let ident = strct.ident;

    if any_optional {
        encode_body = quote! {

            #encode_body
        }
    }

    Ok(quote! {
        impl opcua::types::BinaryEncodable for #ident {
            #[allow(unused)]
            fn byte_len(&self, ctx: &opcua::types::Context<'_>) -> usize {
                let mut size = 0usize;
                #byte_len_body
                size
            }
            #[allow(unused)]
            fn encode<S: std::io::Write + ?Sized>(
                &self,
                stream: &mut S,
                ctx: &opcua::types::Context<'_>,
            ) -> opcua::types::EncodingResult<()> {
                #encode_body
                Ok(())
            }
        }
    })
}

pub fn generate_binary_decode_impl(strct: EncodingStruct) -> syn::Result<TokenStream> {
    let mut decode_impl = quote! {};
    let mut decode_build = quote! {};

    let mut has_context = false;
    let any_optional = strct
        .fields
        .iter()
        .any(|f| f.attr.optional && !f.attr.ignore);

    if any_optional {
        decode_impl.extend(quote! {
            let encoding_mask = u32::decode(stream, ctx)?;
        });
    }

    let mut optional_idx = 0;
    for field in strct.fields {
        if field.attr.ignore {
            continue;
        }

        let ident = field.ident;
        let ident_string = ident.to_string();
        let inner = if ident_string == "request_header" {
            decode_impl.extend(quote! {
                let request_header: opcua::types::RequestHeader = opcua::types::BinaryDecodable::decode(stream, ctx)?;
                let __request_handle = request_header.request_handle;
            });
            decode_build.extend(quote! {
                request_header,
            });
            has_context = true;
            continue;
        } else if ident_string == "response_header" {
            decode_impl.extend(quote! {
                let response_header: opcua::types::ResponseHeader = opcua::types::BinaryDecodable::decode(stream, ctx)?;
                let __request_handle = response_header.request_handle;
            });
            decode_build.extend(quote! {
                response_header,
            });
            has_context = true;
            continue;
        } else if has_context {
            quote! {
                opcua::types::BinaryDecodable::decode(stream, ctx)
                    .map_err(|e| e.with_request_handle(__request_handle))?
            }
        } else {
            quote! {
                opcua::types::BinaryDecodable::decode(stream, ctx)?
            }
        };

        if field.attr.optional {
            decode_build.extend(quote! {
                #ident: if (encoding_mask & (1 << #optional_idx)) != 0 {
                    Some(#inner)
                } else {
                    None
                },
            });
            optional_idx += 1;
        } else {
            decode_build.extend(quote! {
                #ident: #inner,
            });
        }
    }

    let ident = strct.ident;

    Ok(quote! {
        impl opcua::types::BinaryDecodable for #ident {
            #[allow(unused_variables)]
            fn decode<S: std::io::Read + ?Sized>(stream: &mut S, ctx: &opcua::types::Context<'_>) -> opcua::types::EncodingResult<Self> {
                #decode_impl
                Ok(Self {
                    #decode_build
                })
            }
        }
    })
}

pub fn generate_simple_enum_binary_decode_impl(en: SimpleEnum) -> syn::Result<TokenStream> {
    let ident = en.ident;
    let repr = en.repr;

    Ok(quote! {
        impl opcua::types::BinaryDecodable for #ident {
            #[allow(unused_variables)]
            fn decode<S: std::io::Read + ?Sized>(stream: &mut S, ctx: &opcua::types::Context<'_>) -> opcua::types::EncodingResult<Self> {
                let val = #repr::decode(stream, ctx)?;
                Self::try_from(val)
            }
        }
    })
}

pub fn generate_simple_enum_binary_encode_impl(en: SimpleEnum) -> syn::Result<TokenStream> {
    let ident = en.ident;
    let repr = en.repr;

    Ok(quote! {
        impl opcua::types::BinaryEncodable for #ident {
            #[allow(unused)]
            fn byte_len(&self, ctx: &opcua::types::Context<'_>) -> usize {
                (*self as #repr).byte_len(ctx)
            }
            #[allow(unused)]
            fn encode<S: std::io::Write + ?Sized>(
                &self,
                stream: &mut S,
                ctx: &opcua::types::Context<'_>,
            ) -> opcua::types::EncodingResult<()> {
                (*self as #repr).encode(stream, ctx)
            }
        }
    })
}

pub fn generate_union_binary_decode_impl(en: AdvancedEnum) -> syn::Result<TokenStream> {
    let ident = en.ident;

    let mut decode_arms = quote! {};

    let mut idx = 0u32;

    for variant in en.variants {
        if variant.is_null {
            continue;
        }
        idx += 1;

        let name = &variant.name;

        decode_arms.extend(quote! {
            #idx => Self::#name(opcua::types::BinaryDecodable::decode(stream, ctx)?),
        });
    }

    if let Some(null_variant) = en.null_variant {
        decode_arms.extend(quote! {
            0u32 => Self::#null_variant,
        });
    }

    Ok(quote! {
        impl opcua::types::BinaryDecodable for #ident {
            #[allow(unused_variables)]
            fn decode<S: std::io::Read + ?Sized>(stream: &mut S, ctx: &opcua::types::Context<'_>) -> opcua::types::EncodingResult<Self> {
                let disc = u32::decode(stream, ctx)?;
                Ok(match disc {
                    #decode_arms
                    _ => return Err(opcua::types::Error::decoding(format!("Unknown discriminant: {disc}"))),
                })
            }
        }
    })
}

pub fn generate_union_binary_encode_impl(en: AdvancedEnum) -> syn::Result<TokenStream> {
    let ident = en.ident;

    let mut byte_len_arms = quote! {};
    let mut encode_arms = quote! {};

    let mut idx = 0u32;

    for variant in en.variants {
        let name = &variant.name;
        if variant.is_null {
            encode_arms.extend(quote! {
                Self::#name => {
                    0u32.encode(stream, ctx)?;
                }
            });
            byte_len_arms.extend(quote! {
                Self::#name => 0,
            });
            continue;
        }
        idx += 1;

        byte_len_arms.extend(quote! {
            Self::#name(inner) => inner.byte_len(ctx),
        });

        encode_arms.extend(quote! {
            Self::#name(inner) => {
                #idx.encode(stream, ctx)?;
                inner.encode(stream, ctx)?;
            },
        });
    }

    Ok(quote! {
        impl opcua::types::BinaryEncodable for #ident {
            #[allow(unused)]
            fn byte_len(&self, ctx: &opcua::types::Context<'_>) -> usize {
                let mut byte_len = 4;
                byte_len += match self {
                    #byte_len_arms
                };
                byte_len
            }
            #[allow(unused)]
            fn encode<S: std::io::Write + ?Sized>(
                &self,
                stream: &mut S,
                ctx: &opcua::types::Context<'_>,
            ) -> opcua::types::EncodingResult<()> {
                match self {
                    #encode_arms
                }
                Ok(())
            }
        }
    })
}
