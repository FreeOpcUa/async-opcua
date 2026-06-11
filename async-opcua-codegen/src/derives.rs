//! Static derive helpers for generated OPC UA types.

use proc_macro2::TokenStream;
use quote::quote;
use syn::{parse_quote, Ident, Item, Type};

/// Field metadata needed to generate static impls for a generated structure.
#[derive(Clone)]
pub(crate) struct StructFieldImpl {
    pub(crate) ident: Ident,
    pub(crate) ty: Type,
}

impl StructFieldImpl {
    pub(crate) fn new(ident: Ident, ty: Type) -> Self {
        Self { ident, ty }
    }
}

/// Generate static implementations expected by runtime extension object handling.
pub(crate) fn struct_impls(struct_name: &Ident, fields: &[StructFieldImpl]) -> Vec<Item> {
    let mut impls = Vec::new();
    impls.extend(binary_impls(struct_name, fields));
    impls.extend(send_sync_impls(struct_name, fields));
    impls
}

fn binary_impls(struct_name: &Ident, fields: &[StructFieldImpl]) -> Vec<Item> {
    let byte_len_body = fields.iter().map(|field| {
        let ident = &field.ident;
        quote! {
            size += opcua::types::BinaryEncodable::byte_len(&self.#ident, ctx);
        }
    });
    let encode_body = fields.iter().map(|field| {
        let ident = &field.ident;
        quote! {
            opcua::types::BinaryEncodable::encode(&self.#ident, stream, ctx)?;
        }
    });
    let decode_body = decode_body(fields);

    vec![
        parse_quote! {
            impl opcua::types::BinaryEncodable for #struct_name {
                #[allow(unused)]
                // Empty types produce the degenerate `let size = 0; size` form.
                #[allow(clippy::let_and_return)]
                fn byte_len(&self, ctx: &opcua::types::Context<'_>) -> usize {
                    let mut size = 0usize;
                    #(#byte_len_body)*
                    size
                }

                #[allow(unused)]
                fn encode<S: std::io::Write + ?Sized>(
                    &self,
                    stream: &mut S,
                    ctx: &opcua::types::Context<'_>,
                ) -> opcua::types::EncodingResult<()> {
                    #(#encode_body)*
                    Ok(())
                }
            }
        },
        parse_quote! {
            impl opcua::types::BinaryDecodable for #struct_name {
                #[allow(unused_variables)]
                fn decode<S: std::io::Read + ?Sized>(
                    stream: &mut S,
                    ctx: &opcua::types::Context<'_>,
                ) -> opcua::types::EncodingResult<Self> {
                    #decode_body
                }
            }
        },
    ]
}

fn decode_body(fields: &[StructFieldImpl]) -> TokenStream {
    let mut decode_stmts = TokenStream::new();
    let mut field_build = TokenStream::new();
    let mut has_request_context = false;

    for field in fields {
        let ident = &field.ident;
        let ty = &field.ty;
        let ident_name = ident.to_string();

        if ident_name == "request_header" || ident_name == "response_header" {
            decode_stmts.extend(quote! {
                let #ident: #ty = opcua::types::BinaryDecodable::decode(stream, ctx)?;
                let __request_handle = #ident.request_handle;
            });
            field_build.extend(quote! {
                #ident,
            });
            has_request_context = true;
            continue;
        }

        let decode_expr = if has_request_context {
            quote! {
                opcua::types::BinaryDecodable::decode(stream, ctx)
                    .map_err(|e| e.with_request_handle(__request_handle))?
            }
        } else {
            quote! {
                opcua::types::BinaryDecodable::decode(stream, ctx)?
            }
        };

        field_build.extend(quote! {
            #ident: #decode_expr,
        });
    }

    quote! {
        #decode_stmts
        Ok(Self {
            #field_build
        })
    }
}

fn send_sync_impls(struct_name: &Ident, fields: &[StructFieldImpl]) -> Vec<Item> {
    if fields.is_empty() {
        return vec![
            parse_quote! {
                unsafe impl Send for #struct_name {}
            },
            parse_quote! {
                unsafe impl Sync for #struct_name {}
            },
        ];
    }

    let field_types = fields.iter().map(|field| &field.ty);
    let field_types_sync = fields.iter().map(|field| &field.ty);

    vec![
        parse_quote! {
            unsafe impl Send for #struct_name
            where
                #(#field_types: Send,)*
            {}
        },
        parse_quote! {
            unsafe impl Sync for #struct_name
            where
                #(#field_types_sync: Sync,)*
            {}
        },
    ]
}
