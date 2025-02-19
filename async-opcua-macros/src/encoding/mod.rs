use attribute::EncodingFieldAttribute;
use binary::{
    generate_binary_decode_impl, generate_binary_encode_impl,
    generate_simple_enum_binary_decode_impl, generate_simple_enum_binary_encode_impl,
    generate_union_binary_decode_impl, generate_union_binary_encode_impl,
};
use enums::{derive_ua_enum_impl, SimpleEnum};
#[cfg(feature = "json")]
use json::{
    generate_json_decode_impl, generate_json_encode_impl, generate_simple_enum_json_decode_impl,
    generate_simple_enum_json_encode_impl,
};
use json::{generate_union_json_decode_impl, generate_union_json_encode_impl};
use proc_macro2::{Span, TokenStream};
use syn::DeriveInput;
use unions::AdvancedEnum;
#[cfg(feature = "xml")]
use xml::{generate_simple_enum_xml_impl, generate_xml_impl};

use crate::utils::{EmptyAttribute, StructItem};

mod attribute;
mod binary;
mod enums;
#[cfg(feature = "json")]
mod json;
#[cfg(feature = "xml")]
mod xml;

mod unions;

pub(crate) type EncodingStruct = StructItem<EncodingFieldAttribute, EmptyAttribute>;

pub(crate) enum EncodingInput {
    Struct(EncodingStruct),
    SimpleEnum(SimpleEnum),
    AdvancedEnum(AdvancedEnum),
}

impl EncodingInput {
    pub fn from_derive_input(input: DeriveInput) -> syn::Result<Self> {
        match input.data {
            syn::Data::Struct(data_struct) => Ok(Self::Struct(EncodingStruct::from_input(
                data_struct,
                input.attrs,
                input.ident,
            )?)),
            syn::Data::Enum(data_enum) => {
                let is_union = data_enum
                    .variants
                    .first()
                    .is_some_and(|v| !v.fields.is_empty());
                if is_union {
                    return Ok(Self::AdvancedEnum(AdvancedEnum::from_input(
                        data_enum,
                        input.attrs,
                        input.ident,
                    )?));
                }
                Ok(Self::SimpleEnum(SimpleEnum::from_input(
                    data_enum,
                    input.attrs,
                    input.ident,
                )?))
            }
            syn::Data::Union(_) => Err(syn::Error::new_spanned(
                input.ident,
                "Unions are not supported",
            )),
        }
    }
}

pub enum EncodingToImpl {
    BinaryEncode,
    BinaryDecode,
    UaEnum,
    #[cfg(feature = "json")]
    JsonEncode,
    #[cfg(feature = "json")]
    JsonDecode,
    #[cfg(feature = "xml")]
    FromXml,
}

pub fn generate_encoding_impl(
    input: DeriveInput,
    target: EncodingToImpl,
) -> syn::Result<TokenStream> {
    let input = EncodingInput::from_derive_input(input)?;

    match (target, input) {
        (EncodingToImpl::BinaryEncode, EncodingInput::Struct(s)) => generate_binary_encode_impl(s),
        (EncodingToImpl::BinaryEncode, EncodingInput::SimpleEnum(s)) => {
            generate_simple_enum_binary_encode_impl(s)
        }
        (EncodingToImpl::BinaryEncode, EncodingInput::AdvancedEnum(s)) => {
            generate_union_binary_encode_impl(s)
        }
        (EncodingToImpl::BinaryDecode, EncodingInput::Struct(s)) => generate_binary_decode_impl(s),
        (EncodingToImpl::BinaryDecode, EncodingInput::SimpleEnum(s)) => {
            generate_simple_enum_binary_decode_impl(s)
        }
        (EncodingToImpl::BinaryDecode, EncodingInput::AdvancedEnum(s)) => {
            generate_union_binary_decode_impl(s)
        }

        #[cfg(feature = "json")]
        (EncodingToImpl::JsonEncode, EncodingInput::Struct(s)) => generate_json_encode_impl(s),
        #[cfg(feature = "json")]
        (EncodingToImpl::JsonEncode, EncodingInput::SimpleEnum(s)) => {
            generate_simple_enum_json_encode_impl(s)
        }
        #[cfg(feature = "json")]
        (EncodingToImpl::JsonEncode, EncodingInput::AdvancedEnum(s)) => {
            generate_union_json_encode_impl(s)
        }
        #[cfg(feature = "json")]
        (EncodingToImpl::JsonDecode, EncodingInput::Struct(s)) => generate_json_decode_impl(s),
        #[cfg(feature = "json")]
        (EncodingToImpl::JsonDecode, EncodingInput::SimpleEnum(s)) => {
            generate_simple_enum_json_decode_impl(s)
        }
        #[cfg(feature = "json")]
        (EncodingToImpl::JsonDecode, EncodingInput::AdvancedEnum(s)) => {
            generate_union_json_decode_impl(s)
        }

        #[cfg(feature = "xml")]
        (EncodingToImpl::FromXml, EncodingInput::Struct(s)) => generate_xml_impl(s),
        #[cfg(feature = "xml")]
        (EncodingToImpl::FromXml, EncodingInput::SimpleEnum(s)) => generate_simple_enum_xml_impl(s),
        #[cfg(feature = "xml")]
        (EncodingToImpl::FromXml, EncodingInput::AdvancedEnum(s)) => Err(syn::Error::new_spanned(
            s.ident,
            "FromXml is not supported on unions yet",
        )),

        (EncodingToImpl::UaEnum, EncodingInput::SimpleEnum(s)) => derive_ua_enum_impl(s),
        (EncodingToImpl::UaEnum, _) => Err(syn::Error::new(
            Span::call_site(),
            "UaEnum derive macro is only supported on simple enums",
        )),
    }
}
