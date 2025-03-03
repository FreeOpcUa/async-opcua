#![warn(missing_docs)]

//! Crate containing various procedural macros used by rust OPC-UA.

mod encoding;
mod events;
mod utils;

use encoding::{
    derive_all_inner, derive_ua_nullable_inner, generate_encoding_impl, EncodingToImpl,
};
use events::{derive_event_field_inner, derive_event_inner};
use proc_macro::TokenStream;
use syn::parse_macro_input;

#[proc_macro_derive(Event, attributes(opcua))]
/// Derive the `Event` trait. This will also generate
/// an implementation of the `EventField` trait.
///
/// The event struct must have an attribute `opcua` containing
/// the _identifier_ of the node ID, as well as the namespace URI of the event type.
///
/// It must also have a field `base` with a different event type, which may be
/// the `BaseEventType`, and a field `own_namespace_index` storing the namespace index of
/// the event.
///
/// By default, fields will be given `PascalCase` names, you may use `opcua[rename = ...]`
/// to rename individual fields.
///
/// # Example
///
/// ```ignore
/// #[derive(Event)]
/// #[opcua(identifier = "s=myevent", namespace = "uri:my:namespace")]
/// struct MyEvent {
///     base: BaseEventType,
///     own_namespace_index: u16,
///     
///     #[opcua(rename = "my-field")]
///     my_field: f32,
///     my_other_field: EUInformation,
///     #[opcua(ignore)]
///     ignored: i32,
/// }
/// ```
pub fn derive_event(item: TokenStream) -> TokenStream {
    match derive_event_inner(parse_macro_input!(item)) {
        Ok(r) => r.into(),
        Err(e) => e.to_compile_error().into(),
    }
}

#[proc_macro_derive(EventField, attributes(opcua))]
/// Derive the `EventField` trait.
///
/// The event field may have a field `base`, which unless renamed will
/// be used as the base type for this field.
///
/// By default, fields will be given `PascalCase` names, you may use `opcua[rename = ...]`
/// to rename individual fields.
///
/// # Example
///
/// ```ignore
/// #[derive(EventField)]
/// struct MyEventField {
///     float: f32,
/// }
/// ```
pub fn derive_event_field(item: TokenStream) -> TokenStream {
    match derive_event_field_inner(parse_macro_input!(item)) {
        Ok(r) => r.into(),
        Err(e) => e.to_compile_error().into(),
    }
}

#[cfg(feature = "json")]
#[proc_macro_derive(JsonEncodable, attributes(opcua))]
/// Derive the `JsonEncodable` trait on this struct or enum, creating code
/// to write the struct to a JSON stream on OPC-UA reversible encoding.
///
/// All fields must be marked with `opcua(ignore)` or implement `JsonEncodable`.
pub fn derive_json_encodable(item: TokenStream) -> TokenStream {
    match generate_encoding_impl(parse_macro_input!(item), EncodingToImpl::JsonEncode) {
        Ok(r) => r.into(),
        Err(e) => e.to_compile_error().into(),
    }
}

#[cfg(feature = "json")]
#[proc_macro_derive(JsonDecodable, attributes(opcua))]
/// Derive the `JsonDecodable` trait on this struct or enum, creating code
/// to read the struct from an OPC-UA stream with reversible encoding.
///
/// All fields must be marked with `opcua(ignore)` or implement `JsonDecodable`.
pub fn derive_json_decodable(item: TokenStream) -> TokenStream {
    match generate_encoding_impl(parse_macro_input!(item), EncodingToImpl::JsonDecode) {
        Ok(r) => r.into(),
        Err(e) => e.to_compile_error().into(),
    }
}

#[proc_macro_derive(BinaryEncodable, attributes(opcua))]
/// Derive the `BinaryEncodable` trait on this struct or enum, creating code
/// to write the struct to an OPC-UA binary stream.
///
/// All fields must be marked with `opcua(ignore)` or implement `BinaryEncodable`.
pub fn derive_binary_encodable(item: TokenStream) -> TokenStream {
    match generate_encoding_impl(parse_macro_input!(item), EncodingToImpl::BinaryEncode) {
        Ok(r) => r.into(),
        Err(e) => e.to_compile_error().into(),
    }
}

#[proc_macro_derive(BinaryDecodable, attributes(opcua))]
/// Derive the `BinaryDecodable` trait on this struct or enum, creating code
/// to read the struct from an OPC-UA binary stream.
///
/// All fields must be marked with `opcua(ignore)` or implement `BinaryDecodable`.
pub fn derive_binary_decodable(item: TokenStream) -> TokenStream {
    match generate_encoding_impl(parse_macro_input!(item), EncodingToImpl::BinaryDecode) {
        Ok(r) => r.into(),
        Err(e) => e.to_compile_error().into(),
    }
}

#[proc_macro_derive(UaEnum, attributes(opcua))]
/// Derive the `UaEnum` trait on this simple enum, creating code to convert it
/// to and from OPC-UA string representation and its numeric representation.
/// The enum must have a `repr([int])` attribute.
///
/// This also implements `TryFrom<[int]>` for the given `repr`, `Into<[int]>`, `IntoVariant`, and `Default`
/// if a variant is labeled with `#[opcua(default)]`
pub fn derive_ua_enum(item: TokenStream) -> TokenStream {
    match generate_encoding_impl(parse_macro_input!(item), EncodingToImpl::UaEnum) {
        Ok(r) => r.into(),
        Err(e) => e.to_compile_error().into(),
    }
}

#[cfg(feature = "xml")]
#[proc_macro_derive(XmlEncodable, attributes(opcua))]
/// Derive the `XmlEncodable` trait on this struct or enum, creating
/// code to write the struct as OPC-UA XML.
///
/// All fields must be marked with `opcua(ignore)` or implement `XmlEncodable`.
pub fn derive_xml_encodable(item: TokenStream) -> TokenStream {
    match generate_encoding_impl(parse_macro_input!(item), EncodingToImpl::XmlEncode) {
        Ok(r) => r.into(),
        Err(e) => e.to_compile_error().into(),
    }
}

#[cfg(feature = "xml")]
#[proc_macro_derive(XmlDecodable, attributes(opcua))]
/// Derive the `XmlDecodable` trait on this struct or enum, creating
/// code to read the struct from an OPC-UA xml stream.
///
/// All fields must be marked with `opcua(ignore)` or implement `XmlDecodable`.
pub fn derive_xml_decodable(item: TokenStream) -> TokenStream {
    match generate_encoding_impl(parse_macro_input!(item), EncodingToImpl::XmlDecode) {
        Ok(r) => r.into(),
        Err(e) => e.to_compile_error().into(),
    }
}

#[cfg(feature = "xml")]
#[proc_macro_derive(XmlType, attributes(opcua))]
/// Derive the `XmlType` trait on this struct or enum. This simply exposes
/// the type name, which can be overridden with an item-level `opcua(rename = ...)` attribute.
pub fn derive_xml_type(item: TokenStream) -> TokenStream {
    match generate_encoding_impl(parse_macro_input!(item), EncodingToImpl::XmlType) {
        Ok(r) => r.into(),
        Err(e) => e.to_compile_error().into(),
    }
}

#[proc_macro_derive(UaNullable, attributes(opcua))]
/// Derive the `UaNullable` trait on this struct or enum. This indicates whether the
/// value is null/default in OPC-UA encoding.
pub fn derive_ua_nullable(item: TokenStream) -> TokenStream {
    match derive_ua_nullable_inner(parse_macro_input!(item)) {
        Ok(r) => r.into(),
        Err(e) => e.to_compile_error().into(),
    }
}

#[proc_macro_attribute]
/// Derive all the standard encoding traits on this struct or enum.
/// This will derive `BinaryEncodable`, `BinaryDecodable`, `JsonEncodable`, `JsonDecodable`,
/// `XmlEncodable`, `XmlDecodable`, `XmlType`, and `UaEnum` if the type is a simple enum.
///
/// Normal attributes for those still apply. Note that the XML and JSON traits will
/// be behind `"xml"` and `"json"` feature gates respectively.
pub fn ua_encodable(_attr: TokenStream, item: TokenStream) -> TokenStream {
    match derive_all_inner(parse_macro_input!(item)) {
        Ok(r) => r.into(),
        Err(e) => e.to_compile_error().into(),
    }
}
