#![warn(missing_docs)]

//! Core utilities for working with various OPC-UA XML schemas.
//!
//! This crate defines methods for decoding.
//!
//! - A subset of the XMLSchema schema in [schema::xml_schema].
//! - XML schema for OPC-UA BSD files in [schema::opc_binary_schema]
//! - XML schema for OPC-UA types defined in XSD files in [schema::opc_ua_types]
//! - XML schema for NodeSet2 files in [schema::ua_node_set]
//!
//! XML parsing is done with the `roxmltree` crate.

use ext::NodeExt;
use roxmltree::Node;

mod encoding;
mod error;
mod ext;
pub mod schema;

pub use encoding::{XmlReadError, XmlStreamReader, XmlStreamWriter, XmlWriteError};
pub use quick_xml::events;

pub use error::{XmlError, XmlErrorInner};
pub use schema::opc_binary_schema::load_bsd_file;
pub use schema::ua_node_set::load_nodeset2_file;
pub use schema::xml_schema::load_xsd_schema;

pub use schema::opc_ua_types::XmlElement;

/// Get a type by loading it from a string containing an XML document.
pub fn from_str<'a, T: XmlLoad<'a>>(data: &'a str) -> Result<T, XmlError> {
    let doc = roxmltree::Document::parse(data).map_err(|e| XmlError {
        span: 0..data.len(),
        error: e.into(),
    })?;
    T::load(&doc.root().first_child().ok_or_else(|| XmlError {
        span: doc.root().range(),
        error: error::XmlErrorInner::MissingField("Root".to_owned()),
    })?)
}

/// Trait for types that can be loaded from an XML node.
pub trait XmlLoad<'input>: Sized {
    /// Load Self from an XML node.
    fn load(node: &Node<'_, 'input>) -> Result<Self, XmlError>;
}

/// Trait for types that can be loaded from an XML node body.
pub trait FromValue: Sized {
    /// Load Self from the body of a node. `v` is the value being parsed, `attr` and `node` are
    /// given for context and error handling.
    fn from_value(node: &Node<'_, '_>, attr: &str, v: &str) -> Result<Self, XmlError>;
}

macro_rules! from_int {
    ($ty:ident) => {
        impl FromValue for $ty {
            fn from_value(node: &Node<'_, '_>, attr: &str, v: &str) -> Result<Self, XmlError> {
                v.parse().map_err(|e| XmlError::parse_int(node, attr, e))
            }
        }
    };
}

from_int!(i64);
from_int!(u64);
from_int!(i32);
from_int!(u32);
from_int!(i16);
from_int!(u16);
from_int!(i8);
from_int!(u8);

impl FromValue for String {
    fn from_value(_node: &Node<'_, '_>, _attr: &str, v: &str) -> Result<Self, XmlError> {
        Ok(v.to_owned())
    }
}

impl FromValue for f64 {
    fn from_value(node: &Node<'_, '_>, attr: &str, v: &str) -> Result<Self, XmlError> {
        v.parse().map_err(|e| XmlError::parse_float(node, attr, e))
    }
}

impl FromValue for f32 {
    fn from_value(node: &Node<'_, '_>, attr: &str, v: &str) -> Result<Self, XmlError> {
        v.parse().map_err(|e| XmlError::parse_float(node, attr, e))
    }
}

impl FromValue for bool {
    fn from_value(node: &Node<'_, '_>, attr: &str, v: &str) -> Result<Self, XmlError> {
        v.parse().map_err(|e| XmlError::parse_bool(node, attr, e))
    }
}

impl<'input, T> XmlLoad<'input> for T
where
    T: FromValue + Default,
{
    fn load(node: &Node<'_, 'input>) -> Result<Self, XmlError> {
        T::from_value(node, "content", node.try_contents().unwrap_or_default())
    }
}
