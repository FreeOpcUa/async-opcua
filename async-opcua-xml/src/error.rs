use std::{
    num::{ParseFloatError, ParseIntError},
    ops::Range,
    str::ParseBoolError,
};

use chrono::ParseError;
use roxmltree::Node;
use thiserror::Error;

#[derive(Error, Debug, Clone)]
/// Inner error variant of an error parsing an XML document.
pub enum XmlErrorInner {
    #[error("Failed to load XML: {0}")]
    /// XML parsing error.
    Xml(#[from] roxmltree::Error),
    #[error("Expected child: {0}")]
    /// Required field was missing.
    MissingField(String),
    #[error("Expected attribute: {0}")]
    /// Required attribute was missing.
    MissingAttribute(String),
    #[error("Failed to parse {0} as integer.")]
    /// Failed to parse content as integer.
    ParseInt(String, ParseIntError),
    #[error("Failed to parse {0} as float.")]
    /// Failed to parse content as float.
    ParseFloat(String, ParseFloatError),
    #[error("Failed to parse {0} as bool.")]
    /// Failed to parse content as boolean.
    ParseBool(String, ParseBoolError),
    #[error("Missing node content")]
    /// Missing required content.
    MissingContent,
    #[error("Invalid timestamp for {0}: {1}")]
    /// Failed to parse datatime from string.
    ParseDateTime(String, ParseError),
    #[error("Invalid UUID for {0}: {1}")]
    /// Failed to parse UUID from string.
    ParseUuid(String, uuid::Error),
    #[error("{0}")]
    /// Some other error.
    Other(String),
}

#[derive(Error, Debug, Clone)]
#[error("{error} at {span:?}")]
/// Error returned from loading an XML document.
pub struct XmlError {
    /// Where in the document the node that caused the issue is found.
    pub span: Range<usize>,
    /// The inner error variant.
    pub error: XmlErrorInner,
}

impl From<roxmltree::Error> for XmlError {
    fn from(value: roxmltree::Error) -> Self {
        Self {
            span: 0..0,
            error: XmlErrorInner::Xml(value),
        }
    }
}

impl XmlError {
    /// Create an error for a node with a missing field with name `name`.
    pub fn missing_field(node: &Node<'_, '_>, name: &str) -> Self {
        Self {
            span: node.range(),
            error: XmlErrorInner::MissingField(name.to_owned()),
        }
    }

    /// Create an error for a node with a missing attribute with name `name`.
    pub fn missing_attribute(node: &Node<'_, '_>, name: &str) -> Self {
        Self {
            span: node.range(),
            error: XmlErrorInner::MissingAttribute(name.to_owned()),
        }
    }

    /// Create an error for some other, general error.
    pub fn other(node: &Node<'_, '_>, info: &str) -> Self {
        Self {
            span: node.range(),
            error: XmlErrorInner::Other(info.to_owned()),
        }
    }

    /// Create an error for failing to parse a string as an integer.
    pub fn parse_int(node: &Node<'_, '_>, attr: &str, err: ParseIntError) -> Self {
        Self {
            span: node.range(),
            error: XmlErrorInner::ParseInt(attr.to_owned(), err),
        }
    }

    /// Create an error for failing to parse a string as a float.
    pub fn parse_float(node: &Node<'_, '_>, attr: &str, err: ParseFloatError) -> Self {
        Self {
            span: node.range(),
            error: XmlErrorInner::ParseFloat(attr.to_owned(), err),
        }
    }

    /// Create an error for failing to parse a string as a boolean.
    pub fn parse_bool(node: &Node<'_, '_>, attr: &str, err: ParseBoolError) -> Self {
        Self {
            span: node.range(),
            error: XmlErrorInner::ParseBool(attr.to_owned(), err),
        }
    }

    /// Create an error for failing to parse a string as a date time.
    pub fn parse_date_time(node: &Node<'_, '_>, attr: &str, err: ParseError) -> Self {
        Self {
            span: node.range(),
            error: XmlErrorInner::ParseDateTime(attr.to_owned(), err),
        }
    }

    /// Create an error for failing to parse a string as a UUID.
    pub fn parse_uuid(node: &Node<'_, '_>, attr: &str, err: uuid::Error) -> Self {
        Self {
            span: node.range(),
            error: XmlErrorInner::ParseUuid(attr.to_owned(), err),
        }
    }

    /// Create an error indicating that `node` does not have the necessary content.
    pub fn missing_content(node: &Node<'_, '_>) -> Self {
        Self {
            span: node.range(),
            error: XmlErrorInner::MissingContent,
        }
    }
}
