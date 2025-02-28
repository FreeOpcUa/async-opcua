// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2024 Adam Lock

//! Contains the definition of `QualifiedName`.
use std::{
    fmt::Display,
    io::{Read, Write},
    sync::LazyLock,
};

use percent_encoding_rfc3986::percent_decode_str;
use regex::Regex;

use crate::{
    encoding::{BinaryDecodable, BinaryEncodable, EncodingResult},
    string::*,
    NamespaceMap, UaNullable,
};

#[allow(unused)]
mod opcua {
    pub use crate as types;
}

/// An identifier for a error or condition that is associated with a value or an operation.
///
/// A name qualified by a namespace.
///
/// For JSON, the namespace_index is saved as "Uri" and MUST be a numeric value or it will not parse. This is
/// is in accordance with OPC UA spec that says to save the index as a numeric according to rules cut and
/// pasted from spec below:
///
/// Name   The Name component of the QualifiedName.
///
/// Uri    The _NamespaceIndexcomponent_ of the QualifiedNameencoded as a JSON number. The Urifield
///        is omitted if the NamespaceIndex equals 0. For the non-reversible form, the
///        NamespaceUriassociated with the NamespaceIndexportion of the QualifiedNameis encoded as
///        JSON string unless the NamespaceIndexis 1 or if NamespaceUriis unknown. In these cases,
///        the NamespaceIndexis encoded as a JSON number.
#[derive(PartialEq, Debug, Clone, Eq, Hash)]
pub struct QualifiedName {
    /// The namespace index
    pub namespace_index: u16,
    /// The name.
    pub name: UAString,
}

impl UaNullable for QualifiedName {
    fn is_ua_null(&self) -> bool {
        self.is_null()
    }
}

#[cfg(feature = "xml")]
mod xml {
    use crate::{xml::*, UAString};

    use super::QualifiedName;

    impl XmlType for QualifiedName {
        const TAG: &'static str = "QualifiedName";
    }

    impl XmlEncodable for QualifiedName {
        fn encode(
            &self,
            writer: &mut XmlStreamWriter<&mut dyn std::io::Write>,
            context: &Context<'_>,
        ) -> EncodingResult<()> {
            let namespace_index = context.resolve_namespace_index_inverse(self.namespace_index)?;
            writer.encode_child("NamespaceIndex", &namespace_index, context)?;
            writer.encode_child("Name", &self.name, context)?;
            Ok(())
        }
    }

    impl XmlDecodable for QualifiedName {
        fn decode(
            read: &mut XmlStreamReader<&mut dyn std::io::Read>,
            context: &Context<'_>,
        ) -> Result<Self, Error> {
            let mut namespace_index = None;
            let mut name: Option<UAString> = None;

            read.iter_children(
                |key, stream, ctx| {
                    match key.as_str() {
                        "NamespaceIndex" => {
                            namespace_index = Some(XmlDecodable::decode(stream, ctx)?)
                        }
                        "Name" => name = Some(XmlDecodable::decode(stream, ctx)?),
                        _ => {
                            stream.skip_value()?;
                        }
                    }
                    Ok(())
                },
                context,
            )?;

            let Some(name) = name else {
                return Ok(QualifiedName::null());
            };

            if let Some(namespace_index) = namespace_index {
                Ok(QualifiedName {
                    namespace_index: context.resolve_namespace_index(namespace_index)?,
                    name,
                })
            } else {
                Ok(QualifiedName::new(0, name))
            }
        }
    }
}

#[cfg(feature = "json")]
mod json {
    use super::QualifiedName;

    use crate::json::*;

    // JSON encoding for QualifiedName is special, see 5.3.1.14.
    impl JsonEncodable for QualifiedName {
        fn encode(
            &self,
            stream: &mut JsonStreamWriter<&mut dyn std::io::Write>,
            _ctx: &crate::Context<'_>,
        ) -> crate::EncodingResult<()> {
            if self.is_null() {
                stream.null_value()?;
                return Ok(());
            }
            stream.string_value(&self.to_string())?;
            Ok(())
        }
    }

    impl JsonDecodable for QualifiedName {
        fn decode(
            stream: &mut JsonStreamReader<&mut dyn std::io::Read>,
            ctx: &Context<'_>,
        ) -> crate::EncodingResult<Self> {
            if matches!(stream.peek()?, ValueType::Null) {
                return Ok(QualifiedName::null());
            }

            let raw = stream.next_str()?;
            Ok(QualifiedName::parse(raw, ctx.namespaces()))
        }
    }
}

impl Default for QualifiedName {
    fn default() -> Self {
        Self::null()
    }
}

impl<'a> From<&'a str> for QualifiedName {
    fn from(value: &'a str) -> Self {
        Self {
            namespace_index: 0,
            name: UAString::from(value),
        }
    }
}

impl From<&String> for QualifiedName {
    fn from(value: &String) -> Self {
        Self {
            namespace_index: 0,
            name: UAString::from(value),
        }
    }
}

impl From<String> for QualifiedName {
    fn from(value: String) -> Self {
        Self {
            namespace_index: 0,
            name: UAString::from(value),
        }
    }
}

impl BinaryEncodable for QualifiedName {
    fn byte_len(&self, ctx: &opcua::types::Context<'_>) -> usize {
        let mut size: usize = 0;
        size += self.namespace_index.byte_len(ctx);
        size += self.name.byte_len(ctx);
        size
    }

    fn encode<S: Write + ?Sized>(
        &self,
        stream: &mut S,
        ctx: &crate::Context<'_>,
    ) -> EncodingResult<()> {
        self.namespace_index.encode(stream, ctx)?;
        self.name.encode(stream, ctx)
    }
}
impl BinaryDecodable for QualifiedName {
    fn decode<S: Read + ?Sized>(stream: &mut S, ctx: &crate::Context<'_>) -> EncodingResult<Self> {
        let namespace_index = u16::decode(stream, ctx)?;
        let name = UAString::decode(stream, ctx)?;
        Ok(QualifiedName {
            namespace_index,
            name,
        })
    }
}

impl Display for QualifiedName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.namespace_index > 0 {
            write!(f, "{}:{}", self.namespace_index, self.name)
        } else {
            write!(f, "{}", self.name)
        }
    }
}

static NUMERIC_QNAME_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"^(\d+):(.*)$"#).unwrap());

impl QualifiedName {
    /// Create a new qualified name from namespace index and name.
    pub fn new<T>(namespace_index: u16, name: T) -> QualifiedName
    where
        T: Into<UAString>,
    {
        QualifiedName {
            namespace_index,
            name: name.into(),
        }
    }

    /// Create a new empty QualifiedName.
    pub fn null() -> QualifiedName {
        QualifiedName {
            namespace_index: 0,
            name: UAString::null(),
        }
    }

    /// Return `true` if this is the null QualifiedName.
    pub fn is_null(&self) -> bool {
        self.namespace_index == 0 && self.name.is_null()
    }

    /// Parse a QualifiedName from a string.
    /// Note that QualifiedName parsing is unsolvable. This does a best-effort.
    /// If parsing fails, we will capture the string as a name with namespace index 0.
    pub fn parse(raw: &str, namespaces: &NamespaceMap) -> QualifiedName {
        // First, try parsing the string as a numeric QualifiedName.
        if let Some(caps) = NUMERIC_QNAME_REGEX.captures(raw) {
            // Ignore errors here, if we fail we fall back on other options.
            if let Ok(namespace_index) = caps.get(1).unwrap().as_str().parse::<u16>() {
                let name = caps.get(2).unwrap().as_str();
                if namespaces
                    .known_namespaces()
                    .iter()
                    .any(|n| n.1 == &namespace_index)
                {
                    return QualifiedName::new(namespace_index, name);
                }
            }
        }

        // Next, see if the string contains a semicolon, and if it does, try treating the first half as a URI.
        if let Some((l, r)) = raw.split_once(";") {
            if let Ok(l) = percent_decode_str(l) {
                if let Some(namespace_index) = namespaces.get_index(l.decode_utf8_lossy().as_ref())
                {
                    return QualifiedName::new(namespace_index, r);
                }
            }
        }

        QualifiedName::new(0, raw)
    }
}
