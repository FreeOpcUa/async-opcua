//! Definition of types for representing values in a NodeSet2 file.
//!
//! These use a slightly different schema than similar fields in the rest of the file.

use std::collections::HashMap;

use chrono::Utc;
use roxmltree::Node;
use uuid::Uuid;

use crate::{
    ext::{
        children_of_type, children_with_name, first_child_of_type, first_child_with_name_opt,
        value_from_contents_opt,
    },
    XmlError, XmlLoad,
};
/// Owned XML element, simplified greatly.

#[derive(Debug)]
/// Variant as defined in a NodeSet2 file.
pub enum Variant {
    /// Boolean
    Boolean(bool),
    /// List of boolean
    ListOfBoolean(Vec<bool>),
    /// Signed byte
    SByte(i8),
    /// List of signed bytes
    ListOfSByte(Vec<i8>),
    /// Byte
    Byte(u8),
    /// List of bytes
    ListOfByte(Vec<u8>),
    /// Signed 16 bit int
    Int16(i16),
    /// List of signed 16 bit ints
    ListOfInt16(Vec<i16>),
    /// Unsigned 16 bit int
    UInt16(u16),
    /// List of unsigned 16 bit ints
    ListOfUInt16(Vec<u16>),
    /// Signed 32 bit int
    Int32(i32),
    /// List of signed 32 bit ints
    ListOfInt32(Vec<i32>),
    /// Unsigned 32 bit int
    UInt32(u32),
    /// List of unsigned 32 bit ints
    ListOfUInt32(Vec<u32>),
    /// Signed 64 bit int
    Int64(i64),
    /// List of signed 64 bit ints
    ListOfInt64(Vec<i64>),
    /// Unsigned 64 bit int
    UInt64(u64),
    /// List of unsigned 64 bit ints
    ListOfUInt64(Vec<u64>),
    /// 32 bit floating point number
    Float(f32),
    /// List of 32 bit floating point numbers
    ListOfFloat(Vec<f32>),
    /// 64 bit floating point number.
    Double(f64),
    /// List of 64 bit floating point numbers.
    ListOfDouble(Vec<f64>),
    /// String
    String(String),
    /// List of strings
    ListOfString(Vec<String>),
    /// DateTime
    DateTime(chrono::DateTime<Utc>),
    /// List of DateTimes
    ListOfDateTime(Vec<chrono::DateTime<Utc>>),
    /// GUID
    Guid(uuid::Uuid),
    /// List of GUIDs
    ListOfGuid(Vec<uuid::Uuid>),
    /// ByteString
    ByteString(String),
    /// List of ByteStrings
    ListOfByteString(Vec<String>),
    /// XmlElement
    XmlElement(Vec<XmlElement>),
    /// List of XmlElements
    ListOfXmlElement(Vec<Vec<XmlElement>>),
    /// QualifiedName
    QualifiedName(QualifiedName),
    /// List of QualifiedNames
    ListOfQualifiedName(Vec<QualifiedName>),
    /// LocalizedText
    LocalizedText(LocalizedText),
    /// List of LocalizedTexts
    ListOfLocalizedText(Vec<LocalizedText>),
    /// NodeId
    NodeId(NodeId),
    /// List of NodeIds
    ListOfNodeId(Vec<NodeId>),
    /// ExpandedNodeId
    ExpandedNodeId(NodeId),
    /// List of ExpandedNodeIds
    ListOfExpandedNodeId(Vec<NodeId>),
    /// ExtensionObject
    ExtensionObject(ExtensionObject),
    /// List of ExtensionObjects
    ListOfExtensionObject(Vec<ExtensionObject>),
    /// Variant
    Variant(Box<Variant>),
    /// List of Variants
    ListOfVariant(Vec<Variant>),
    /// StatusCode
    StatusCode(StatusCode),
    /// List of StatusCodes
    ListOfStatusCode(Vec<StatusCode>),
}

impl<'input> XmlLoad<'input> for Variant {
    fn load(node: &Node<'_, 'input>) -> Result<Self, XmlError> {
        Ok(match node.tag_name().name() {
            "Boolean" => Variant::Boolean(XmlLoad::load(node)?),
            "ListOfBoolean" => Variant::ListOfBoolean(children_with_name(node, "Boolean")?),
            "SByte" => Variant::SByte(XmlLoad::load(node)?),
            "ListOfSByte" => Variant::ListOfSByte(children_with_name(node, "SByte")?),
            "Byte" => Variant::Byte(XmlLoad::load(node)?),
            "ListOfByte" => Variant::ListOfByte(children_with_name(node, "Byte")?),
            "Int16" => Variant::Int16(XmlLoad::load(node)?),
            "ListOfInt16" => Variant::ListOfInt16(children_with_name(node, "Int16")?),
            "UInt16" => Variant::UInt16(XmlLoad::load(node)?),
            "ListOfUInt16" => Variant::ListOfUInt16(children_with_name(node, "UInt16")?),
            "Int32" => Variant::Int32(XmlLoad::load(node)?),
            "ListOfInt32" => Variant::ListOfInt32(children_with_name(node, "Int32")?),
            "UInt32" => Variant::UInt32(XmlLoad::load(node)?),
            "ListOfUInt32" => Variant::ListOfUInt32(children_with_name(node, "UInt32")?),
            "Int64" => Variant::Int64(XmlLoad::load(node)?),
            "ListOfInt64" => Variant::ListOfInt64(children_with_name(node, "Int64")?),
            "UInt64" => Variant::UInt64(XmlLoad::load(node)?),
            "ListOfUInt64" => Variant::ListOfUInt64(children_with_name(node, "UInt64")?),
            "Float" => Variant::Float(XmlLoad::load(node)?),
            "ListOfFloat" => Variant::ListOfFloat(children_with_name(node, "Float")?),
            "Double" => Variant::Double(XmlLoad::load(node)?),
            "ListOfDouble" => Variant::ListOfDouble(children_with_name(node, "Double")?),
            "String" => Variant::String(value_from_contents_opt(node)?.unwrap_or_default()),
            "ListOfString" => Variant::ListOfString(children_with_name(node, "String")?),
            "DateTime" => Variant::DateTime(XmlLoad::load(node)?),
            "ListOfDateTime" => Variant::ListOfDateTime(children_with_name(node, "DateTime")?),
            "Guid" => Variant::Guid(XmlLoad::load(node)?),
            "ListOfGuid" => Variant::ListOfGuid(children_with_name(node, "Guid")?),
            "ByteString" => Variant::ByteString(XmlLoad::load(node)?),
            "ListOfByteString" => {
                Variant::ListOfByteString(children_with_name(node, "ByteString")?)
            }
            "XmlElement" => Variant::XmlElement(children_of_type(node)?),
            "ListOfXmlElement" => Variant::ListOfXmlElement(
                node.children()
                    .filter(|n| n.tag_name().name() == "XmlElement")
                    .map(|n| children_of_type(&n))
                    .collect::<Result<Vec<_>, _>>()?,
            ),
            "QualifiedName" => Variant::QualifiedName(XmlLoad::load(node)?),
            "ListOfQualifiedName" => {
                Variant::ListOfQualifiedName(children_with_name(node, "QualifiedName")?)
            }
            "LocalizedText" => Variant::LocalizedText(XmlLoad::load(node)?),
            "ListOfLocalizedText" => {
                Variant::ListOfLocalizedText(children_with_name(node, "LocalizedText")?)
            }
            "NodeId" => Variant::NodeId(XmlLoad::load(node)?),
            "ListOfNodeId" => Variant::ListOfNodeId(children_with_name(node, "NodeId")?),
            "ExpandedNodeId" => Variant::ExpandedNodeId(XmlLoad::load(node)?),
            "ListOfExpandedNodeId" => {
                Variant::ListOfExpandedNodeId(children_with_name(node, "ExpandedNodeId")?)
            }
            "ExtensionObject" => Variant::ExtensionObject(XmlLoad::load(node)?),
            "ListOfExtensionObject" => {
                Variant::ListOfExtensionObject(children_with_name(node, "ExtensionObject")?)
            }
            "Variant" => Variant::Variant(Box::new(XmlLoad::load(node)?)),
            "ListOfVariant" => Variant::ListOfVariant(children_with_name(node, "Variant")?),
            "StatusCode" => Variant::StatusCode(XmlLoad::load(node)?),
            "ListOfStatusCode" => {
                Variant::ListOfStatusCode(children_with_name(node, "StatusCode")?)
            }
            r => return Err(XmlError::other(node, &format!("Unknown variant type: {r}"))),
        })
    }
}

impl<'input> XmlLoad<'input> for uuid::Uuid {
    fn load(node: &Node<'_, 'input>) -> Result<Self, XmlError> {
        let Some(content): Option<String> = first_child_with_name_opt(node, "String")? else {
            return Ok(Uuid::nil());
        };

        Uuid::try_parse(&content).map_err(|e| XmlError::parse_uuid(node, "content", e))
    }
}

#[derive(Debug)]
/// Node ID as defined in a data type.
pub struct NodeId {
    /// Node ID identifier or alias.
    pub identifier: Option<String>,
}

impl<'input> XmlLoad<'input> for NodeId {
    fn load(node: &roxmltree::Node<'_, 'input>) -> Result<Self, crate::XmlError> {
        Ok(Self {
            identifier: first_child_with_name_opt(node, "Identifier")?,
        })
    }
}

#[derive(Debug)]
/// Status code.
pub struct StatusCode {
    /// Status code numeric value.
    pub code: u32,
}

impl<'input> XmlLoad<'input> for StatusCode {
    fn load(node: &roxmltree::Node<'_, 'input>) -> Result<Self, crate::XmlError> {
        Ok(Self {
            code: first_child_with_name_opt(node, "Code")?.unwrap_or(0),
        })
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
/// Full XML element, requires further type information to convert to a data type.
pub struct XmlElement {
    /// XML Element body.
    pub text: Option<String>,
    /// Tag name.
    pub tag: String,
    /// Map of attribute names to values.
    pub attributes: HashMap<String, String>,
    /// Map of child tag names to value.
    pub children: HashMap<String, Vec<XmlElement>>,
}

impl std::fmt::Display for XmlElement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<{}", self.tag)?;
        for (k, v) in &self.attributes {
            write!(f, " {k}=\"{v}\"")?;
        }
        write!(f, ">")?;
        if let Some(text) = &self.text {
            write!(f, "{text}")?;
        }
        for elems in self.children.values() {
            for child in elems {
                write!(f, "{child}")?;
            }
        }
        write!(f, "</{}>", self.tag)?;

        Ok(())
    }
}

impl<'input> XmlLoad<'input> for Option<XmlElement> {
    fn load(node: &Node<'_, 'input>) -> Result<Self, XmlError> {
        let tag_name = node.tag_name().name();
        if tag_name.is_empty() {
            return Ok(None);
        };
        let mut children: HashMap<String, Vec<XmlElement>> = HashMap::new();
        for child in children_of_type::<XmlElement>(node)? {
            if let Some(ch) = children.get_mut(&child.tag) {
                ch.push(child);
            } else {
                children.insert(child.tag.clone(), vec![child]);
            }
        }
        Ok(Some(XmlElement {
            text: node.text().and_then(|t| {
                let trimmed = t.trim();
                if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed.to_owned())
                }
            }),
            tag: tag_name.to_owned(),
            attributes: node
                .attributes()
                .map(|a| (a.name().to_owned(), a.value().to_owned()))
                .collect(),
            children,
        }))
    }
}

impl XmlElement {
    /// Get all children of this node with the given name.
    pub fn children_with_name<'a>(
        &'a self,
        name: &'a str,
    ) -> impl Iterator<Item = &'a XmlElement> + 'a {
        let inner = self.children.get(name);
        inner.into_iter().flat_map(|m| m.iter())
    }

    /// Get the first child with the given name.
    pub fn first_child_with_name<'a>(&'a self, name: &'a str) -> Option<&'a XmlElement> {
        self.children_with_name(name).next()
    }

    /// Get the content of the first child with the given name.
    pub fn child_content<'a>(&'a self, name: &'a str) -> Option<&'a str> {
        self.first_child_with_name(name)
            .and_then(|c| c.text.as_ref())
            .map(|c| c.as_str())
    }

    /// Parse the XML element from a string.
    pub fn parse(input: &str) -> Result<Option<Self>, XmlError> {
        let doc = roxmltree::Document::parse(input)?;
        let root = doc.root_element();
        XmlLoad::load(&root)
    }
}

#[derive(Debug)]
/// Qualified name in an OPC-UA type.
pub struct QualifiedName {
    /// Namespace index, defaults to 0.
    pub namespace_index: Option<u16>,
    /// Qualified name value.
    pub name: Option<String>,
}

impl<'input> XmlLoad<'input> for QualifiedName {
    fn load(node: &Node<'_, 'input>) -> Result<Self, XmlError> {
        Ok(Self {
            namespace_index: first_child_with_name_opt(node, "NamespaceIndex")?,
            name: first_child_with_name_opt(node, "Name")?,
        })
    }
}

#[derive(Debug)]
/// Localized text in an OPC-UA type.
pub struct LocalizedText {
    /// Locale.
    pub locale: Option<String>,
    /// Body.
    pub text: Option<String>,
}

impl<'input> XmlLoad<'input> for LocalizedText {
    fn load(node: &Node<'_, 'input>) -> Result<Self, XmlError> {
        Ok(Self {
            locale: first_child_with_name_opt(node, "Locale")?,
            text: first_child_with_name_opt(node, "Text")?,
        })
    }
}

/*
It's suboptimal that we need both the raw body and the parsed XML element,
but roxmltree doesn't do well when starting from the middle of a document,
and we can't yet replace the entire parsing machinery with quick-xml due to the
lack of a raw element in quick-xml's serde implementation.
*/

#[derive(Debug)]
/// Body of an extension object.
pub struct ExtensionObjectBody {
    /// Raw extension object body, just an XML node.
    pub data: Option<XmlElement>,
    /// The data node as string, copied directly from the source document.
    /// We currently need both, since one is used for codegen, and the other is used for
    /// NodeSet2 parsing.
    pub raw: Option<String>,
}

impl<'input> XmlLoad<'input> for ExtensionObjectBody {
    fn load(node: &Node<'_, 'input>) -> Result<Self, XmlError> {
        Ok(Self {
            data: first_child_of_type(node)?,
            raw: node
                .first_element_child()
                .map(|n| n.document().input_text()[n.range()].to_owned()),
        })
    }
}

#[derive(Debug)]
/// Extension object, containing some custom type resolved later.
pub struct ExtensionObject {
    /// Extension object type ID.
    pub type_id: Option<NodeId>,
    /// Extension object body.
    pub body: Option<ExtensionObjectBody>,
}

impl<'input> XmlLoad<'input> for ExtensionObject {
    fn load(node: &Node<'_, 'input>) -> Result<Self, XmlError> {
        Ok(Self {
            type_id: first_child_with_name_opt(node, "TypeId")?,
            body: first_child_with_name_opt(node, "Body")?,
        })
    }
}
