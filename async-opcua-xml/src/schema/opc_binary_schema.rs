//! This module contains an implementation of the OPCBinarySchema.xsd XML schema,
//! for use with code generation.
//! Attributes such as `any` or `anyAttribute` are not added.

use roxmltree::{Document, Node};

use crate::{
    error::XmlError,
    ext::{children_with_name, first_child_with_name_opt, int_attr, uint_attr, NodeExt},
    XmlLoad,
};

#[derive(Debug)]
/// Documentation object.
pub struct Documentation {
    /// Documentation node content.
    pub contents: Option<String>,
}

impl<'input> XmlLoad<'input> for Documentation {
    fn load(node: &Node<'_, 'input>) -> Result<Self, XmlError> {
        Ok(Self {
            contents: node.text().map(|a| a.to_owned()),
        })
    }
}

#[derive(Debug)]
/// Byte order for a value.
pub enum ByteOrder {
    /// Big endian.
    BigEndian,
    /// Little endian.
    LittleEndian,
}

impl ByteOrder {
    pub(crate) fn from_node(node: &Node<'_, '_>, attr: &str) -> Result<Option<Self>, XmlError> {
        Ok(match node.attribute(attr) {
            Some("LittleEndian") => Some(ByteOrder::LittleEndian),
            Some("BigEndian") => Some(ByteOrder::BigEndian),
            Some(r) => {
                return Err(XmlError::other(
                    node,
                    &format!("Expected LittleEndian or BigEndian for {attr}, got {r}"),
                ))
            }
            None => None,
        })
    }
}

#[derive(Debug)]
/// Description of a type in an OPC-UA binary schema.
pub struct TypeDescription {
    /// Documentation object.
    pub documentation: Option<Documentation>,
    /// Type name.
    pub name: String,
    /// Default byte order.
    pub default_byte_order: Option<ByteOrder>,
}

impl<'input> XmlLoad<'input> for TypeDescription {
    fn load(node: &Node<'_, 'input>) -> Result<Self, XmlError> {
        Ok(Self {
            documentation: first_child_with_name_opt(node, "Documentation")?,
            name: node.try_attribute("Name")?.to_owned(),
            default_byte_order: ByteOrder::from_node(node, "DefaultByteOrder")?,
        })
    }
}

#[derive(Debug)]
/// Opaque type, these are stored as some other primitive type.
pub struct OpaqueType {
    /// Type description.
    pub description: TypeDescription,
    /// Fixed length in bits. Can be left out if the type has dynamic length.
    pub length_in_bits: Option<i64>,
    /// Whether the byte order is significant.
    pub byte_order_significant: bool,
}

impl<'input> XmlLoad<'input> for OpaqueType {
    fn load(node: &Node<'_, 'input>) -> Result<Self, XmlError> {
        Ok(Self {
            description: TypeDescription::load(node)?,
            length_in_bits: int_attr(node, "LengthInBits")?,
            byte_order_significant: node.attribute("ByteOrderSignificant") == Some("true"),
        })
    }
}

#[derive(Debug)]
/// Description of an enum value.
pub struct EnumeratedValue {
    /// Value documentation.
    pub documentation: Option<Documentation>,
    /// Enum value name.
    pub name: Option<String>,
    /// Numeric value.
    pub value: Option<i64>,
}
impl<'input> XmlLoad<'input> for EnumeratedValue {
    fn load(node: &Node<'_, 'input>) -> Result<Self, XmlError> {
        Ok(Self {
            documentation: first_child_with_name_opt(node, "Documentation")?,
            name: node.attribute("Name").map(|n| n.to_owned()),
            value: int_attr(node, "Value")?,
        })
    }
}

#[derive(Debug)]
/// Description of an enumerated type.
pub struct EnumeratedType {
    /// Base opaque type.
    pub opaque: OpaqueType,
    /// Possible enum variants.
    pub variants: Vec<EnumeratedValue>,
    /// Whether this is an option set, i.e. it can have multiple values at the same time.
    pub is_option_set: bool,
}

impl<'input> XmlLoad<'input> for EnumeratedType {
    fn load(node: &Node<'_, 'input>) -> Result<Self, XmlError> {
        Ok(Self {
            opaque: OpaqueType::load(node)?,
            variants: children_with_name(node, "EnumeratedValue")?,
            is_option_set: node.attribute("IsOptionSet") == Some("true"),
        })
    }
}

#[derive(Debug)]
/// Switch operand.
pub enum SwitchOperand {
    /// Equality operator.
    Equals,
    /// Greater than operator.
    GreaterThan,
    /// Less than operator.
    LessThan,
    /// Greater than or equal to operator.
    GreaterThanOrEqual,
    /// Less than or eqaul to operator.
    LessThanOrEqual,
    /// Not equal operator.
    NotEqual,
}

impl SwitchOperand {
    pub(crate) fn from_node(node: &Node<'_, '_>, attr: &str) -> Result<Option<Self>, XmlError> {
        Ok(match node.attribute(attr) {
            Some("Equals") => Some(SwitchOperand::Equals),
            Some("GreaterThan") => Some(SwitchOperand::GreaterThan),
            Some("LessThan") => Some(SwitchOperand::LessThan),
            Some("GreaterThanOrEqual") => Some(SwitchOperand::GreaterThanOrEqual),
            Some("LessThanOrEqual") => Some(SwitchOperand::LessThanOrEqual),
            Some("NotEqual") => Some(SwitchOperand::NotEqual),
            Some(r) => {
                return Err(XmlError::other(
                    node,
                    &format!("Unexpected value for {attr}: {r}"),
                ))
            }
            _ => None,
        })
    }
}

#[derive(Debug)]
/// Type of a struct field.
pub struct FieldType {
    /// Field documentation.
    pub documentation: Option<Documentation>,
    /// Field name.
    pub name: String,
    /// Name of this fields type.
    pub type_name: Option<String>,
    /// Fixed field length.
    pub length: Option<u64>,
    /// Name of field storing this fields length.
    pub length_field: Option<String>,
    /// Whether the length is in bytes or number of elements.
    pub is_length_in_bytes: bool,
    /// Field to switch on.
    pub switch_field: Option<String>,
    /// Value to compare to.
    pub switch_value: Option<u64>,
    /// Switch operand.
    pub switch_operand: Option<SwitchOperand>,
    /// Field terminator.
    pub terminator: Option<String>,
}

impl<'input> XmlLoad<'input> for FieldType {
    fn load(node: &Node<'_, 'input>) -> Result<Self, XmlError> {
        Ok(Self {
            documentation: first_child_with_name_opt(node, "Documentation")?,
            name: node.try_attribute("Name")?.to_owned(),
            type_name: node.attribute("TypeName").map(|a| a.to_owned()),
            length: uint_attr(node, "Length")?,
            length_field: node.attribute("LengthField").map(|a| a.to_owned()),
            is_length_in_bytes: node.attribute("IsLengthInBytes") == Some("true"),
            switch_field: node.attribute("SwitchField").map(|a| a.to_owned()),
            switch_value: uint_attr(node, "SwitchValue")?,
            switch_operand: SwitchOperand::from_node(node, "SwitchOperand")?,
            terminator: node.attribute("Terminator").map(|a| a.to_owned()),
        })
    }
}

#[derive(Debug)]
/// Description of a structured type.
pub struct StructuredType {
    /// Type description.
    pub description: TypeDescription,
    /// List of fields, the order is significant.
    pub fields: Vec<FieldType>,
    /// Base type.
    pub base_type: Option<String>,
}

impl<'input> XmlLoad<'input> for StructuredType {
    fn load(node: &Node<'_, 'input>) -> Result<Self, XmlError> {
        Ok(Self {
            description: TypeDescription::load(node)?,
            fields: children_with_name(node, "Field")?,
            base_type: node.attribute("BaseType").map(|t| t.to_owned()),
        })
    }
}

#[derive(Debug)]
/// Import types from some other schema.
pub struct ImportDirective {
    /// Namespace to import.
    pub namespace: Option<String>,
    /// Location of import.
    pub location: Option<String>,
}

impl<'input> XmlLoad<'input> for ImportDirective {
    fn load(node: &Node<'_, 'input>) -> Result<Self, XmlError> {
        Ok(Self {
            namespace: node.attribute("Namespace").map(|a| a.to_owned()),
            location: node.attribute("Location").map(|a| a.to_owned()),
        })
    }
}

#[derive(Debug)]
/// Item in the outer type dictionary.
pub enum TypeDictionaryItem {
    /// An opaque type represented via some primitive type.
    Opaque(OpaqueType),
    /// An enum.
    Enumerated(EnumeratedType),
    /// A structured type.
    Structured(StructuredType),
}

#[derive(Debug)]
/// The outer type dictionary containing the types in an OPC UA BSD file.
pub struct TypeDictionary {
    /// Type dictionary documentation.
    pub documentation: Option<Documentation>,
    /// List of imports.
    pub imports: Vec<ImportDirective>,
    /// List of types defined in this schema.
    pub elements: Vec<TypeDictionaryItem>,
    /// Target OPC-UA namespace, required.
    pub target_namespace: String,
    /// Default byte order for types in this schema.
    pub default_byte_order: Option<ByteOrder>,
}

impl<'input> XmlLoad<'input> for TypeDictionary {
    fn load(node: &Node<'_, 'input>) -> Result<Self, XmlError> {
        Ok(Self {
            documentation: first_child_with_name_opt(node, "Documentation")?,
            imports: children_with_name(node, "Import")?,
            elements: node
                .children()
                .filter_map(|e| match e.tag_name().name() {
                    "OpaqueType" => Some(OpaqueType::load(&e).map(TypeDictionaryItem::Opaque)),
                    "EnumeratedType" => {
                        Some(EnumeratedType::load(&e).map(TypeDictionaryItem::Enumerated))
                    }
                    "StructuredType" => {
                        Some(StructuredType::load(&e).map(TypeDictionaryItem::Structured))
                    }
                    _ => None,
                })
                .collect::<Result<Vec<_>, _>>()?,
            target_namespace: node.try_attribute("TargetNamespace")?.to_owned(),
            default_byte_order: ByteOrder::from_node(node, "DefaultByteOrder")?,
        })
    }
}

/// Load an OPC-UA BSD file from a string, `document` is the content of an OPC-UA BSD file.
pub fn load_bsd_file(document: &str) -> Result<TypeDictionary, XmlError> {
    let document = Document::parse(document).map_err(|e| XmlError {
        span: 0..1,
        error: crate::error::XmlErrorInner::Xml(e),
    })?;
    TypeDictionary::load(&document.root().first_child_with_name("TypeDictionary")?)
}
