//! A limited implementation of code generation based on an xml schema. Adapted for
//! OPC-UA code generation.

use roxmltree::{Document, Node};

use crate::{
    ext::{
        children_of_type, children_with_name, first_child_of_type, first_child_of_type_req,
        first_child_with_name, first_child_with_name_opt, value_from_attr, value_from_attr_opt,
    },
    FromValue, XmlError, XmlLoad,
};

/// Load an XSD schema from a document.
pub fn load_xsd_schema(document: &str) -> Result<XmlSchema, XmlError> {
    let document = Document::parse(document).map_err(|e| XmlError {
        span: 0..1,
        error: crate::error::XmlErrorInner::Xml(e),
    })?;
    let root = document.root();
    first_child_with_name(&root, "schema")
}

#[derive(Debug, Clone)]
/// Value of a Facet node.
pub struct FacetValue {
    /// Facet value.
    pub value: String,
    /// Whether the facet is fixed.
    pub fixed: bool,
}

impl<'input> XmlLoad<'input> for FacetValue {
    fn load(node: &Node<'_, 'input>) -> Result<Self, XmlError> {
        Ok(Self {
            value: value_from_attr(node, "value")?,
            fixed: value_from_attr_opt(node, "fixed")?.unwrap_or(false),
        })
    }
}

#[derive(Debug, Clone)]
/// A restriction facet.
pub enum Facet {
    /// Exclusive minimum of the type value.
    MinExclusive(FacetValue),
    /// Inclusive minimum of the type value.
    MinInclusive(FacetValue),
    /// Exclusive maximum of the type value.
    MaxExclusive(FacetValue),
    /// Inclusive maximum of the type value.
    MaxInclusive(FacetValue),
    /// Total number of digits in values of this type.
    TotalDigits(FacetValue),
    /// Total number of digits after the comma in values of this type.
    FractionDigits(FacetValue),
    /// Length of values of this type.
    Length(FacetValue),
    /// Minimum length of values of this type.
    MinLength(FacetValue),
    /// Maximum length of values of this type.
    MaxLength(FacetValue),
    /// Possible value. The presence of one of these means the type is an enum.
    Enumeration(FacetValue),
    /// Handling of white space in the value.
    WhiteSpace(FacetValue),
    /// Pattern values of this type must match.
    Pattern(FacetValue),
}

impl<'input> XmlLoad<'input> for Option<Facet> {
    fn load(node: &Node<'_, 'input>) -> Result<Self, XmlError> {
        Ok(Some(match node.tag_name().name() {
            "minExclusive" => Facet::MinExclusive(FacetValue::load(node)?),
            "minInclusive" => Facet::MinInclusive(FacetValue::load(node)?),
            "maxExclusive" => Facet::MaxExclusive(FacetValue::load(node)?),
            "maxInclusive" => Facet::MaxInclusive(FacetValue::load(node)?),
            "totalDigits" => Facet::TotalDigits(FacetValue::load(node)?),
            "fractionDigits" => Facet::FractionDigits(FacetValue::load(node)?),
            "length" => Facet::Length(FacetValue::load(node)?),
            "minLength" => Facet::MinLength(FacetValue::load(node)?),
            "maxLength" => Facet::MaxLength(FacetValue::load(node)?),
            "enumeration" => Facet::Enumeration(FacetValue::load(node)?),
            "whiteSpace" => Facet::WhiteSpace(FacetValue::load(node)?),
            "pattern" => Facet::Pattern(FacetValue::load(node)?),
            _ => return Ok(None),
        }))
    }
}

#[derive(Debug, Clone)]
/// A restriction is a property of a type that limits valid values.
pub struct Restriction {
    /// Inherit from some other type.
    pub base: Option<String>,
    /// List of facets.
    pub facets: Vec<Facet>,
    /// Inner structure type, may not be present for primitive types.
    pub content: Option<SimpleType>,
    /// Type definition particle.
    pub particle: Option<TypeDefParticle>,
    /// Extra attributes.
    pub attributes: Vec<Attribute>,
}

impl<'input> XmlLoad<'input> for Restriction {
    fn load(node: &Node<'_, 'input>) -> Result<Self, XmlError> {
        Ok(Self {
            base: value_from_attr_opt(node, "base")?,
            facets: children_of_type(node)?,
            particle: first_child_of_type(node)?,
            attributes: children_with_name(node, "")?,
            content: first_child_with_name_opt(node, "simpleType")?,
        })
    }
}

#[derive(Debug, Clone)]
/// List of values.
pub struct List {
    /// Inner type.
    pub content: Option<SimpleType>,
    /// Item type.
    pub item_type: Option<String>,
}

impl<'input> XmlLoad<'input> for List {
    fn load(node: &Node<'_, 'input>) -> Result<Self, XmlError> {
        Ok(Self {
            content: first_child_with_name_opt(node, "simpleType")?,
            item_type: value_from_attr_opt(node, "itemType")?,
        })
    }
}

#[derive(Debug, Clone)]
/// Discriminated union of different variants.
pub struct Union {
    /// Possible variants.
    pub variants: Vec<SimpleType>,
    /// Member types.
    pub member_types: Option<Vec<String>>,
}

impl<'input> XmlLoad<'input> for Union {
    fn load(node: &Node<'_, 'input>) -> Result<Self, XmlError> {
        Ok(Self {
            variants: children_with_name(node, "simpleType")?,
            member_types: value_from_attr_opt(node, "memberTypes")?,
        })
    }
}

#[derive(Debug, Clone)]
/// Simple derivation.
pub enum SimpleDerivation {
    /// Restriction type.
    Restriction(Box<Restriction>),
    /// List type.
    List(Box<List>),
    /// Union type.
    Union(Box<Union>),
}

impl<'input> XmlLoad<'input> for Option<SimpleDerivation> {
    fn load(node: &Node<'_, 'input>) -> Result<Self, XmlError> {
        Ok(Some(match node.tag_name().name() {
            "restriction" => SimpleDerivation::Restriction(Box::new(XmlLoad::load(node)?)),
            "list" => SimpleDerivation::List(Box::new(XmlLoad::load(node)?)),
            "union" => SimpleDerivation::Union(Box::new(XmlLoad::load(node)?)),
            _ => return Ok(None),
        }))
    }
}

#[derive(Debug, Clone)]
/// A simple type.
pub struct SimpleType {
    /// Type name.
    pub name: Option<String>,
    /// Type content.
    pub content: Option<SimpleDerivation>,
}

impl<'input> XmlLoad<'input> for SimpleType {
    fn load(node: &Node<'_, 'input>) -> Result<Self, XmlError> {
        Ok(Self {
            name: value_from_attr_opt(node, "name")?,
            content: first_child_of_type(node)?,
        })
    }
}

#[derive(Debug, Clone)]
/// The Any type.
pub struct Any {
    /// Minimum number of times this field occurs.
    pub min_occurs: Option<u32>,
    /// Maximum number of times this field occurs.
    pub max_uccors: Option<MaxOccurs>,
}

impl<'input> XmlLoad<'input> for Any {
    fn load(node: &Node<'_, 'input>) -> Result<Self, XmlError> {
        Ok(Self {
            min_occurs: value_from_attr_opt(node, "minOccurs")?,
            max_uccors: value_from_attr_opt(node, "maxOccurs")?,
        })
    }
}

/// Particle, some element of the schema.
#[derive(Debug, Clone)]
pub enum Particle {
    /// General element.
    Element(Element),
    /// An list of particles that must all be true.
    All(Group),
    /// A choice between a list of different particles.
    Choice(Group),
    /// A sequence of particles in a fixed order.
    Sequence(Group),
    /// Anything
    Any(Any),
}

impl<'input> XmlLoad<'input> for Option<Particle> {
    fn load(node: &Node<'_, 'input>) -> Result<Self, XmlError> {
        Ok(Some(match node.tag_name().name() {
            "element" => Particle::Element(XmlLoad::load(node)?),
            "all" => Particle::All(XmlLoad::load(node)?),
            "choice" => Particle::Choice(XmlLoad::load(node)?),
            "sequence" => Particle::Sequence(XmlLoad::load(node)?),
            "any" => Particle::Any(XmlLoad::load(node)?),
            _ => return Ok(None),
        }))
    }
}

#[derive(Debug, Clone)]
/// A variant of particle that can occur inside another object.
pub enum NestedParticle {
    /// Element type
    Element(Element),
    /// Choice between different types.
    Choice(Group),
    /// Sequence of particles in a fixed order.
    Sequence(Group),
    /// Anything
    Any(Any),
}

impl<'input> XmlLoad<'input> for Option<NestedParticle> {
    fn load(node: &Node<'_, 'input>) -> Result<Self, XmlError> {
        Ok(Some(match node.tag_name().name() {
            "element" => NestedParticle::Element(XmlLoad::load(node)?),
            "choice" => NestedParticle::Choice(XmlLoad::load(node)?),
            "sequence" => NestedParticle::Sequence(XmlLoad::load(node)?),
            "any" => NestedParticle::Any(XmlLoad::load(node)?),
            _ => return Ok(None),
        }))
    }
}

#[derive(Debug, Clone)]
/// A group of multiple particles.
pub struct Group {
    /// Particles in the group.
    pub content: Vec<NestedParticle>,
    /// Minimum occurences of the group.
    pub min_occurs: Option<u32>,
    /// Maximum occurences of the group.
    pub max_uccors: Option<MaxOccurs>,
}

impl<'input> XmlLoad<'input> for Group {
    fn load(node: &Node<'_, 'input>) -> Result<Self, XmlError> {
        Ok(Self {
            content: children_of_type(node)?,
            min_occurs: value_from_attr_opt(node, "minOccurs")?,
            max_uccors: value_from_attr_opt(node, "maxOccurs")?,
        })
    }
}

#[derive(Debug, Clone)]
/// Type definition particle.
pub enum TypeDefParticle {
    /// All elements of the group must hold.
    All(Group),
    /// One of the elements of the group.
    Choice(Group),
    /// A fixed sequence of group elements.
    Sequence(Group),
}

impl<'input> XmlLoad<'input> for Option<TypeDefParticle> {
    fn load(node: &Node<'_, 'input>) -> Result<Self, XmlError> {
        Ok(Some(match node.tag_name().name() {
            "all" => TypeDefParticle::All(XmlLoad::load(node)?),
            "choice" => TypeDefParticle::Choice(XmlLoad::load(node)?),
            "sequence" => TypeDefParticle::Sequence(XmlLoad::load(node)?),
            _ => return Ok(None),
        }))
    }
}

#[derive(Debug, Clone)]
/// A type that extends another type.
pub struct Extension {
    /// Extension content.
    pub content: Option<TypeDefParticle>,
    /// Attributes on the extension.
    pub attributes: Vec<Attribute>,
    /// Base type.
    pub base: String,
}

impl<'input> XmlLoad<'input> for Extension {
    fn load(node: &Node<'_, 'input>) -> Result<Self, XmlError> {
        Ok(Self {
            content: first_child_of_type(node)?,
            attributes: children_with_name(node, "attributes")?,
            base: value_from_attr(node, "base")?,
        })
    }
}

#[derive(Debug, Clone)]
/// Content of a simple type.
pub enum SimpleContent {
    /// Restriction of some other type.
    Restriction(Restriction),
    /// Extension of some other type.
    Extension(Extension),
}

impl<'input> XmlLoad<'input> for Option<SimpleContent> {
    fn load(node: &Node<'_, 'input>) -> Result<Self, XmlError> {
        Ok(Some(match node.tag_name().name() {
            "restriction" => SimpleContent::Restriction(XmlLoad::load(node)?),
            "extension" => SimpleContent::Extension(XmlLoad::load(node)?),
            _ => return Ok(None),
        }))
    }
}

#[derive(Debug, Clone)]
/// Complex restriction variant.
pub struct ComplexRestriction {
    /// Inner base restriction.
    pub base: Restriction,
    /// Extension particle.
    pub particle: Option<TypeDefParticle>,
}

impl<'input> XmlLoad<'input> for ComplexRestriction {
    fn load(node: &Node<'_, 'input>) -> Result<Self, XmlError> {
        Ok(Self {
            base: Restriction::load(node)?,
            particle: first_child_of_type(node)?,
        })
    }
}

#[derive(Debug, Clone)]
/// Content of a complex type.
pub enum ComplexContent {
    /// Complex restriction of some other type.
    Restriction(ComplexRestriction),
    /// Extension of some other type.
    Extension(Extension),
}

impl<'input> XmlLoad<'input> for Option<ComplexContent> {
    fn load(node: &Node<'_, 'input>) -> Result<Self, XmlError> {
        Ok(Some(match node.tag_name().name() {
            "restriction" => ComplexContent::Restriction(XmlLoad::load(node)?),
            "extension" => ComplexContent::Extension(XmlLoad::load(node)?),
            _ => return Ok(None),
        }))
    }
}

#[derive(Debug, Clone)]
/// Possible contents of a complex type.
pub enum ComplexTypeContents {
    /// Simple content.
    Simple(SimpleContent),
    /// Complex content.
    Complex(ComplexContent),
}

impl<'input> XmlLoad<'input> for Option<ComplexTypeContents> {
    fn load(node: &Node<'_, 'input>) -> Result<Self, XmlError> {
        Ok(Some(match node.tag_name().name() {
            "simpleContent" => ComplexTypeContents::Simple(first_child_of_type_req(
                node,
                "restriction or extension",
            )?),
            "complexContent" => ComplexTypeContents::Complex(first_child_of_type_req(
                node,
                "restriction or extension",
            )?),
            _ => {
                return Ok(None);
            }
        }))
    }
}

#[derive(Debug, Clone)]
/// A complex structure.
pub struct ComplexType {
    /// Complex type contents.
    pub content: Option<ComplexTypeContents>,
    /// Inner particle.
    pub particle: Option<TypeDefParticle>,
    /// List of attributes.
    pub attributes: Vec<Attribute>,
    /// Type name.
    pub name: Option<String>,
}

impl<'input> XmlLoad<'input> for ComplexType {
    fn load(node: &Node<'_, 'input>) -> Result<Self, XmlError> {
        Ok(Self {
            content: first_child_of_type(node)?,
            particle: first_child_of_type(node)?,
            attributes: children_with_name(node, "attribute")?,
            name: value_from_attr_opt(node, "name")?,
        })
    }
}

#[derive(Debug, Clone)]
/// Contents of an element.
pub enum ElementContents {
    /// A simple type.
    SimpleType(SimpleType),
    /// A complex type.
    ComplexType(ComplexType),
}

impl<'input> XmlLoad<'input> for Option<ElementContents> {
    fn load(node: &Node<'_, 'input>) -> Result<Self, XmlError> {
        Ok(Some(match node.tag_name().name() {
            "simpleType" => ElementContents::SimpleType(XmlLoad::load(node)?),
            "complexType" => ElementContents::ComplexType(XmlLoad::load(node)?),
            _ => return Ok(None),
        }))
    }
}

#[derive(Debug, Clone)]
/// Maximum number of occurences of something.
pub enum MaxOccurs {
    /// A specific number.
    Count(u32),
    /// Unbounded.
    Unbounded,
}

impl FromValue for MaxOccurs {
    fn from_value(node: &Node<'_, '_>, attr: &str, v: &str) -> Result<Self, XmlError> {
        if v == "unbounded" {
            return Ok(Self::Unbounded);
        }

        Ok(Self::Count(u32::from_value(node, attr, v)?))
    }
}

#[derive(Debug, Clone)]
/// Legal uses of an attribute.
pub enum AttributeUse {
    /// Attribute cannot be used.
    Prohibited,
    /// Attribute is optional.
    Optional,
    /// Attribute is required.
    Required,
}

impl FromValue for AttributeUse {
    fn from_value(node: &Node<'_, '_>, attr: &str, v: &str) -> Result<Self, XmlError> {
        match v {
            "prohibited" => Ok(Self::Prohibited),
            "optional" => Ok(Self::Optional),
            "required" => Ok(Self::Required),
            r => Err(XmlError::other(
                node,
                &format!("Unexpected value for {attr}: {r}"),
            )),
        }
    }
}

#[derive(Debug, Clone)]
/// Definition of an attribute on a type.
pub struct Attribute {
    /// Attribute content.
    pub content: Option<SimpleType>,
    /// Attribute name.
    pub name: Option<String>,
    /// Attribute reference.
    pub r#ref: Option<String>,
    /// Attribute type.
    pub r#type: Option<String>,
    /// Usage patterns.
    pub r#use: AttributeUse,
    /// Attribute default value.
    pub default: Option<String>,
}

impl<'input> XmlLoad<'input> for Attribute {
    fn load(node: &Node<'_, 'input>) -> Result<Self, XmlError> {
        Ok(Self {
            content: first_child_with_name_opt(node, "simpleType")?,
            name: value_from_attr_opt(node, "name")?,
            r#ref: value_from_attr_opt(node, "ref")?,
            r#type: value_from_attr_opt(node, "type")?,
            r#use: value_from_attr_opt(node, "use")?.unwrap_or(AttributeUse::Optional),
            default: value_from_attr_opt(node, "default")?,
        })
    }
}

#[derive(Debug, Clone)]
/// Attribute declaration wrapper.
pub struct AttrDecls {
    /// Attributes in declaration.
    pub attributes: Vec<Attribute>,
}

impl<'input> XmlLoad<'input> for AttrDecls {
    fn load(node: &Node<'_, 'input>) -> Result<Self, XmlError> {
        Ok(Self {
            attributes: children_with_name(node, "attribute")?,
        })
    }
}

#[derive(Debug, Clone)]
/// Element, representing some part of a type.
pub struct Element {
    /// Element type.
    pub r#type: Option<String>,
    /// Element default value.
    pub default: Option<String>,
    /// Whether the element is nullable.
    pub nillable: bool,
    /// Contents.
    pub contents: Option<ElementContents>,
    /// Element name.
    pub name: Option<String>,
    /// Element reference.
    pub r#ref: Option<String>,
    /// Minimum number of occurences.
    pub min_occurs: Option<u32>,
    /// Maximum number of occurences.
    pub max_occurs: Option<MaxOccurs>,
}

impl<'input> XmlLoad<'input> for Element {
    fn load(node: &Node<'_, 'input>) -> Result<Self, XmlError> {
        Ok(Self {
            r#type: value_from_attr_opt(node, "type")?,
            default: value_from_attr_opt(node, "default")?,
            nillable: value_from_attr_opt(node, "nillable")?.unwrap_or(false),
            name: value_from_attr_opt(node, "name")?,
            r#ref: value_from_attr_opt(node, "ref")?,
            min_occurs: value_from_attr_opt(node, "minOccurs")?,
            max_occurs: value_from_attr_opt(node, "maxOccurs")?,
            contents: first_child_of_type(node)?,
        })
    }
}

#[derive(Debug)]
/// Item in an XSD file.
pub enum XsdFileItem {
    /// A simple type.
    SimpleType(SimpleType),
    /// A complex type.
    ComplexType(ComplexType),
    /// A top level element.
    Element(Element),
}

impl<'input> XmlLoad<'input> for Option<XsdFileItem> {
    fn load(node: &Node<'_, 'input>) -> Result<Self, XmlError> {
        Ok(Some(match node.tag_name().name() {
            "simpleType" => XsdFileItem::SimpleType(XmlLoad::load(node)?),
            "complexType" => XsdFileItem::ComplexType(XmlLoad::load(node)?),
            "element" => XsdFileItem::Element(XmlLoad::load(node)?),
            _ => return Ok(None),
        }))
    }
}

#[derive(Debug)]
/// Type representing a full XmlSchema file.
pub struct XmlSchema {
    /// Top level items.
    pub items: Vec<XsdFileItem>,
    /// Target namespace.
    pub target_namespace: Option<String>,
    /// Schema version.
    pub version: Option<String>,
}

impl<'input> XmlLoad<'input> for XmlSchema {
    fn load(node: &Node<'_, 'input>) -> Result<Self, XmlError> {
        Ok(Self {
            items: children_of_type(node)?,
            target_namespace: value_from_attr_opt(node, "targetNamespace")?,
            version: value_from_attr_opt(node, "version")?,
        })
    }
}

#[derive(Debug)]
/// Top level element in an XML schema when it is a type.
pub enum XsdFileType {
    /// Simple type.
    Simple(SimpleType),
    /// Complex type.
    Complex(ComplexType),
}
