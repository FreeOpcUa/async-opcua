// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2024 Adam Lock

//! Implementation of content filters.
//!
//! These are used as part of the `Query` service, and for events.

use std::convert::TryFrom;

use crate::{
    attribute::AttributeId, match_extension_object_owned, status_code::StatusCode,
    AttributeOperand, ContentFilter, ContentFilterElement, ElementOperand, ExtensionObject,
    FilterOperator, LiteralOperand, NodeId, NumericRange, QualifiedName, SimpleAttributeOperand,
    Variant,
};

#[derive(PartialEq)]
/// Type of operand.
pub enum OperandType {
    /// Operand pointing at another filter element.
    ElementOperand,
    /// Operand resolving to a literal value.
    LiteralOperand,
    /// Operand resolving to an attribute of some node.
    AttributeOperand,
    /// Operand resolving to an attribute of some type.
    SimpleAttributeOperand,
}

#[derive(Debug, Clone)]
/// A filter operand.
pub enum Operand {
    /// Operand pointing at another filter element.
    ElementOperand(ElementOperand),
    /// Operand resolving to a literal value.
    LiteralOperand(LiteralOperand),
    /// Operand resolving to an attribute of some node.
    AttributeOperand(AttributeOperand),
    /// Operand resolving to an attribute of some type.
    SimpleAttributeOperand(SimpleAttributeOperand),
}

impl From<i8> for LiteralOperand {
    fn from(v: i8) -> Self {
        Self::from(Variant::from(v))
    }
}

impl From<u8> for LiteralOperand {
    fn from(v: u8) -> Self {
        Self::from(Variant::from(v))
    }
}

impl From<i16> for LiteralOperand {
    fn from(v: i16) -> Self {
        Self::from(Variant::from(v))
    }
}

impl From<u16> for LiteralOperand {
    fn from(v: u16) -> Self {
        Self::from(Variant::from(v))
    }
}

impl From<i32> for LiteralOperand {
    fn from(v: i32) -> Self {
        Self::from(Variant::from(v))
    }
}

impl From<u32> for LiteralOperand {
    fn from(v: u32) -> Self {
        Self::from(Variant::from(v))
    }
}

impl From<f32> for LiteralOperand {
    fn from(v: f32) -> Self {
        Self::from(Variant::from(v))
    }
}

impl From<f64> for LiteralOperand {
    fn from(v: f64) -> Self {
        Self::from(Variant::from(v))
    }
}

impl From<bool> for LiteralOperand {
    fn from(v: bool) -> Self {
        Self::from(Variant::from(v))
    }
}

impl From<&str> for LiteralOperand {
    fn from(v: &str) -> Self {
        Self::from(Variant::from(v))
    }
}

impl From<()> for LiteralOperand {
    fn from(_v: ()) -> Self {
        Self::from(Variant::from(()))
    }
}

impl From<Variant> for LiteralOperand {
    fn from(v: Variant) -> Self {
        LiteralOperand { value: v }
    }
}

impl TryFrom<ExtensionObject> for Operand {
    type Error = StatusCode;

    fn try_from(v: ExtensionObject) -> Result<Self, Self::Error> {
        let operand = match_extension_object_owned!(v,
            v: ElementOperand => Self::ElementOperand(v),
            v: LiteralOperand => Self::LiteralOperand(v),
            v: AttributeOperand => Self::AttributeOperand(v),
            v: SimpleAttributeOperand => Self::SimpleAttributeOperand(v),
            _ => return Err(StatusCode::BadFilterOperandInvalid)
        );

        Ok(operand)
    }
}

impl From<Operand> for ExtensionObject {
    fn from(v: Operand) -> Self {
        match v {
            Operand::ElementOperand(op) => ExtensionObject::from_message(op),
            Operand::LiteralOperand(op) => ExtensionObject::from_message(op),
            Operand::AttributeOperand(op) => ExtensionObject::from_message(op),
            Operand::SimpleAttributeOperand(op) => ExtensionObject::from_message(op),
        }
    }
}

impl From<&Operand> for ExtensionObject {
    fn from(v: &Operand) -> Self {
        Self::from(v.clone())
    }
}

impl From<(FilterOperator, Vec<Operand>)> for ContentFilterElement {
    fn from(v: (FilterOperator, Vec<Operand>)) -> ContentFilterElement {
        ContentFilterElement {
            filter_operator: v.0,
            filter_operands: Some(v.1.iter().map(|op| op.into()).collect()),
        }
    }
}

impl From<ElementOperand> for Operand {
    fn from(v: ElementOperand) -> Operand {
        Operand::ElementOperand(v)
    }
}

impl From<LiteralOperand> for Operand {
    fn from(v: LiteralOperand) -> Self {
        Operand::LiteralOperand(v)
    }
}

impl From<SimpleAttributeOperand> for Operand {
    fn from(v: SimpleAttributeOperand) -> Self {
        Operand::SimpleAttributeOperand(v)
    }
}

impl Operand {
    /// Create an element operand with the given index.
    pub fn element(index: u32) -> Operand {
        ElementOperand { index }.into()
    }

    /// Create a literal operand with the given type.
    pub fn literal<T>(literal: T) -> Operand
    where
        T: Into<LiteralOperand>,
    {
        Operand::LiteralOperand(literal.into())
    }

    /// Creates a simple attribute operand. The browse path is the browse name using / as a separator.
    pub fn simple_attribute<T>(
        type_definition_id: T,
        browse_path: &str,
        attribute_id: AttributeId,
        index_range: NumericRange,
    ) -> Operand
    where
        T: Into<NodeId>,
    {
        SimpleAttributeOperand::new(type_definition_id, browse_path, attribute_id, index_range)
            .into()
    }

    /// Get the operand type.
    pub fn operand_type(&self) -> OperandType {
        match self {
            Operand::ElementOperand(_) => OperandType::ElementOperand,
            Operand::LiteralOperand(_) => OperandType::LiteralOperand,
            Operand::AttributeOperand(_) => OperandType::AttributeOperand,
            Operand::SimpleAttributeOperand(_) => OperandType::SimpleAttributeOperand,
        }
    }

    /// Return `true` if the operand is an element operand.
    pub fn is_element(&self) -> bool {
        self.operand_type() == OperandType::ElementOperand
    }

    /// Return `true` if the operand is a literal operand.
    pub fn is_literal(&self) -> bool {
        self.operand_type() == OperandType::LiteralOperand
    }

    /// Return `true` if the operand is an attribute operand.
    pub fn is_attribute(&self) -> bool {
        self.operand_type() == OperandType::AttributeOperand
    }

    /// Return `true` if the operand is a simple attribute operand.
    pub fn is_simple_attribute(&self) -> bool {
        self.operand_type() == OperandType::SimpleAttributeOperand
    }
}

/// This is a convenience for building [`ContentFilter`] using operands as building blocks
/// This builder does not check to see that the content filter is valid, i.e. if you
/// reference an element by index that doesn't exist, or introduce a loop then you will
/// not get an error until you feed it to a server and the server rejects it or breaks.
///
/// The builder takes generic types to make it easier to work with. Operands are converted to
/// extension objects.
#[derive(Debug, Default)]
pub struct ContentFilterBuilder {
    elements: Vec<ContentFilterElement>,
}

impl ContentFilterBuilder {
    /// Create a new empty content filter builder.
    pub fn new() -> Self {
        Self::default()
    }

    fn add_element(
        mut self,
        filter_operator: FilterOperator,
        filter_operands: Vec<Operand>,
    ) -> Self {
        let filter_operands = filter_operands.iter().map(ExtensionObject::from).collect();
        self.elements.push(ContentFilterElement {
            filter_operator,
            filter_operands: Some(filter_operands),
        });
        self
    }

    /// Add an equality operand.
    pub fn eq<T, S>(self, o1: T, o2: S) -> Self
    where
        T: Into<Operand>,
        S: Into<Operand>,
    {
        self.add_element(FilterOperator::Equals, vec![o1.into(), o2.into()])
    }

    /// Add an `is_null` operand.
    pub fn is_null<T>(self, o1: T) -> Self
    where
        T: Into<Operand>,
    {
        self.add_element(FilterOperator::IsNull, vec![o1.into()])
    }

    /// Add a greater than operand.
    pub fn gt<T, S>(self, o1: T, o2: S) -> Self
    where
        T: Into<Operand>,
        S: Into<Operand>,
    {
        self.add_element(FilterOperator::GreaterThan, vec![o1.into(), o2.into()])
    }

    /// Add a less than operand.
    pub fn lt<T, S>(self, o1: T, o2: S) -> Self
    where
        T: Into<Operand>,
        S: Into<Operand>,
    {
        self.add_element(FilterOperator::LessThan, vec![o1.into(), o2.into()])
    }

    /// Add a greater than or equal operand.
    pub fn gte<T, S>(self, o1: T, o2: S) -> Self
    where
        T: Into<Operand>,
        S: Into<Operand>,
    {
        self.add_element(
            FilterOperator::GreaterThanOrEqual,
            vec![o1.into(), o2.into()],
        )
    }

    /// Add a less than or equal operand.
    pub fn lte<T, S>(self, o1: T, o2: S) -> Self
    where
        T: Into<Operand>,
        S: Into<Operand>,
    {
        self.add_element(FilterOperator::LessThanOrEqual, vec![o1.into(), o2.into()])
    }

    /// Add a "like" operand.
    pub fn like<T, S>(self, o1: T, o2: S) -> Self
    where
        T: Into<Operand>,
        S: Into<Operand>,
    {
        self.add_element(FilterOperator::Like, vec![o1.into(), o2.into()])
    }

    /// Add a "not" operand.
    pub fn not<T>(self, o1: T) -> Self
    where
        T: Into<Operand>,
    {
        self.add_element(FilterOperator::Not, vec![o1.into()])
    }

    /// Add a "between" operand.
    pub fn between<T, S, U>(self, o1: T, o2: S, o3: U) -> Self
    where
        T: Into<Operand>,
        S: Into<Operand>,
        U: Into<Operand>,
    {
        self.add_element(
            FilterOperator::Between,
            vec![o1.into(), o2.into(), o3.into()],
        )
    }

    /// Add an "in list" operand.
    pub fn in_list<T, S>(self, o1: T, list_items: Vec<S>) -> Self
    where
        T: Into<Operand>,
        S: Into<Operand>,
    {
        // Make a list from the operand and then the items
        let mut filter_operands = Vec::with_capacity(list_items.len() + 1);
        filter_operands.push(o1.into());
        list_items.into_iter().for_each(|list_item| {
            filter_operands.push(list_item.into());
        });
        self.add_element(FilterOperator::InList, filter_operands)
    }

    /// Add an "and" operand.
    pub fn and<T, S>(self, o1: T, o2: S) -> Self
    where
        T: Into<Operand>,
        S: Into<Operand>,
    {
        self.add_element(FilterOperator::And, vec![o1.into(), o2.into()])
    }

    /// Add an "or" operand.
    pub fn or<T, S>(self, o1: T, o2: S) -> Self
    where
        T: Into<Operand>,
        S: Into<Operand>,
    {
        self.add_element(FilterOperator::Or, vec![o1.into(), o2.into()])
    }

    /// Add a "cast" operand.
    pub fn cast<T, S>(self, o1: T, o2: S) -> Self
    where
        T: Into<Operand>,
        S: Into<Operand>,
    {
        self.add_element(FilterOperator::Cast, vec![o1.into(), o2.into()])
    }

    /// Add a "bitwise and" operand.
    pub fn bitwise_and<T, S>(self, o1: T, o2: S) -> Self
    where
        T: Into<Operand>,
        S: Into<Operand>,
    {
        self.add_element(FilterOperator::BitwiseAnd, vec![o1.into(), o2.into()])
    }

    /// Add a "bitwise or" operand.
    pub fn bitwise_or<T, S>(self, o1: T, o2: S) -> Self
    where
        T: Into<Operand>,
        S: Into<Operand>,
    {
        self.add_element(FilterOperator::BitwiseOr, vec![o1.into(), o2.into()])
    }

    /// Build a content filter.
    pub fn build(self) -> ContentFilter {
        ContentFilter {
            elements: Some(self.elements),
        }
    }
}

impl SimpleAttributeOperand {
    /// Create a new simple attribute operand.
    pub fn new<T>(
        type_definition_id: T,
        browse_path: &str,
        attribute_id: AttributeId,
        index_range: NumericRange,
    ) -> Self
    where
        T: Into<NodeId>,
    {
        // An improbable string to replace escaped forward slashes.
        const ESCAPE_PATTERN: &str = "###!!!###@@@$$$$";
        // Any escaped forward slashes will be replaced temporarily to allow split to work.
        let browse_path = browse_path.replace(r"\/", ESCAPE_PATTERN);
        // If we had a regex with look around support then we could split a pattern such as `r"(?<!\\)/"` where it
        // matches only if the pattern `/` isn't preceded by a backslash. Unfortunately the regex crate doesn't offer
        // this so an escaped forward slash is replaced with an improbable string instead.
        let browse_path = browse_path
            .split('/')
            .map(|s| QualifiedName::new(0, s.replace(ESCAPE_PATTERN, "/")))
            .collect();
        SimpleAttributeOperand {
            type_definition_id: type_definition_id.into(),
            browse_path: Some(browse_path),
            attribute_id: attribute_id as u32,
            index_range,
        }
    }
}
