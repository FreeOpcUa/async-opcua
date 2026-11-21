use std::cmp::Ordering;

use regex::Regex;
use tracing::error;

use opcua_types::{
    AttributeId, EventFieldList, FilterOperator, NodeId, NumericRange, QualifiedName, Variant,
    VariantScalarTypeId, VariantTypeId,
};

use crate::TypeTree;

use super::{
    event::Event,
    validation::{
        ParsedContentFilter, ParsedEventFilter, ParsedOperand, ParsedSimpleAttributeOperand,
    },
};

impl ParsedEventFilter {
    /// Evaluate the event filter, returning `None` if the
    /// filter does not accept the event, and a list of event fields fetched from
    /// the event if it does.
    pub fn evaluate(
        &self,
        event: &dyn Event,
        client_handle: u32,
        type_tree: &dyn TypeTree,
    ) -> Option<EventFieldList> {
        if !self.content_filter.evaluate(event, type_tree) {
            return None;
        }

        let fields: Vec<_> = self
            .select_clauses
            .iter()
            .map(|c| c.as_ref().map_or(Variant::Empty, |c| get_field(event, c)))
            .collect();
        Some(EventFieldList {
            client_handle,
            event_fields: Some(fields),
        })
    }
}

/// Evaluate an operand of a filter element.
///
/// An element with a null operand evaluates to null, so if the operand is
/// null this returns null from the function evaluating the element.
macro_rules! operand {
    ($slf:ident, $evt:ident, $tt:ident, $op:ident, $idx:expr) => {{
        let v = $slf.evaluate_operand($evt, $tt, &$op.operands[$idx]);
        if v.is_empty() {
            return Variant::Empty;
        }
        v
    }};
}

macro_rules! cmp_op {
    ($slf:ident, $evt:ident, $tt:ident, $op:ident, $pt:pat) => {
        matches!(
            ParsedContentFilter::compare_op(
                operand!($slf, $evt, $tt, $op, 0),
                operand!($slf, $evt, $tt, $op, 1),
            ),
            $pt
        )
        .into()
    };
}

macro_rules! as_type {
    ($v:expr, $t:ident, $def:expr) => {{
        let v = $v.convert(VariantTypeId::Scalar(VariantScalarTypeId::$t));
        let Variant::$t(v) = v else {
            return $def;
        };
        v
    }};
}

macro_rules! bw_op {
    ($lhs:expr, $rhs:expr, $op:expr) => {{
        match $op {
            BitOperation::And => ($lhs & $rhs).into(),
            BitOperation::Or => ($lhs | $rhs).into(),
        }
    }};
}

/// Trait for something that can be queried for attribute values.
///
/// Implemented by `dyn Event`. Types passed to a content filter must
/// implement this.
pub trait AttributeQueryable: Copy {
    /// Get an attribute value from the item.
    fn get_attribute(
        &self,
        type_definition_id: &NodeId,
        browse_path: &[QualifiedName],
        attribute_id: AttributeId,
        index_range: &NumericRange,
    ) -> Variant;

    /// Get the type definition of the item.
    fn get_type(&self) -> NodeId;
}

impl AttributeQueryable for &dyn Event {
    fn get_attribute(
        &self,
        type_definition_id: &NodeId,
        browse_path: &[QualifiedName],
        attribute_id: AttributeId,
        index_range: &NumericRange,
    ) -> Variant {
        self.get_field(type_definition_id, attribute_id, index_range, browse_path)
    }

    fn get_type(&self) -> NodeId {
        self.event_type_id().clone()
    }
}

enum BitOperation {
    And,
    Or,
}

impl ParsedContentFilter {
    /// Evaluate the content filter, returning `true` if it
    /// passes the filter.
    pub fn evaluate(&self, item: impl AttributeQueryable, type_tree: &dyn TypeTree) -> bool {
        if self.elements.is_empty() {
            return true;
        }
        matches!(
            self.evulate_element(item, type_tree, 0),
            Variant::Boolean(true)
        )
    }

    fn evulate_element(
        &self,
        item: impl AttributeQueryable,
        type_tree: &dyn TypeTree,
        index: usize,
    ) -> Variant {
        let Some(op) = self.elements.get(index) else {
            return Variant::Empty;
        };

        match op.operator {
            FilterOperator::Equals => Self::equals(
                operand!(self, item, type_tree, op, 0),
                operand!(self, item, type_tree, op, 1),
            )
            .into(),
            FilterOperator::IsNull => {
                (self.evaluate_operand(item, type_tree, &op.operands[0]) == Variant::Empty).into()
            }
            FilterOperator::GreaterThan => {
                cmp_op!(self, item, type_tree, op, Some(Ordering::Greater))
            }
            FilterOperator::LessThan => cmp_op!(self, item, type_tree, op, Some(Ordering::Less)),
            FilterOperator::GreaterThanOrEqual => {
                cmp_op!(
                    self,
                    item,
                    type_tree,
                    op,
                    Some(Ordering::Equal | Ordering::Greater)
                )
            }
            FilterOperator::LessThanOrEqual => {
                cmp_op!(
                    self,
                    item,
                    type_tree,
                    op,
                    Some(Ordering::Equal | Ordering::Less)
                )
            }
            FilterOperator::Like => Self::like(
                operand!(self, item, type_tree, op, 0),
                operand!(self, item, type_tree, op, 1),
            )
            .into(),
            FilterOperator::Not => {
                Self::not(self.evaluate_operand(item, type_tree, &op.operands[0]))
            }
            FilterOperator::Between => Self::between(
                operand!(self, item, type_tree, op, 0),
                operand!(self, item, type_tree, op, 1),
                operand!(self, item, type_tree, op, 2),
            )
            .into(),
            FilterOperator::InList => Self::in_list(
                operand!(self, item, type_tree, op, 0),
                op.operands
                    .iter()
                    .skip(1)
                    .map(|o| self.evaluate_operand(item, type_tree, o)),
            ),
            FilterOperator::And => Self::and(
                self.evaluate_operand(item, type_tree, &op.operands[0]),
                self.evaluate_operand(item, type_tree, &op.operands[1]),
            ),
            FilterOperator::Or => Self::or(
                self.evaluate_operand(item, type_tree, &op.operands[0]),
                self.evaluate_operand(item, type_tree, &op.operands[1]),
            ),
            FilterOperator::Cast => Self::cast(
                self.evaluate_operand(item, type_tree, &op.operands[0]),
                self.evaluate_operand(item, type_tree, &op.operands[1]),
            ),
            FilterOperator::BitwiseAnd => Self::bitwise_op(
                self.evaluate_operand(item, type_tree, &op.operands[0]),
                self.evaluate_operand(item, type_tree, &op.operands[1]),
                BitOperation::And,
            ),
            FilterOperator::BitwiseOr => Self::bitwise_op(
                self.evaluate_operand(item, type_tree, &op.operands[0]),
                self.evaluate_operand(item, type_tree, &op.operands[1]),
                BitOperation::Or,
            ),
            FilterOperator::OfType => Self::of_type(
                self.evaluate_operand(item, type_tree, &op.operands[0]),
                item,
                type_tree,
            )
            .into(),
            // TODO: Support RelatedTo. InView is not really possible until we build
            // proper view support.
            _ => Variant::Empty,
        }
    }

    fn evaluate_operand(
        &self,
        item: impl AttributeQueryable,
        type_tree: &dyn TypeTree,
        op: &ParsedOperand,
    ) -> Variant {
        match op {
            ParsedOperand::ElementOperand(o) => {
                self.evulate_element(item, type_tree, o.index as usize)
            }
            ParsedOperand::LiteralOperand(o) => o.value.clone(),
            ParsedOperand::AttributeOperand(_) => unreachable!(),
            ParsedOperand::SimpleAttributeOperand(o) => item.get_attribute(
                &o.type_definition_id,
                &o.browse_path,
                o.attribute_id,
                &o.index_range,
            ),
        }
    }

    /// Equality as used by `Equals` and `InList`, after implicitly converting
    /// the operands to a common type.
    ///
    /// Unlike the ordering operators this is defined for every type, so a
    /// `NodeId`, `String` or `Guid` can be equal to another of the same kind
    /// even though it cannot be greater or less than it.
    fn equals(lhs: Variant, rhs: Variant) -> bool {
        let (lhs, rhs) = Self::convert(lhs, rhs);
        match (&lhs, &rhs) {
            // A failed conversion leaves a null behind, and the operands are
            // then not equal. Nothing is equal to a null, not even another
            // null, that is what `IsNull` is for.
            (Variant::Empty, _) | (_, Variant::Empty) => false,
            // Floating point values are equal when the ordering operators
            // say they are.
            (Variant::Float(_), Variant::Float(_)) | (Variant::Double(_), Variant::Double(_)) => {
                matches!(Self::compare_op(lhs, rhs), Some(Ordering::Equal))
            }
            _ => lhs == rhs,
        }
    }

    /// `lhs` must not be null. A null in the list does not hide a match, but
    /// without a match it makes the result null: the value might have been
    /// equal to whatever is missing.
    fn in_list(lhs: Variant, rhs: impl Iterator<Item = Variant>) -> Variant {
        let mut any_null = false;
        for it in rhs {
            if it.is_empty() {
                any_null = true;
            } else if Self::equals(lhs.clone(), it) {
                return true.into();
            }
        }
        if any_null {
            Variant::Empty
        } else {
            false.into()
        }
    }

    fn between(it: Variant, gte: Variant, lte: Variant) -> bool {
        matches!(
            Self::compare_op(it.clone(), gte),
            Some(Ordering::Greater | Ordering::Equal)
        ) && matches!(
            Self::compare_op(it, lte),
            Some(Ordering::Less | Ordering::Equal)
        )
    }

    fn not(rhs: Variant) -> Variant {
        let rhs = as_type!(rhs, Boolean, Variant::Empty);
        (!rhs).into()
    }

    /// Resolve an operand of `And` or `Or` to a Boolean. An operand that
    /// cannot be resolved to one is considered null.
    fn as_boolean(v: Variant) -> Option<bool> {
        match v.convert(VariantTypeId::Scalar(VariantScalarTypeId::Boolean)) {
            Variant::Boolean(v) => Some(v),
            _ => None,
        }
    }

    /// Logical AND with null operands, OPC UA Part 4 table 123: false if
    /// either operand is false, even if the other one is null.
    fn and(lhs: Variant, rhs: Variant) -> Variant {
        match (Self::as_boolean(lhs), Self::as_boolean(rhs)) {
            (Some(false), _) | (_, Some(false)) => false.into(),
            (Some(true), Some(true)) => true.into(),
            _ => Variant::Empty,
        }
    }

    /// Logical OR with null operands, OPC UA Part 4 table 124: true if
    /// either operand is true, even if the other one is null.
    fn or(lhs: Variant, rhs: Variant) -> Variant {
        match (Self::as_boolean(lhs), Self::as_boolean(rhs)) {
            (Some(true), _) | (_, Some(true)) => true.into(),
            (Some(false), Some(false)) => false.into(),
            _ => Variant::Empty,
        }
    }

    fn like(lhs: Variant, rhs: Variant) -> bool {
        let lhs = as_type!(lhs, String, false);
        let rhs = as_type!(rhs, String, false);
        let Ok(re) = like_to_regex(rhs.as_ref()) else {
            return false;
        };
        re.is_match(lhs.as_ref())
    }

    fn cast(lhs: Variant, rhs: Variant) -> Variant {
        let type_id = match rhs {
            Variant::NodeId(n) => {
                let Ok(t) = VariantTypeId::try_from(&*n) else {
                    return Variant::Empty;
                };
                t
            }
            Variant::ExpandedNodeId(n) => {
                let Ok(t) = VariantTypeId::try_from(&n.node_id) else {
                    return Variant::Empty;
                };
                t
            }
            _ => return Variant::Empty,
        };
        lhs.cast(type_id)
    }

    fn convert(lhs: Variant, rhs: Variant) -> (Variant, Variant) {
        let lhs_type = lhs.type_id();
        match lhs_type.precedence().cmp(&rhs.type_id().precedence()) {
            std::cmp::Ordering::Less => {
                let c = rhs.convert(lhs_type);
                (lhs, c)
            }
            std::cmp::Ordering::Equal => (lhs, rhs),
            std::cmp::Ordering::Greater => (lhs.convert(rhs.type_id()), rhs),
        }
    }

    fn bitwise_op(lhs: Variant, rhs: Variant, op: BitOperation) -> Variant {
        let (lhs, rhs) = Self::convert(lhs, rhs);

        match (lhs, rhs) {
            (Variant::SByte(lhs), Variant::SByte(rhs)) => bw_op!(lhs, rhs, op),
            (Variant::Byte(lhs), Variant::Byte(rhs)) => bw_op!(lhs, rhs, op),
            (Variant::Int16(lhs), Variant::Int16(rhs)) => bw_op!(lhs, rhs, op),
            (Variant::Int32(lhs), Variant::Int32(rhs)) => bw_op!(lhs, rhs, op),
            (Variant::Int64(lhs), Variant::Int64(rhs)) => bw_op!(lhs, rhs, op),
            (Variant::UInt16(lhs), Variant::UInt16(rhs)) => bw_op!(lhs, rhs, op),
            (Variant::UInt32(lhs), Variant::UInt32(rhs)) => bw_op!(lhs, rhs, op),
            (Variant::UInt64(lhs), Variant::UInt64(rhs)) => bw_op!(lhs, rhs, op),
            _ => Variant::Empty,
        }
    }

    fn compare_op(lhs: Variant, rhs: Variant) -> Option<Ordering> {
        let (lhs, rhs) = Self::convert(lhs, rhs);
        match (lhs, rhs) {
            (Variant::SByte(lhs), Variant::SByte(rhs)) => Some(lhs.cmp(&rhs)),
            (Variant::Byte(lhs), Variant::Byte(rhs)) => Some(lhs.cmp(&rhs)),
            (Variant::Int16(lhs), Variant::Int16(rhs)) => Some(lhs.cmp(&rhs)),
            (Variant::Int32(lhs), Variant::Int32(rhs)) => Some(lhs.cmp(&rhs)),
            (Variant::Int64(lhs), Variant::Int64(rhs)) => Some(lhs.cmp(&rhs)),
            (Variant::UInt16(lhs), Variant::UInt16(rhs)) => Some(lhs.cmp(&rhs)),
            (Variant::UInt32(lhs), Variant::UInt32(rhs)) => Some(lhs.cmp(&rhs)),
            (Variant::UInt64(lhs), Variant::UInt64(rhs)) => Some(lhs.cmp(&rhs)),
            (Variant::Double(lhs), Variant::Double(rhs)) => Some(lhs.total_cmp(&rhs)),
            (Variant::Float(lhs), Variant::Float(rhs)) => Some(lhs.total_cmp(&rhs)),
            (Variant::Boolean(lhs), Variant::Boolean(rhs)) => Some(lhs.cmp(&rhs)),
            (Variant::DateTime(lhs), Variant::DateTime(rhs)) => Some(lhs.cmp(&rhs)),
            _ => None,
        }
    }

    fn of_type(lhs: Variant, item: impl AttributeQueryable, type_tree: &dyn TypeTree) -> bool {
        let type_id = as_type!(lhs, NodeId, false);

        let item_type = item.get_type();
        type_tree.is_subtype_of(&item_type, &type_id)
    }
}

fn get_field(event: &dyn Event, attr: &ParsedSimpleAttributeOperand) -> Variant {
    event.get_field(
        &attr.type_definition_id,
        attr.attribute_id,
        &attr.index_range,
        &attr.browse_path,
    )
}

/// Converts the OPC UA SQL-esque Like format into a regular expression.
fn like_to_regex(v: &str) -> Result<Regex, ()> {
    // Give a reasonable buffer
    let mut pattern = String::with_capacity(v.len() * 2);

    let mut in_list = false;

    // Turn the chars into a vec to make it easier to index them
    let v = v.chars().collect::<Vec<char>>();

    pattern.push('^');
    v.iter().enumerate().for_each(|(i, c)| {
        if in_list {
            if *c == ']' && (i == 0 || v[i - 1] != '\\') {
                // Close the list
                in_list = false;
                pattern.push(*c);
            } else {
                // Chars in list are escaped if required
                match c {
                    '$' | '(' | ')' | '.' | '+' | '*' | '?' => {
                        // Other regex chars except for ^ are escaped
                        pattern.push('\\');
                        pattern.push(*c);
                    }
                    _ => {
                        // Everything between two [] will be treated as-is
                        pattern.push(*c);
                    }
                }
            }
        } else {
            match c {
                '$' | '^' | '(' | ')' | '.' | '+' | '*' | '?' => {
                    // Other regex chars are escaped
                    pattern.push('\\');
                    pattern.push(*c);
                }
                '[' => {
                    // Opens a list of chars to match
                    if i == 0 || v[i - 1] != '\\' {
                        // Open the list
                        in_list = true;
                    }
                    pattern.push(*c);
                }
                // A % is a match on zero or more chans unless it is escaped
                '%' if i == 0 || v[i - 1] != '\\' => {
                    pattern.push_str(".*");
                }
                '_' => {
                    if i == 0 || v[i - 1] != '\\' {
                        // A _ is a match on a single char unless it is escaped
                        pattern.push('?');
                    } else {
                        // Remove escaping of the underscore
                        let _ = pattern.pop();
                        pattern.push(*c);
                    }
                }
                _ => {
                    pattern.push(*c);
                }
            }
        }
    });
    pattern.push('$');
    Regex::new(&pattern).map_err(|err| {
        error!("Problem parsing, error = {}", err);
    })
}

#[cfg(test)]
mod tests {
    use regex::Regex;

    use crate::{
        events::evaluate::like_to_regex, BaseEventType, DefaultTypeTree, Event,
        ParsedContentFilter, ParsedEventFilter,
    };
    use opcua_types::{
        AttributeId, ByteString, ContentFilter, ContentFilterElement, DateTime, EventFilter,
        ExpandedNodeId, FilterOperator, Guid, LocalizedText, NodeClass, NodeId, NumericRange,
        ObjectTypeId, Operand, SimpleAttributeOperand, StatusCode, Variant,
    };

    fn compare_regex(r1: Regex, r2: Regex) {
        assert_eq!(r1.as_str(), r2.as_str());
    }

    #[test]
    fn like_to_regex_tests() {
        compare_regex(like_to_regex("").unwrap(), Regex::new("^$").unwrap());
        compare_regex(like_to_regex("^$").unwrap(), Regex::new(r"^\^\$$").unwrap());
        compare_regex(like_to_regex("%").unwrap(), Regex::new("^.*$").unwrap());
        compare_regex(like_to_regex("[%]").unwrap(), Regex::new("^[%]$").unwrap());
        compare_regex(like_to_regex("[_]").unwrap(), Regex::new("^[_]$").unwrap());
        compare_regex(
            like_to_regex(r"[\]]").unwrap(),
            Regex::new(r"^[\]]$").unwrap(),
        );
        compare_regex(
            like_to_regex("[$().+*?]").unwrap(),
            Regex::new(r"^[\$\(\)\.\+\*\?]$").unwrap(),
        );
        compare_regex(like_to_regex("_").unwrap(), Regex::new("^?$").unwrap());
        compare_regex(
            like_to_regex("[a-z]").unwrap(),
            Regex::new("^[a-z]$").unwrap(),
        );
        compare_regex(
            like_to_regex("[abc]").unwrap(),
            Regex::new("^[abc]$").unwrap(),
        );
        compare_regex(
            like_to_regex(r"\[\]").unwrap(),
            Regex::new(r"^\[\]$").unwrap(),
        );
        compare_regex(
            like_to_regex("[^0-9]").unwrap(),
            Regex::new("^[^0-9]$").unwrap(),
        );

        // Some samples from OPC UA part 4
        let re = like_to_regex("Th[ia][ts]%").unwrap();
        assert!(re.is_match("That is fine"));
        assert!(re.is_match("This is fine"));
        assert!(re.is_match("That as one"));
        assert!(!re.is_match("Then at any")); // Spec says this should pass when it obviously wouldn't

        let re = like_to_regex("%en%").unwrap();
        assert!(re.is_match("entail"));
        assert!(re.is_match("green"));
        assert!(re.is_match("content"));

        let re = like_to_regex("abc[13-68]").unwrap();
        assert!(re.is_match("abc1"));
        assert!(!re.is_match("abc2"));
        assert!(re.is_match("abc3"));
        assert!(re.is_match("abc4"));
        assert!(re.is_match("abc5"));
        assert!(re.is_match("abc6"));
        assert!(!re.is_match("abc7"));
        assert!(re.is_match("abc8"));

        let re = like_to_regex("ABC[^13-5]").unwrap();
        assert!(!re.is_match("ABC1"));
        assert!(re.is_match("ABC2"));
        assert!(!re.is_match("ABC3"));
        assert!(!re.is_match("ABC4"));
        assert!(!re.is_match("ABC5"));
    }

    mod opcua {
        pub(super) use crate as nodes;
        pub(super) use opcua_types as types;
    }

    #[derive(Event)]
    #[opcua(identifier = "i=123", namespace = "my:namespace:uri")]
    struct TestEvent {
        base: BaseEventType,
        own_namespace_index: u16,
        field: i32,
    }

    impl TestEvent {
        pub(super) fn new(
            type_id: impl Into<NodeId>,
            event_id: ByteString,
            message: impl Into<LocalizedText>,
            time: DateTime,
            field: i32,
        ) -> Self {
            Self {
                base: BaseEventType::new(type_id, event_id, message, time),
                field,
                own_namespace_index: 1,
            }
        }
    }

    fn type_tree() -> DefaultTypeTree {
        let mut type_tree = DefaultTypeTree::new();

        let event_type_id = NodeId::new(1, 123);
        type_tree.add_type_node(
            &event_type_id,
            &ObjectTypeId::BaseEventType.into(),
            NodeClass::ObjectType,
        );
        type_tree.add_type_property(
            &NodeId::new(1, "field"),
            &event_type_id,
            &[&"Field".into()],
            NodeClass::Variable,
        );

        type_tree
    }

    fn filter(
        elements: Vec<ContentFilterElement>,
        type_tree: &DefaultTypeTree,
    ) -> ParsedContentFilter {
        let (_, f) = ParsedContentFilter::parse(
            ContentFilter {
                elements: Some(elements),
            },
            type_tree,
            false,
            &[FilterOperator::InView, FilterOperator::RelatedTo],
        );
        f.unwrap()
    }

    fn filter_elem(operands: &[Operand], op: FilterOperator) -> ContentFilterElement {
        ContentFilterElement {
            filter_operator: op,
            filter_operands: Some(operands.iter().map(|o| o.into()).collect()),
        }
    }

    fn event(field: i32) -> TestEvent {
        TestEvent::new(
            NodeId::new(1, 123),
            ByteString::null(),
            "message",
            DateTime::now(),
            field,
        )
    }

    #[test]
    fn test_equality_filter() {
        let type_tree = type_tree();
        let f = filter(
            vec![filter_elem(
                &[Operand::literal(10), Operand::literal(9)],
                FilterOperator::Equals,
            )],
            &type_tree,
        );
        let event = event(2);
        assert!(!f.evaluate(&event as &dyn Event, &type_tree));
        let f = filter(
            vec![filter_elem(
                &[
                    Operand::literal(2),
                    Operand::simple_attribute(
                        ObjectTypeId::BaseEventType,
                        "Field",
                        AttributeId::Value,
                        NumericRange::None,
                    ),
                ],
                FilterOperator::Equals,
            )],
            &type_tree,
        );
        assert!(f.evaluate(&event as &dyn Event, &type_tree));
    }

    fn event_type_operand() -> Operand {
        Operand::simple_attribute(
            ObjectTypeId::BaseEventType,
            "EventType",
            AttributeId::Value,
            NumericRange::None,
        )
    }

    /// Evaluate a filter with a single binary operator against a test event.
    fn evaluate_binary(lhs: Operand, rhs: Operand, op: FilterOperator) -> bool {
        let type_tree = type_tree();
        let f = filter(vec![filter_elem(&[lhs, rhs], op)], &type_tree);
        f.evaluate(&event(2) as &dyn Event, &type_tree)
    }

    #[test]
    fn test_equality_filter_non_numeric_types() {
        let literal = |v: Variant| Operand::literal(v);
        let equals = |lhs: Variant, rhs: Variant| {
            evaluate_binary(literal(lhs), literal(rhs), FilterOperator::Equals)
        };

        // NodeId, against a field of the event and against a literal.
        assert!(evaluate_binary(
            event_type_operand(),
            literal(NodeId::new(1, 123).into()),
            FilterOperator::Equals
        ));
        assert!(!evaluate_binary(
            event_type_operand(),
            literal(NodeId::new(1, 456).into()),
            FilterOperator::Equals
        ));
        assert!(equals(
            NodeId::new(1, "a").into(),
            NodeId::new(1, "a").into()
        ));
        assert!(!equals(
            NodeId::new(1, "a").into(),
            NodeId::new(2, "a").into()
        ));

        // String
        assert!(equals("source".into(), "source".into()));
        assert!(!equals("source".into(), "other".into()));

        // DateTime
        let time = DateTime::now();
        assert!(equals(time.into(), time.into()));
        assert!(!equals(time.into(), DateTime::null().into()));

        // Guid
        let guid = Guid::new();
        assert!(equals(guid.clone().into(), guid.clone().into()));
        assert!(!equals(guid.into(), Guid::new().into()));

        // ByteString
        assert!(equals(
            ByteString::from(vec![1u8, 2, 3]).into(),
            ByteString::from(vec![1u8, 2, 3]).into()
        ));
        assert!(!equals(
            ByteString::from(vec![1u8, 2, 3]).into(),
            ByteString::from(vec![1u8, 2, 4]).into()
        ));

        // Operands of different types are converted to a common type first.
        assert!(equals(
            NodeId::new(1, 123).into(),
            ExpandedNodeId::from(NodeId::new(1, 123)).into()
        ));
        assert!(!equals(
            NodeId::new(1, 123).into(),
            ExpandedNodeId::from(NodeId::new(1, 456)).into()
        ));

        // No conversion between the two, so they are not equal.
        assert!(!equals(NodeId::new(1, 123).into(), 123.into()));
        assert!(!equals(time.into(), "source".into()));

        // Numeric operands are still converted to a common type and compared.
        assert!(equals(2i32.into(), 2i64.into()));
        assert!(equals(2u8.into(), 2.0f64.into()));
        assert!(equals(1.5f32.into(), 1.5f64.into()));
        assert!(!equals(2i32.into(), 3i64.into()));
        assert!(!equals(1.5f32.into(), 2.5f64.into()));

        // A null is not equal to anything, including another null.
        assert!(!equals(Variant::Empty, Variant::Empty));
        assert!(!equals(Variant::Empty, NodeId::new(1, 123).into()));
    }

    #[test]
    fn test_ordering_filters_reject_unordered_types() {
        // Two equal NodeIds are equal, but neither is greater or less than the other.
        for op in [
            FilterOperator::GreaterThan,
            FilterOperator::GreaterThanOrEqual,
            FilterOperator::LessThan,
            FilterOperator::LessThanOrEqual,
        ] {
            assert!(!evaluate_binary(
                event_type_operand(),
                Operand::literal(Variant::from(NodeId::new(1, 123))),
                op
            ));
        }
    }

    #[test]
    fn test_lt_filter() {
        let type_tree = type_tree();
        let f = filter(
            vec![filter_elem(
                &[Operand::literal(10), Operand::literal(9)],
                FilterOperator::LessThan,
            )],
            &type_tree,
        );
        let event = event(2);
        assert!(!f.evaluate(&event as &dyn Event, &type_tree));
        let f = filter(
            vec![filter_elem(
                &[
                    Operand::literal(1),
                    Operand::simple_attribute(
                        ObjectTypeId::BaseEventType,
                        "Field",
                        AttributeId::Value,
                        NumericRange::None,
                    ),
                ],
                FilterOperator::LessThan,
            )],
            &type_tree,
        );
        assert!(f.evaluate(&event as &dyn Event, &type_tree));
        let f = filter(
            vec![filter_elem(
                &[
                    Operand::literal(2),
                    Operand::simple_attribute(
                        ObjectTypeId::BaseEventType,
                        "Field",
                        AttributeId::Value,
                        NumericRange::None,
                    ),
                ],
                FilterOperator::LessThan,
            )],
            &type_tree,
        );
        assert!(!f.evaluate(&event as &dyn Event, &type_tree));
    }

    #[test]
    fn test_lte_filter() {
        let type_tree = type_tree();
        let f = filter(
            vec![filter_elem(
                &[Operand::literal(10), Operand::literal(9)],
                FilterOperator::LessThanOrEqual,
            )],
            &type_tree,
        );
        let event = event(2);
        assert!(!f.evaluate(&event as &dyn Event, &type_tree));
        let f = filter(
            vec![filter_elem(
                &[
                    Operand::literal(1),
                    Operand::simple_attribute(
                        ObjectTypeId::BaseEventType,
                        "Field",
                        AttributeId::Value,
                        NumericRange::None,
                    ),
                ],
                FilterOperator::LessThanOrEqual,
            )],
            &type_tree,
        );
        assert!(f.evaluate(&event as &dyn Event, &type_tree));
        let f = filter(
            vec![filter_elem(
                &[
                    Operand::literal(2),
                    Operand::simple_attribute(
                        ObjectTypeId::BaseEventType,
                        "Field",
                        AttributeId::Value,
                        NumericRange::None,
                    ),
                ],
                FilterOperator::LessThanOrEqual,
            )],
            &type_tree,
        );
        assert!(f.evaluate(&event as &dyn Event, &type_tree));
    }

    #[test]
    fn test_gt_filter() {
        let type_tree = type_tree();
        let f = filter(
            vec![filter_elem(
                &[Operand::literal(10), Operand::literal(9)],
                FilterOperator::GreaterThan,
            )],
            &type_tree,
        );
        let event = event(2);
        assert!(f.evaluate(&event as &dyn Event, &type_tree));
        let f = filter(
            vec![filter_elem(
                &[
                    Operand::literal(3),
                    Operand::simple_attribute(
                        ObjectTypeId::BaseEventType,
                        "Field",
                        AttributeId::Value,
                        NumericRange::None,
                    ),
                ],
                FilterOperator::GreaterThan,
            )],
            &type_tree,
        );
        assert!(f.evaluate(&event as &dyn Event, &type_tree));
        let f = filter(
            vec![filter_elem(
                &[
                    Operand::literal(2),
                    Operand::simple_attribute(
                        ObjectTypeId::BaseEventType,
                        "Field",
                        AttributeId::Value,
                        NumericRange::None,
                    ),
                ],
                FilterOperator::GreaterThan,
            )],
            &type_tree,
        );
        assert!(!f.evaluate(&event as &dyn Event, &type_tree));
    }

    #[test]
    fn test_gte_filter() {
        let type_tree = type_tree();
        let f = filter(
            vec![filter_elem(
                &[Operand::literal(10), Operand::literal(9)],
                FilterOperator::GreaterThanOrEqual,
            )],
            &type_tree,
        );
        let event = event(2);
        assert!(f.evaluate(&event as &dyn Event, &type_tree));
        let f = filter(
            vec![filter_elem(
                &[
                    Operand::literal(3),
                    Operand::simple_attribute(
                        ObjectTypeId::BaseEventType,
                        "Field",
                        AttributeId::Value,
                        NumericRange::None,
                    ),
                ],
                FilterOperator::GreaterThanOrEqual,
            )],
            &type_tree,
        );
        assert!(f.evaluate(&event as &dyn Event, &type_tree));
        let f = filter(
            vec![filter_elem(
                &[
                    Operand::literal(2),
                    Operand::simple_attribute(
                        ObjectTypeId::BaseEventType,
                        "Field",
                        AttributeId::Value,
                        NumericRange::None,
                    ),
                ],
                FilterOperator::GreaterThanOrEqual,
            )],
            &type_tree,
        );
        assert!(f.evaluate(&event as &dyn Event, &type_tree));
    }

    #[test]
    fn test_not_filter() {
        let type_tree = type_tree();
        let f = filter(
            vec![filter_elem(&[Operand::literal(false)], FilterOperator::Not)],
            &type_tree,
        );
        let evt = event(2);
        assert!(f.evaluate(&evt as &dyn Event, &type_tree));

        let f = filter(
            vec![
                filter_elem(&[Operand::element(1)], FilterOperator::Not),
                filter_elem(
                    &[
                        Operand::simple_attribute(
                            ObjectTypeId::BaseEventType,
                            "Field",
                            AttributeId::Value,
                            NumericRange::None,
                        ),
                        Operand::literal(3),
                    ],
                    FilterOperator::Equals,
                ),
            ],
            &type_tree,
        );
        assert!(f.evaluate(&evt as &dyn Event, &type_tree));
        let evt = event(3);
        assert!(!f.evaluate(&evt as &dyn Event, &type_tree));
    }

    #[test]
    fn test_between_filter() {
        let type_tree = type_tree();
        let f = filter(
            vec![filter_elem(
                &[
                    Operand::literal(9),
                    Operand::literal(8),
                    Operand::literal(10),
                ],
                FilterOperator::Between,
            )],
            &type_tree,
        );
        let evt = event(2);
        assert!(f.evaluate(&evt as &dyn Event, &type_tree));
        let f = filter(
            vec![filter_elem(
                &[
                    Operand::simple_attribute(
                        ObjectTypeId::BaseEventType,
                        "Field",
                        AttributeId::Value,
                        NumericRange::None,
                    ),
                    Operand::literal(8),
                    Operand::literal(10),
                ],
                FilterOperator::Between,
            )],
            &type_tree,
        );
        assert!(!f.evaluate(&evt as &dyn Event, &type_tree));
        let evt = event(9);
        assert!(f.evaluate(&evt as &dyn Event, &type_tree));
        let evt = event(10);
        assert!(f.evaluate(&evt as &dyn Event, &type_tree));
        let evt = event(8);
        assert!(f.evaluate(&evt as &dyn Event, &type_tree));
        let evt = event(11);
        assert!(!f.evaluate(&evt as &dyn Event, &type_tree));
    }

    #[test]
    fn test_ordering_filters_date_time() {
        let type_tree = type_tree();
        let evaluate = |operands: &[Operand], op: FilterOperator| {
            let f = filter(vec![filter_elem(operands, op)], &type_tree);
            f.evaluate(&event(2) as &dyn Event, &type_tree)
        };
        let literal = |v: DateTime| Operand::literal(Variant::from(v));
        let compare = |lhs: DateTime, rhs: DateTime, op: FilterOperator| {
            evaluate(&[literal(lhs), literal(rhs)], op)
        };
        let early = DateTime::ymd(2020, 1, 1);
        let middle = DateTime::ymd(2021, 1, 1);
        let late = DateTime::ymd(2022, 1, 1);

        assert!(compare(late, early, FilterOperator::GreaterThan));
        assert!(!compare(early, late, FilterOperator::GreaterThan));
        assert!(!compare(early, early, FilterOperator::GreaterThan));

        assert!(compare(late, early, FilterOperator::GreaterThanOrEqual));
        assert!(compare(early, early, FilterOperator::GreaterThanOrEqual));
        assert!(!compare(early, late, FilterOperator::GreaterThanOrEqual));

        assert!(compare(early, late, FilterOperator::LessThan));
        assert!(!compare(late, early, FilterOperator::LessThan));
        assert!(!compare(early, early, FilterOperator::LessThan));

        assert!(compare(early, late, FilterOperator::LessThanOrEqual));
        assert!(compare(early, early, FilterOperator::LessThanOrEqual));
        assert!(!compare(late, early, FilterOperator::LessThanOrEqual));

        // Against a field of the event, which was raised just now.
        let time = || {
            Operand::simple_attribute(
                ObjectTypeId::BaseEventType,
                "Time",
                AttributeId::Value,
                NumericRange::None,
            )
        };
        assert!(evaluate(
            &[time(), literal(late)],
            FilterOperator::GreaterThan
        ));
        assert!(!evaluate(
            &[time(), literal(late)],
            FilterOperator::LessThan
        ));

        let between = |it: DateTime, low: DateTime, high: DateTime| {
            evaluate(
                &[literal(it), literal(low), literal(high)],
                FilterOperator::Between,
            )
        };
        assert!(between(middle, early, late));
        assert!(between(early, early, late));
        assert!(between(late, early, late));
        assert!(!between(early, middle, late));
        assert!(!between(late, early, middle));

        // There is no implicit conversion to or from DateTime, so it has no
        // order relative to a value of any other type.
        assert!(!evaluate(
            &[literal(late), Operand::literal(1)],
            FilterOperator::GreaterThan
        ));
        assert!(!evaluate(
            &[Operand::literal(1), literal(late)],
            FilterOperator::LessThan
        ));
    }

    #[test]
    fn test_and_filter() {
        let type_tree = type_tree();
        let f = filter(
            vec![filter_elem(
                &[Operand::literal(true), Operand::literal(false)],
                FilterOperator::And,
            )],
            &type_tree,
        );
        let evt = event(2);
        assert!(!f.evaluate(&evt as &dyn Event, &type_tree));
        let f = filter(
            vec![
                filter_elem(
                    &[Operand::element(1), Operand::element(2)],
                    FilterOperator::And,
                ),
                filter_elem(
                    &[
                        Operand::simple_attribute(
                            ObjectTypeId::BaseEventType,
                            "Field",
                            AttributeId::Value,
                            NumericRange::None,
                        ),
                        Operand::literal(3),
                    ],
                    FilterOperator::Equals,
                ),
                filter_elem(
                    &[Operand::literal(3), Operand::literal(3)],
                    FilterOperator::Equals,
                ),
            ],
            &type_tree,
        );

        assert!(!f.evaluate(&evt as &dyn Event, &type_tree));
        let evt = event(3);
        assert!(f.evaluate(&evt as &dyn Event, &type_tree));
    }

    #[test]
    fn test_or_filter() {
        let type_tree = type_tree();
        let f = filter(
            vec![filter_elem(
                &[Operand::literal(true), Operand::literal(false)],
                FilterOperator::Or,
            )],
            &type_tree,
        );
        let evt = event(2);
        assert!(f.evaluate(&evt as &dyn Event, &type_tree));
        let f = filter(
            vec![
                filter_elem(
                    &[Operand::element(1), Operand::element(2)],
                    FilterOperator::Or,
                ),
                filter_elem(
                    &[
                        Operand::simple_attribute(
                            ObjectTypeId::BaseEventType,
                            "Field",
                            AttributeId::Value,
                            NumericRange::None,
                        ),
                        Operand::literal(3),
                    ],
                    FilterOperator::Equals,
                ),
                filter_elem(
                    &[Operand::literal(3), Operand::literal(2)],
                    FilterOperator::Equals,
                ),
            ],
            &type_tree,
        );

        assert!(!f.evaluate(&evt as &dyn Event, &type_tree));
        let evt = event(3);
        assert!(f.evaluate(&evt as &dyn Event, &type_tree));
    }

    #[test]
    fn test_in_list() {
        let type_tree = type_tree();
        let f = filter(
            vec![filter_elem(
                &[
                    Operand::literal(1),
                    Operand::literal(2),
                    Operand::literal(3),
                    Operand::literal(1),
                ],
                FilterOperator::InList,
            )],
            &type_tree,
        );
        let evt = event(2);
        assert!(f.evaluate(&evt as &dyn Event, &type_tree));
        let f = filter(
            vec![filter_elem(
                &[
                    Operand::simple_attribute(
                        ObjectTypeId::BaseEventType,
                        "Field",
                        AttributeId::Value,
                        NumericRange::None,
                    ),
                    Operand::literal(1),
                    Operand::literal(2),
                    Operand::literal(3),
                ],
                FilterOperator::InList,
            )],
            &type_tree,
        );
        assert!(f.evaluate(&evt as &dyn Event, &type_tree));
        let evt = event(4);
        assert!(!f.evaluate(&evt as &dyn Event, &type_tree));
    }

    #[test]
    fn test_in_list_node_id() {
        // This is the where clause clients such as Python asyncua build to
        // subscribe to events of a given type: EventType InList [type, subtypes...]
        let in_list = |types: &[NodeId]| {
            let type_tree = type_tree();
            let mut operands = vec![event_type_operand()];
            operands.extend(
                types
                    .iter()
                    .map(|t| Operand::literal(Variant::from(t.clone()))),
            );
            let f = filter(
                vec![filter_elem(&operands, FilterOperator::InList)],
                &type_tree,
            );
            f.evaluate(&event(2) as &dyn Event, &type_tree)
        };

        assert!(in_list(&[NodeId::new(1, 123)]));
        assert!(in_list(&[NodeId::new(1, 456), NodeId::new(1, 123)]));
        assert!(!in_list(&[NodeId::new(1, 456), NodeId::new(1, 789)]));
    }

    #[test]
    fn test_of_type() {
        let type_tree = type_tree();
        let f = filter(
            vec![filter_elem(
                &[Operand::literal(NodeId::new(1, 123))],
                FilterOperator::OfType,
            )],
            &type_tree,
        );
        let evt = event(2);
        assert!(f.evaluate(&evt as &dyn Event, &type_tree));

        // Test a non-match as well...
        let f = filter(
            vec![filter_elem(
                &[Operand::literal(NodeId::new(1, 456))],
                FilterOperator::OfType,
            )],
            &type_tree,
        );
        let evt = event(2);
        assert!(!f.evaluate(&evt as &dyn Event, &type_tree));

        // And with the super-type
        let f = filter(
            vec![filter_elem(
                &[Operand::literal(ObjectTypeId::BaseEventType)],
                FilterOperator::OfType,
            )],
            &type_tree,
        );
        let evt = event(2);
        assert!(f.evaluate(&evt as &dyn Event, &type_tree));
    }

    #[test]
    fn test_invalid_select_clause_keeps_its_place() {
        let type_tree = type_tree();
        let clause = |type_id: NodeId, path: &str| {
            SimpleAttributeOperand::new(type_id, path, AttributeId::Value, NumericRange::None)
        };
        let (result, f) = ParsedEventFilter::new(
            EventFilter {
                where_clause: ContentFilter { elements: None },
                select_clauses: Some(vec![
                    clause(ObjectTypeId::BaseEventType.into(), "Message"),
                    clause(NodeId::new(1, 123), "NoSuchField"),
                    clause(NodeId::new(1, 123), "Field"),
                ]),
            },
            &type_tree,
        );
        assert_eq!(
            result.select_clause_results,
            Some(vec![
                StatusCode::Good,
                StatusCode::BadNodeIdUnknown,
                StatusCode::Good
            ])
        );

        let fields = f
            .unwrap()
            .evaluate(&event(2) as &dyn Event, 1, &type_tree)
            .unwrap()
            .event_fields
            .unwrap();
        assert_eq!(
            fields,
            vec![
                Variant::from(LocalizedText::from("message")),
                Variant::Empty,
                Variant::from(2i32),
            ]
        );
    }

    /// The result of the first element of a filter: `Variant::Empty` is null.
    fn evaluate_elements(elements: Vec<ContentFilterElement>) -> Variant {
        let type_tree = type_tree();
        let f = filter(elements, &type_tree);
        f.evulate_element(&event(2) as &dyn Event, &type_tree, 0)
    }

    fn null() -> Operand {
        Operand::literal(Variant::Empty)
    }

    #[test]
    fn test_null_operand() {
        // A field the event does not have is null as well.
        let missing = || {
            Operand::simple_attribute(
                ObjectTypeId::BaseEventType,
                "NoSuchField",
                AttributeId::Value,
                NumericRange::None,
            )
        };

        // An element with a null operand is null, not false.
        for op in [
            FilterOperator::Equals,
            FilterOperator::GreaterThan,
            FilterOperator::LessThan,
            FilterOperator::GreaterThanOrEqual,
            FilterOperator::LessThanOrEqual,
        ] {
            for operands in [
                [null(), Operand::literal(1)],
                [Operand::literal(1), null()],
                [null(), null()],
                [missing(), Operand::literal(1)],
            ] {
                assert_eq!(
                    evaluate_elements(vec![filter_elem(&operands, op)]),
                    Variant::Empty,
                    "{op:?}"
                );
            }
        }
        assert_eq!(
            evaluate_elements(vec![filter_elem(
                &[null(), Operand::literal("%")],
                FilterOperator::Like
            )]),
            Variant::Empty
        );
        assert_eq!(
            evaluate_elements(vec![filter_elem(
                &[Operand::literal("a"), null()],
                FilterOperator::Like
            )]),
            Variant::Empty
        );
        for operands in [
            [null(), Operand::literal(1), Operand::literal(3)],
            [Operand::literal(2), null(), Operand::literal(3)],
            [Operand::literal(2), Operand::literal(1), null()],
        ] {
            assert_eq!(
                evaluate_elements(vec![filter_elem(&operands, FilterOperator::Between)]),
                Variant::Empty
            );
        }

        // IsNull is the one operator that is true for a null operand.
        assert_eq!(
            evaluate_elements(vec![filter_elem(&[null()], FilterOperator::IsNull)]),
            Variant::Boolean(true)
        );
        assert_eq!(
            evaluate_elements(vec![filter_elem(&[missing()], FilterOperator::IsNull)]),
            Variant::Boolean(true)
        );

        // Operands that are not null, but cannot be compared, are still false.
        assert_eq!(
            evaluate_elements(vec![filter_elem(
                &[Operand::literal(NodeId::new(1, 123)), Operand::literal(1)],
                FilterOperator::Equals
            )]),
            Variant::Boolean(false)
        );

        // Null survives a FilterOperator::Not, so neither the element nor its negation
        // accepts the event.
        let type_tree = type_tree();
        let evt = event(2);
        let equals = filter_elem(&[missing(), Operand::literal(1)], FilterOperator::Equals);
        let f = filter(vec![equals.clone()], &type_tree);
        assert!(!f.evaluate(&evt as &dyn Event, &type_tree));
        let f = filter(
            vec![
                filter_elem(&[Operand::element(1)], FilterOperator::Not),
                equals,
            ],
            &type_tree,
        );
        assert!(!f.evaluate(&evt as &dyn Event, &type_tree));
    }

    #[test]
    fn test_in_list_null_operand() {
        let in_list = |operands: &[Operand]| {
            evaluate_elements(vec![filter_elem(operands, FilterOperator::InList)])
        };
        let literal = |v: i32| Operand::literal(v);

        // Nothing is equal to a null.
        assert_eq!(in_list(&[null(), literal(1)]), Variant::Empty);
        assert_eq!(in_list(&[null(), null()]), Variant::Empty);
        // A null in the list does not hide a match...
        assert_eq!(
            in_list(&[literal(1), null(), literal(1)]),
            Variant::Boolean(true)
        );
        assert_eq!(
            in_list(&[literal(1), literal(1), null()]),
            Variant::Boolean(true)
        );
        // ...but without a match it is unknown whether the value is in the list.
        assert_eq!(in_list(&[literal(1), null(), literal(2)]), Variant::Empty);
        assert_eq!(
            in_list(&[literal(1), literal(2), literal(3)]),
            Variant::Boolean(false)
        );
    }

    #[test]
    fn test_and_or_null_operand() {
        // OPC UA Part 4, tables 123 and 124.
        let yes = || Operand::literal(true);
        let no = || Operand::literal(false);
        let and = |lhs: Operand, rhs: Operand| {
            evaluate_elements(vec![filter_elem(&[lhs, rhs], FilterOperator::And)])
        };
        let or = |lhs: Operand, rhs: Operand| {
            evaluate_elements(vec![filter_elem(&[lhs, rhs], FilterOperator::Or)])
        };

        assert_eq!(and(yes(), yes()), Variant::Boolean(true));
        assert_eq!(and(yes(), no()), Variant::Boolean(false));
        assert_eq!(and(no(), yes()), Variant::Boolean(false));
        assert_eq!(and(no(), no()), Variant::Boolean(false));
        assert_eq!(and(yes(), null()), Variant::Empty);
        assert_eq!(and(null(), yes()), Variant::Empty);
        assert_eq!(and(no(), null()), Variant::Boolean(false));
        assert_eq!(and(null(), no()), Variant::Boolean(false));
        assert_eq!(and(null(), null()), Variant::Empty);

        assert_eq!(or(yes(), yes()), Variant::Boolean(true));
        assert_eq!(or(yes(), no()), Variant::Boolean(true));
        assert_eq!(or(no(), yes()), Variant::Boolean(true));
        assert_eq!(or(no(), no()), Variant::Boolean(false));
        assert_eq!(or(yes(), null()), Variant::Boolean(true));
        assert_eq!(or(null(), yes()), Variant::Boolean(true));
        assert_eq!(or(no(), null()), Variant::Empty);
        assert_eq!(or(null(), no()), Variant::Empty);
        assert_eq!(or(null(), null()), Variant::Empty);

        // An operand that is not a Boolean counts as null.
        assert_eq!(and(yes(), Operand::literal("text")), Variant::Empty);
        assert_eq!(or(Operand::literal("text"), yes()), Variant::Boolean(true));
    }
}
