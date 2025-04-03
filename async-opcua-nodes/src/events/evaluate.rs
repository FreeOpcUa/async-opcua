use std::cmp::Ordering;

use regex::Regex;
use tracing::error;

use opcua_types::{
    AttributeId, EventFieldList, FilterOperator, NodeId, NumericRange, QualifiedName, Variant,
    VariantScalarTypeId, VariantTypeId,
};

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
    pub fn evaluate(&self, event: &dyn Event, client_handle: u32) -> Option<EventFieldList> {
        if !self.content_filter.evaluate(event) {
            return None;
        }

        let fields: Vec<_> = self
            .select_clauses
            .iter()
            .map(|c| get_field(event, c))
            .collect();
        Some(EventFieldList {
            client_handle,
            event_fields: Some(fields),
        })
    }
}

macro_rules! cmp_op {
    ($slf:ident, $evt:ident, $op:ident, $pt:pat) => {
        matches!(
            ParsedContentFilter::compare_op(
                $slf.evaluate_operand($evt, &$op.operands[0]),
                $slf.evaluate_operand($evt, &$op.operands[1]),
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
}

enum BitOperation {
    And,
    Or,
}

impl ParsedContentFilter {
    /// Evaluate the content filter, returning `true` if it
    /// passes the filter.
    pub fn evaluate(&self, item: impl AttributeQueryable) -> bool {
        if self.elements.is_empty() {
            return true;
        }
        matches!(self.evulate_element(item, 0), Variant::Boolean(true))
    }

    fn evulate_element(&self, item: impl AttributeQueryable, index: usize) -> Variant {
        let Some(op) = self.elements.get(index) else {
            return Variant::Empty;
        };

        match op.operator {
            FilterOperator::Equals => cmp_op!(self, item, op, Some(Ordering::Equal)),
            FilterOperator::IsNull => {
                (self.evaluate_operand(item, &op.operands[0]) == Variant::Empty).into()
            }
            FilterOperator::GreaterThan => cmp_op!(self, item, op, Some(Ordering::Greater)),
            FilterOperator::LessThan => cmp_op!(self, item, op, Some(Ordering::Less)),
            FilterOperator::GreaterThanOrEqual => {
                cmp_op!(self, item, op, Some(Ordering::Equal | Ordering::Greater))
            }
            FilterOperator::LessThanOrEqual => {
                cmp_op!(self, item, op, Some(Ordering::Equal | Ordering::Less))
            }
            FilterOperator::Like => Self::like(
                self.evaluate_operand(item, &op.operands[0]),
                self.evaluate_operand(item, &op.operands[1]),
            )
            .into(),
            FilterOperator::Not => Self::not(self.evaluate_operand(item, &op.operands[0])),
            FilterOperator::Between => Self::between(
                self.evaluate_operand(item, &op.operands[0]),
                self.evaluate_operand(item, &op.operands[1]),
                self.evaluate_operand(item, &op.operands[2]),
            )
            .into(),
            FilterOperator::InList => Self::in_list(
                self.evaluate_operand(item, &op.operands[0]),
                op.operands
                    .iter()
                    .skip(1)
                    .map(|o| self.evaluate_operand(item, o)),
            )
            .into(),
            FilterOperator::And => Self::and(
                self.evaluate_operand(item, &op.operands[0]),
                self.evaluate_operand(item, &op.operands[1]),
            ),
            FilterOperator::Or => Self::or(
                self.evaluate_operand(item, &op.operands[0]),
                self.evaluate_operand(item, &op.operands[1]),
            ),
            FilterOperator::Cast => Self::cast(
                self.evaluate_operand(item, &op.operands[0]),
                self.evaluate_operand(item, &op.operands[1]),
            ),
            FilterOperator::BitwiseAnd => Self::bitwise_op(
                self.evaluate_operand(item, &op.operands[0]),
                self.evaluate_operand(item, &op.operands[1]),
                BitOperation::And,
            ),
            FilterOperator::BitwiseOr => Self::bitwise_op(
                self.evaluate_operand(item, &op.operands[0]),
                self.evaluate_operand(item, &op.operands[1]),
                BitOperation::Or,
            ),
            _ => Variant::Empty,
        }
    }

    fn evaluate_operand(&self, item: impl AttributeQueryable, op: &ParsedOperand) -> Variant {
        match op {
            ParsedOperand::ElementOperand(o) => self.evulate_element(item, o.index as usize),
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

    fn in_list(lhs: Variant, rhs: impl Iterator<Item = Variant>) -> bool {
        for it in rhs {
            if matches!(Self::compare_op(lhs.clone(), it), Some(Ordering::Equal)) {
                return true;
            }
        }
        false
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

    fn and(lhs: Variant, rhs: Variant) -> Variant {
        let lhs = as_type!(lhs, Boolean, Variant::Empty);
        let rhs = as_type!(rhs, Boolean, Variant::Empty);

        (lhs && rhs).into()
    }

    fn or(lhs: Variant, rhs: Variant) -> Variant {
        let lhs = as_type!(lhs, Boolean, Variant::Empty);
        let rhs = as_type!(rhs, Boolean, Variant::Empty);

        (lhs || rhs).into()
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
            _ => None,
        }
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
                '%' => {
                    if i == 0 || v[i - 1] != '\\' {
                        // A % is a match on zero or more chans unless it is escaped
                        pattern.push_str(".*");
                    } else {
                        pattern.push(*c);
                    }
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
        events::evaluate::like_to_regex, BaseEventType, DefaultTypeTree, Event, ParsedContentFilter,
    };
    use opcua_types::{
        AttributeId, ByteString, ContentFilter, ContentFilterElement, DateTime, FilterOperator,
        LocalizedText, NodeClass, NodeId, NumericRange, ObjectTypeId, Operand,
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
        pub use crate as nodes;
        pub use opcua_types as types;
    }

    #[derive(Event)]
    #[opcua(identifier = "i=123", namespace = "my:namespace:uri")]
    struct TestEvent {
        base: BaseEventType,
        own_namespace_index: u16,
        field: i32,
    }

    impl TestEvent {
        pub fn new(
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
            false,
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
        assert!(!f.evaluate(&event as &dyn Event));
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
        assert!(f.evaluate(&event as &dyn Event));
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
        assert!(!f.evaluate(&event as &dyn Event));
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
        assert!(f.evaluate(&event as &dyn Event));
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
        assert!(!f.evaluate(&event as &dyn Event));
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
        assert!(!f.evaluate(&event as &dyn Event));
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
        assert!(f.evaluate(&event as &dyn Event));
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
        assert!(f.evaluate(&event as &dyn Event));
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
        assert!(f.evaluate(&event as &dyn Event));
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
        assert!(f.evaluate(&event as &dyn Event));
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
        assert!(!f.evaluate(&event as &dyn Event));
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
        assert!(f.evaluate(&event as &dyn Event));
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
        assert!(f.evaluate(&event as &dyn Event));
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
        assert!(f.evaluate(&event as &dyn Event));
    }

    #[test]
    fn test_not_filter() {
        let type_tree = type_tree();
        let f = filter(
            vec![filter_elem(&[Operand::literal(false)], FilterOperator::Not)],
            &type_tree,
        );
        let evt = event(2);
        assert!(f.evaluate(&evt as &dyn Event));

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
        assert!(f.evaluate(&evt as &dyn Event));
        let evt = event(3);
        assert!(!f.evaluate(&evt as &dyn Event));
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
        assert!(f.evaluate(&evt as &dyn Event));
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
        assert!(!f.evaluate(&evt as &dyn Event));
        let evt = event(9);
        assert!(f.evaluate(&evt as &dyn Event));
        let evt = event(10);
        assert!(f.evaluate(&evt as &dyn Event));
        let evt = event(8);
        assert!(f.evaluate(&evt as &dyn Event));
        let evt = event(11);
        assert!(!f.evaluate(&evt as &dyn Event));
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
        assert!(!f.evaluate(&evt as &dyn Event));
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

        assert!(!f.evaluate(&evt as &dyn Event));
        let evt = event(3);
        assert!(f.evaluate(&evt as &dyn Event));
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
        assert!(f.evaluate(&evt as &dyn Event));
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

        assert!(!f.evaluate(&evt as &dyn Event));
        let evt = event(3);
        assert!(f.evaluate(&evt as &dyn Event));
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
        assert!(f.evaluate(&evt as &dyn Event));
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
        assert!(f.evaluate(&evt as &dyn Event));
        let evt = event(4);
        assert!(!f.evaluate(&evt as &dyn Event));
    }
}
