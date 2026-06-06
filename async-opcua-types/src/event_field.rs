//! Core logic for reading Variant values from an event.

use std::collections::HashMap;

use crate::{Array, AttributeId, IntoVariant, NumericRange, QualifiedName, Variant, VariantType};

/// Trait implemented by any type that can be a field in an event.
pub trait EventField {
    /// Get the variant representation of this field, using the given index range.
    ///
    /// # Arguments
    ///
    ///  * `attribute_id` - the attribute to get. Should be either `NodeId` or `Value`.
    ///  * `index_range` - the range of the value to get.
    ///  * `remaining_path` - the remaining path to the actual value to retrieve.
    fn get_value(
        &self,
        attribute_id: AttributeId,
        index_range: &NumericRange,
        remaining_path: &[QualifiedName],
    ) -> Variant;
}

impl<T> EventField for T
where
    T: IntoVariant + Clone,
{
    fn get_value(
        &self,
        attribute_id: AttributeId,
        index_range: &NumericRange,
        remaining_path: &[QualifiedName],
    ) -> Variant {
        if !remaining_path.is_empty()
            || attribute_id != AttributeId::Value
            || !matches!(index_range, NumericRange::None)
        {
            return Variant::Empty;
        }
        let val: Variant = self.clone().into_variant();
        val.range_of_owned(index_range).unwrap_or(Variant::Empty)
    }
}

impl<T> EventField for Option<T>
where
    T: EventField,
{
    fn get_value(
        &self,
        attribute_id: AttributeId,
        index_range: &NumericRange,
        remaining_path: &[QualifiedName],
    ) -> Variant {
        let Some(val) = self.as_ref() else {
            return Variant::Empty;
        };
        val.get_value(attribute_id, index_range, remaining_path)
    }
}

impl<T> EventField for Vec<T>
where
    T: EventField + Clone + VariantType,
{
    fn get_value(
        &self,
        attribute_id: AttributeId,
        index_range: &NumericRange,
        remaining_path: &[QualifiedName],
    ) -> Variant {
        if !remaining_path.is_empty() {
            return Variant::Empty;
        }

        let values: Vec<_> = match index_range {
            NumericRange::None => self
                .iter()
                .map(|v| v.get_value(attribute_id, &NumericRange::None, &[]))
                .collect(),
            NumericRange::Index(i) => {
                return self.get((*i) as usize).cloned().get_value(
                    attribute_id,
                    &NumericRange::None,
                    &[],
                );
            }
            NumericRange::Range(s, e) => {
                if e <= s {
                    return Variant::Empty;
                }
                let Some(r) = self.get(((*s) as usize)..((*e) as usize)) else {
                    return Variant::Empty;
                };
                r.iter()
                    .map(|v| v.get_value(attribute_id, &NumericRange::None, &[]))
                    .collect()
            }
            NumericRange::MultipleRanges(r) => {
                let mut values = Vec::new();
                for range in r {
                    match range {
                        NumericRange::Index(i) => {
                            values.push(self.get((*i) as usize).cloned().get_value(
                                attribute_id,
                                &NumericRange::None,
                                &[],
                            ));
                        }
                        NumericRange::Range(s, e) => {
                            if e <= s {
                                return Variant::Empty;
                            }
                            let Some(r) = self.get(((*s) as usize)..((*e) as usize)) else {
                                continue;
                            };
                            values.extend(
                                r.iter()
                                    .map(|v| v.get_value(attribute_id, &NumericRange::None, &[])),
                            )
                        }
                        _ => return Variant::Empty,
                    }
                }
                values
            }
        };

        let Ok(arr) = Array::new(T::variant_type_id(), values) else {
            return Variant::Empty;
        };
        Variant::Array(Box::new(arr))
    }
}

impl EventField for Variant {
    fn get_value(
        &self,
        attribute_id: AttributeId,
        index_range: &NumericRange,
        remaining_path: &[QualifiedName],
    ) -> Variant {
        if !remaining_path.is_empty() || attribute_id != AttributeId::Value {
            return Variant::Empty;
        }
        self.clone()
            .range_of_owned(index_range)
            .unwrap_or(Variant::Empty)
    }
}

impl EventField for NumericRange {
    fn get_value(
        &self,
        attribute_id: AttributeId,
        index_range: &NumericRange,
        remaining_path: &[QualifiedName],
    ) -> Variant {
        if !remaining_path.is_empty() || attribute_id != AttributeId::Value {
            return Variant::Empty;
        }
        let val: Variant = self.to_string().into();
        val.range_of_owned(index_range).unwrap_or(Variant::Empty)
    }
}

#[derive(Debug)]
/// Struct for an event field placeholder, i.e. a dynamic list of fields.
pub struct PlaceholderEventField<T> {
    items: HashMap<QualifiedName, T>,
}

impl<T> Default for PlaceholderEventField<T> {
    fn default() -> Self {
        Self {
            items: Default::default(),
        }
    }
}

impl<T> PlaceholderEventField<T> {
    /// Create a new empty placeholder field.
    pub fn new() -> Self {
        Self {
            items: HashMap::new(),
        }
    }

    /// Get the field given by `name`.
    pub fn get_field(&self, name: &QualifiedName) -> Option<&T> {
        self.items.get(name)
    }

    /// Get a mutable reference to the field given by `name`.
    pub fn get_field_mut(&mut self, name: &QualifiedName) -> Option<&mut T> {
        self.items.get_mut(name)
    }

    /// Remove the field given by `name`.
    pub fn remove_field(&mut self, name: &QualifiedName) -> Option<T> {
        self.items.remove(name)
    }

    /// Insert `field` with key `name`.
    pub fn insert_field(&mut self, name: QualifiedName, field: T) -> Option<T> {
        self.items.insert(name, field)
    }

    /// Get a mutable reference to the inner items map.
    pub fn items_mut(&mut self) -> &mut HashMap<QualifiedName, T> {
        &mut self.items
    }

    /// Get a reference to the inner items map.
    pub fn items(&self) -> &HashMap<QualifiedName, T> {
        &self.items
    }
}

impl<T: EventField> PlaceholderEventField<T> {
    /// Try to get the inner event value given by `key`.
    pub fn try_get_value(
        &self,
        key: &QualifiedName,
        attribute_id: AttributeId,
        index_range: &NumericRange,
        remaining_path: &[QualifiedName],
    ) -> Option<Variant> {
        let field = self.get_field(key)?;
        Some(field.get_value(attribute_id, index_range, remaining_path))
    }
}
