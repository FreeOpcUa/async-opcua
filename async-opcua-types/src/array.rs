//! The [`Array`] type, used to contain OPC-UA arrays, which are potentially
//! multi-dimensional, but stored as a single vector of Variants.

use thiserror::Error;
use tracing::error;

use crate::variant::*;

/// An array is a vector of values with an optional number of dimensions.
/// It is expected that the multi-dimensional array is valid, or it might not be encoded or decoded
/// properly. The dimensions should match the number of values, or the array is invalid.
#[derive(Debug, Clone, PartialEq)]
pub struct Array {
    /// Type of elements in the array
    pub value_type: VariantScalarTypeId,

    /// Values are stored sequentially
    pub values: Vec<Variant>,

    /// Multi dimension array which can contain any scalar type, all the same type. Nested
    /// arrays are rejected. Higher rank dimensions are serialized first. For example an array
    /// with dimensions `[2,2,2]` is written in this order - `[0,0,0]`, `[0,0,1]`, `[0,1,0]`, `[0,1,1]`,
    /// `[1,0,0]`, `[1,0,1]`, `[1,1,0]`, `[1,1,1]`.
    pub dimensions: Option<Vec<u32>>,
}

#[derive(Debug, Error)]
/// Error returned when creating arrays.
pub enum ArrayError {
    #[error("Variant array do not match outer type")]
    /// Variant array does not match outer type.
    ContentMismatch,
    /// Variant array dimensions multiplied together does not equal the actual array length.
    #[error("Variant array dimensions multiplied together do not equal the actual array length")]
    InvalidDimensions,
}

impl Array {
    /// Constructs a single dimension array from the supplied values
    pub fn new<V>(value_type: VariantScalarTypeId, values: V) -> Result<Array, ArrayError>
    where
        V: Into<Vec<Variant>>,
    {
        let values = values.into();
        Self::validate_array_type_to_values(value_type, &values)?;
        Ok(Array {
            value_type,
            values,
            dimensions: None,
        })
    }

    /// Constructs a multi-dimensional array from the supplied values. The values are still provided
    /// and held as a single dimension array but a separate dimensions parameter indicates how the
    /// values are accessed.
    pub fn new_multi<V, D>(
        value_type: VariantScalarTypeId,
        values: V,
        dimensions: D,
    ) -> Result<Array, ArrayError>
    where
        V: Into<Vec<Variant>>,
        D: Into<Vec<u32>>,
    {
        let values = values.into();
        let dimensions: Vec<_> = dimensions.into();

        if !Self::validate_dimensions(values.len(), &dimensions) {
            return Err(ArrayError::InvalidDimensions);
        }

        Self::validate_array_type_to_values(value_type, &values)?;
        Ok(Array {
            value_type,
            values,
            dimensions: Some(dimensions),
        })
    }

    /// This is a runtime check to ensure the type of the array also matches the types of the variants in the array.
    fn validate_array_type_to_values(
        value_type: VariantScalarTypeId,
        values: &[Variant],
    ) -> Result<(), ArrayError> {
        if !values_are_of_type(values, value_type) {
            // If the values exist, then validate them to the type
            Err(ArrayError::ContentMismatch)
        } else {
            Ok(())
        }
    }

    /// Whether this is a valid array.
    pub fn is_valid(&self) -> bool {
        self.is_valid_dimensions() && Self::array_is_valid(&self.values)
    }

    /// Encoding mask.
    pub fn encoding_mask(&self) -> u8 {
        let mut encoding_mask = self.value_type.encoding_mask();
        encoding_mask |= EncodingMask::ARRAY_VALUES_BIT;
        if self.dimensions.is_some() {
            encoding_mask |= EncodingMask::ARRAY_DIMENSIONS_BIT;
        }
        encoding_mask
    }

    /// Tests that the variants in the slice all have the same variant type
    fn array_is_valid(values: &[Variant]) -> bool {
        if values.is_empty() {
            true
        } else {
            let expected_type_id = values[0].type_id();
            match expected_type_id {
                VariantTypeId::Array(_, _) => {
                    // Nested arrays are explicitly NOT allowed
                    error!("Variant array contains nested array {:?}", expected_type_id);
                    false
                }
                VariantTypeId::Empty => {
                    error!("Variant array contains null values");
                    false
                }
                VariantTypeId::Scalar(s) => {
                    if values.len() > 1 {
                        values_are_of_type(&values[1..], s)
                    } else {
                        true
                    }
                }
            }
        }
    }

    fn validate_dimensions(values_len: usize, dimensions: &[u32]) -> bool {
        let len = dimensions
            .iter()
            .map(|d| *d as usize)
            .reduce(|a, b| a * b)
            .unwrap_or(0);
        len == values_len
    }

    fn is_valid_dimensions(&self) -> bool {
        if let Some(ref dimensions) = self.dimensions {
            Self::validate_dimensions(self.values.len(), dimensions)
        } else {
            true
        }
    }
}

/// Check that all elements in the slice of arrays are the same type.
pub fn values_are_of_type(values: &[Variant], expected_type: VariantScalarTypeId) -> bool {
    // Ensure all remaining elements are the same type as the first element
    let found_unexpected = values.iter().any(|v| match v.type_id() {
        VariantTypeId::Array(_, _) => true,
        VariantTypeId::Scalar(s) => s != expected_type,
        VariantTypeId::Empty => true,
    });
    if found_unexpected {
        error!(
            "Variant array's type is expected to be {:?} but found other types in it",
            expected_type
        );
    };
    !found_unexpected
}
