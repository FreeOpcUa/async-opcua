//! Convenient implementation of the `ValueRank` type in OPC-UA,
//! representing the rank of an OPC-UA variable.

use crate::{IntoVariant, Variant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// A representation of the ValueRank type in OPC-UA.
///
/// ValueRank indicates the number of dimensions a variable has.
///
///  - A ValueRank of -1 indicates a scalar value.
///  - A ValueRank of 0 indicates one or more dimensions.
///  - A ValueRank of -2 indicates any value rank.
///  - A ValueRank of -3 indicates a scalar or one dimensional array.
///  - A ValueRank of n (n >= 1) indicates exactly n dimensions.
pub struct ValueRank(i32);

impl From<i32> for ValueRank {
    fn from(value: i32) -> Self {
        if value < -3 {
            return ValueRank::ANY;
        }
        ValueRank(value)
    }
}

impl From<ValueRank> for i32 {
    fn from(value: ValueRank) -> Self {
        value.0
    }
}

impl IntoVariant for ValueRank {
    fn into_variant(self) -> Variant {
        Variant::Int32(self.0)
    }
}

impl ValueRank {
    /// ValueRank indicating a scalar value.
    pub const SCALAR: ValueRank = ValueRank(-1);
    /// ValueRank indicating one or more dimensions.
    pub const ONE_OR_MORE_DIMENSIONS: ValueRank = ValueRank(0);
    /// ValueRank indicating any value rank.
    pub const ANY: ValueRank = ValueRank(-2);
    /// ValueRank indicating a scalar or one dimensional array.
    pub const SCALAR_OR_ONE_DIMENSION: ValueRank = ValueRank(-3);

    /// Create a new ValueRank, returning None if the value is invalid.
    pub fn new_checked(value: i32) -> Option<Self> {
        if value < -3 {
            None
        } else {
            Some(ValueRank(value))
        }
    }

    /// Create a new ValueRank from an i32 value. If the value is invalid
    /// (less than -3), it will be set to ANY.
    pub fn new(value: i32) -> Self {
        ValueRank::from(value)
    }

    /// Check if the ValueRank represents a scalar value.
    pub fn is_scalar(&self) -> bool {
        self == &ValueRank::SCALAR
    }

    /// Create a ValueRank inidicating exactly `n` dimensions.
    pub fn n_dimensions(n: u32) -> Self {
        ValueRank(n as i32)
    }

    /// Get the i32 representation of the ValueRank.
    pub fn to_i32(self) -> i32 {
        self.0
    }
}
