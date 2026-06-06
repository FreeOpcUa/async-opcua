use crate::Error;

/// Trait implemented by simple OPC-UA enums and bitfields.
pub trait UaEnum: Sized {
    /// The numeric type used to represent this enum when encoded.
    type Repr: Copy;

    /// Convert from a numeric value to an instance of this enum.
    fn from_repr(repr: Self::Repr) -> Result<Self, Error>;

    /// Convert this enum into its numeric representation.
    fn into_repr(self) -> Self::Repr;

    /// Get the string representation of this enum,
    /// on the form `[NAME]_[REPRESENTATION]`, i.e. `KEY_1`.
    fn as_str(&self) -> &'static str;

    /// Convert from the string representation of this enum to its value,
    /// on the form `[NAME]_[REPRESENTATION]`, i.e. `KEY_1`.
    fn from_str(val: &str) -> Result<Self, Error>;
}
