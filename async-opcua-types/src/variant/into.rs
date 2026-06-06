use uuid::Uuid;

use crate::{
    ByteString, DataValue, DateTime, DateTimeUtc, DiagnosticInfo, DynEncodable, ExpandedNodeId,
    ExtensionObject, Guid, LocalizedText, NodeId, QualifiedName, StatusCode, UAString,
};

use super::{Array, Variant, VariantScalarTypeId, VariantType, XmlElement};

/// Trait implemented by types that can be converted to a variant.
/// This is a workaround for specialization in `EventField`.
///
/// Any type that implements this also implements `Into<Variant>` (and variant
/// implements `From<T> where T : IntoVariant`). Variant also implements
/// `From<Vec<T>>` and `From<Option<T>>`, so prefer to use that unless you
/// need to special case `Vec` and `Option` behavior, like `EventField` does.
pub trait IntoVariant {
    /// Convert self into a variant.
    fn into_variant(self) -> Variant;
}

macro_rules! impl_into_variant {
    ($tp:ty, $venum:ident) => {
        impl IntoVariant for $tp {
            fn into_variant(self) -> Variant {
                Variant::$venum(self)
            }
        }
    };
}

macro_rules! impl_into_variant_boxed {
    ($tp:ty, $venum:ident) => {
        impl IntoVariant for $tp {
            fn into_variant(self) -> Variant {
                Variant::$venum(Box::new(self))
            }
        }

        impl IntoVariant for Box<$tp> {
            fn into_variant(self) -> Variant {
                Variant::$venum(self)
            }
        }
    };
}

impl From<()> for Variant {
    fn from(_: ()) -> Self {
        Variant::Empty
    }
}

impl_into_variant!(bool, Boolean);
impl_into_variant!(i8, SByte);
impl_into_variant!(u8, Byte);
impl_into_variant!(i16, Int16);
impl_into_variant!(u16, UInt16);
impl_into_variant!(i32, Int32);
impl_into_variant!(u32, UInt32);
impl_into_variant!(i64, Int64);
impl_into_variant!(u64, UInt64);
impl_into_variant!(f32, Float);
impl_into_variant!(f64, Double);
impl_into_variant!(UAString, String);
impl_into_variant!(XmlElement, XmlElement);
impl_into_variant_boxed!(DateTime, DateTime);
impl_into_variant_boxed!(Guid, Guid);
impl_into_variant!(StatusCode, StatusCode);
impl_into_variant!(ByteString, ByteString);
impl_into_variant_boxed!(QualifiedName, QualifiedName);
impl_into_variant_boxed!(LocalizedText, LocalizedText);
impl_into_variant_boxed!(NodeId, NodeId);
impl_into_variant_boxed!(ExpandedNodeId, ExpandedNodeId);
impl_into_variant!(ExtensionObject, ExtensionObject);
impl_into_variant_boxed!(DataValue, DataValue);
impl_into_variant_boxed!(DiagnosticInfo, DiagnosticInfo);
impl_into_variant_boxed!(Array, Array);

impl IntoVariant for &str {
    fn into_variant(self) -> Variant {
        Variant::String(UAString::from(self))
    }
}

impl IntoVariant for String {
    fn into_variant(self) -> Variant {
        Variant::String(UAString::from(self))
    }
}

impl IntoVariant for Uuid {
    fn into_variant(self) -> Variant {
        Variant::Guid(Box::new(self.into()))
    }
}

impl IntoVariant for DateTimeUtc {
    fn into_variant(self) -> Variant {
        Variant::DateTime(Box::new(self.into()))
    }
}

impl<T> IntoVariant for T
where
    T: DynEncodable,
{
    fn into_variant(self) -> Variant {
        Variant::ExtensionObject(ExtensionObject::new(self))
    }
}

impl<T> From<T> for Variant
where
    T: IntoVariant,
{
    fn from(value: T) -> Self {
        value.into_variant()
    }
}

impl<T> From<Option<T>> for Variant
where
    T: Into<Variant>,
{
    fn from(value: Option<T>) -> Self {
        match value {
            Some(v) => v.into(),
            None => Variant::Empty,
        }
    }
}

impl<'a, T> From<&'a Vec<T>> for Variant
where
    T: Into<Variant> + VariantType + Clone,
{
    fn from(value: &'a Vec<T>) -> Self {
        Self::from(value.as_slice())
    }
}

impl<T> From<Vec<T>> for Variant
where
    T: Into<Variant> + VariantType,
{
    fn from(value: Vec<T>) -> Self {
        let array: Vec<Variant> = value.into_iter().map(|v| v.into()).collect();
        Variant::from((T::variant_type_id(), array))
    }
}

impl<'a, T> From<&'a [T]> for Variant
where
    T: Into<Variant> + VariantType + Clone,
{
    fn from(value: &'a [T]) -> Self {
        let array: Vec<Variant> = value.iter().map(|v| v.clone().into()).collect();
        Variant::from((T::variant_type_id(), array))
    }
}

impl<'a, 'b> From<(VariantScalarTypeId, &'a [&'b str])> for Variant {
    fn from(v: (VariantScalarTypeId, &'a [&'b str])) -> Self {
        let values: Vec<Variant> = v.1.iter().map(|v| Variant::from(*v)).collect();
        let value = Array::new(v.0, values).unwrap();
        Variant::from(value)
    }
}

impl<T: Into<Variant>> From<(VariantScalarTypeId, Vec<T>)> for Variant {
    fn from(v: (VariantScalarTypeId, Vec<T>)) -> Self {
        let value = Array::new(v.0, v.1.into_iter().map(|v| v.into()).collect::<Vec<_>>()).unwrap();
        Variant::from(value)
    }
}

impl<T: Into<Variant>> From<(VariantScalarTypeId, Vec<T>, Vec<u32>)> for Variant {
    fn from(v: (VariantScalarTypeId, Vec<T>, Vec<u32>)) -> Self {
        let value = Array::new_multi(
            v.0,
            v.1.into_iter().map(|v| v.into()).collect::<Vec<_>>(),
            v.2,
        )
        .unwrap();
        Variant::from(value)
    }
}
