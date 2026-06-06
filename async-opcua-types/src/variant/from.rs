use uuid::Uuid;

use crate::{
    ByteString, DataValue, DateTime, DateTimeUtc, DiagnosticInfo, DynEncodable, Error,
    ExpandedNodeId, ExtensionObject, Guid, LocalizedText, NodeId, QualifiedName, StatusCode,
    UAString, VariantScalarTypeId,
};

use super::{Variant, XmlElement};

/// Trait for types that can be cast from a variant.
///
/// Unlike `IntoVariant`, this does not imply `TryFrom<Variant>`, due to
/// orphan rules.
pub trait TryFromVariant: Sized {
    /// Try to cast the given variant to this type.
    fn try_from_variant(v: Variant) -> Result<Self, Error>;
}

macro_rules! impl_from_variant_primitive {
    ($tp:ty, $vt:ident) => {
        impl TryFromVariant for $tp {
            fn try_from_variant(v: Variant) -> Result<Self, Error> {
                let cast = v.cast(VariantScalarTypeId::$vt);
                if let Variant::$vt(v) = cast {
                    Ok(v)
                } else {
                    Err(Error::new(
                        StatusCode::BadTypeMismatch,
                        concat!("Unable to convert variant to ", stringify!($vt)),
                    ))
                }
            }
        }
    };
}

macro_rules! impl_from_variant_primitive_unbox {
    ($tp:ty, $vt:ident) => {
        impl TryFromVariant for $tp {
            fn try_from_variant(v: Variant) -> Result<Self, Error> {
                let cast = v.cast(VariantScalarTypeId::$vt);
                if let Variant::$vt(v) = cast {
                    Ok(*v)
                } else {
                    Err(Error::new(
                        StatusCode::BadTypeMismatch,
                        concat!("Unable to convert variant to ", stringify!($vt)),
                    ))
                }
            }
        }
    };
}

impl_from_variant_primitive!(bool, Boolean);
impl_from_variant_primitive!(i8, SByte);
impl_from_variant_primitive!(u8, Byte);
impl_from_variant_primitive!(i16, Int16);
impl_from_variant_primitive!(u16, UInt16);
impl_from_variant_primitive!(i32, Int32);
impl_from_variant_primitive!(u32, UInt32);
impl_from_variant_primitive!(i64, Int64);
impl_from_variant_primitive!(u64, UInt64);
impl_from_variant_primitive!(f32, Float);
impl_from_variant_primitive!(f64, Double);
impl_from_variant_primitive!(UAString, String);
impl_from_variant_primitive!(XmlElement, XmlElement);
impl_from_variant_primitive_unbox!(DateTime, DateTime);
impl_from_variant_primitive_unbox!(Guid, Guid);
impl_from_variant_primitive!(StatusCode, StatusCode);
impl_from_variant_primitive!(ByteString, ByteString);
impl_from_variant_primitive_unbox!(QualifiedName, QualifiedName);
impl_from_variant_primitive_unbox!(LocalizedText, LocalizedText);
impl_from_variant_primitive_unbox!(NodeId, NodeId);
impl_from_variant_primitive_unbox!(ExpandedNodeId, ExpandedNodeId);
impl_from_variant_primitive!(ExtensionObject, ExtensionObject);
impl_from_variant_primitive_unbox!(DataValue, DataValue);
impl_from_variant_primitive_unbox!(DiagnosticInfo, DiagnosticInfo);

impl TryFromVariant for String {
    fn try_from_variant(v: Variant) -> Result<Self, Error> {
        Ok(UAString::try_from_variant(v)?.into())
    }
}

impl TryFromVariant for Uuid {
    fn try_from_variant(v: Variant) -> Result<Self, Error> {
        Ok(Guid::try_from_variant(v)?.into())
    }
}

impl TryFromVariant for DateTimeUtc {
    fn try_from_variant(v: Variant) -> Result<Self, Error> {
        Ok(DateTime::try_from_variant(v)?.as_chrono())
    }
}

impl<T> TryFromVariant for T
where
    T: DynEncodable,
{
    fn try_from_variant(v: Variant) -> Result<Self, Error> {
        let Variant::ExtensionObject(o) = v else {
            return Err(Error::new(
                StatusCode::BadTypeMismatch,
                "Variant is not extension object",
            ));
        };
        o.into_inner_as().map(|v| *v).ok_or_else(|| {
            Error::new(
                StatusCode::BadTypeMismatch,
                "Variant is extension object, but not requested type",
            )
        })
    }
}

impl<T> TryFromVariant for Option<T>
where
    T: TryFromVariant,
{
    fn try_from_variant(v: Variant) -> Result<Self, Error> {
        if v.is_empty() {
            return Ok(None);
        }
        Ok(Some(T::try_from_variant(v)?))
    }
}

impl<T> TryFromVariant for Vec<T>
where
    T: TryFromVariant,
{
    fn try_from_variant(v: Variant) -> Result<Self, Error> {
        match v {
            Variant::Empty => Err(Error::new(
                StatusCode::BadTypeMismatch,
                "Attempted to cast empty variant to array",
            )),
            Variant::Array(a) => a
                .values
                .into_iter()
                .map(|v| T::try_from_variant(v))
                .collect::<Result<Vec<_>, _>>(),
            r => Ok(vec![T::try_from_variant(r)?]),
        }
    }
}

impl TryFromVariant for Variant {
    fn try_from_variant(v: Variant) -> Result<Self, Error> {
        Ok(v)
    }
}

impl<const N: usize, T> TryFromVariant for [T; N]
where
    T: TryFromVariant,
{
    fn try_from_variant(v: Variant) -> Result<Self, Error> {
        let vals = match v {
            Variant::Empty => {
                return Err(Error::new(
                    StatusCode::BadTypeMismatch,
                    "Attempted to cast empty variant to array",
                ))
            }
            Variant::Array(a) => {
                if N != a.values.len() {
                    return Err(Error::new(
                        StatusCode::BadTypeMismatch,
                        "Array size mismatch",
                    ));
                }
                a.values
                    .into_iter()
                    .map(|v| T::try_from_variant(v))
                    .collect::<Result<Vec<_>, _>>()?
            }
            r => {
                if N != 1 {
                    return Err(Error::new(
                        StatusCode::BadTypeMismatch,
                        "Array size mismatch",
                    ));
                }
                vec![T::try_from_variant(r)?]
            }
        };

        vals.try_into()
            .map_err(|_| Error::new(StatusCode::BadTypeMismatch, "Array size mismatch"))
    }
}
