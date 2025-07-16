use std::{
    fmt,
    hash::{Hash, Hasher},
    str::FromStr,
};

use crate::{node_id::id_ref::IdentifierRef, ByteString, Guid, GuidRef, UAString};

/// The kind of identifier, numeric, string, guid or byte
#[derive(Eq, PartialEq, Clone, Debug)]
pub enum Identifier {
    /// Numeric node ID identifier. i=123
    Numeric(u32),
    /// String node ID identifier, s=...
    String(UAString),
    /// GUID node ID identifier, g=...
    Guid(Guid),
    /// Opaque node ID identifier, o=...
    ByteString(ByteString),
}

/// Value used as discriminator when hashing numeric node IDs.
pub const IDENTIFIER_HASH_NUMERIC: u8 = 0;
/// Value used as discriminator when hashing string node IDs.
pub const IDENTIFIER_HASH_STRING: u8 = 1;
/// Value used as discriminator when hashing Guid node IDs.
pub const IDENTIFIER_HASH_GUID: u8 = 2;
/// Value used as discriminator when hashing byte string node IDs.
pub const IDENTIFIER_HASH_BYTE_STRING: u8 = 3;

impl std::hash::Hash for Identifier {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self {
            Identifier::Numeric(v) => {
                IDENTIFIER_HASH_NUMERIC.hash(state);
                v.hash(state)
            }
            Identifier::String(v) => {
                IDENTIFIER_HASH_STRING.hash(state);
                v.as_ref().hash(state)
            }
            Identifier::Guid(v) => {
                IDENTIFIER_HASH_GUID.hash(state);
                v.as_bytes().hash(state)
            }
            Identifier::ByteString(v) => {
                IDENTIFIER_HASH_BYTE_STRING.hash(state);
                v.as_ref().hash(state)
            }
        }
    }
}

impl fmt::Display for Identifier {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Identifier::Numeric(v) => write!(f, "i={}", *v),
            Identifier::String(v) => write!(f, "s={v}"),
            Identifier::Guid(v) => write!(f, "g={v:?}"),
            Identifier::ByteString(v) => write!(f, "b={}", v.as_base64()),
        }
    }
}

impl FromStr for Identifier {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() < 2 {
            Err(())
        } else {
            let k = &s[..2];
            let v = &s[2..];
            match k {
                "i=" => v.parse::<u32>().map(|v| v.into()).map_err(|_| ()),
                "s=" => Ok(UAString::from(v).into()),
                "g=" => Guid::from_str(v).map(|v| v.into()).map_err(|_| ()),
                "b=" => ByteString::from_base64(v).map(|v| v.into()).ok_or(()),
                _ => Err(()),
            }
        }
    }
}

impl From<u32> for Identifier {
    fn from(v: u32) -> Self {
        Identifier::Numeric(v)
    }
}

impl<'a> From<&'a str> for Identifier {
    fn from(v: &'a str) -> Self {
        Identifier::from(UAString::from(v))
    }
}

impl From<&String> for Identifier {
    fn from(v: &String) -> Self {
        Identifier::from(UAString::from(v))
    }
}

impl From<String> for Identifier {
    fn from(v: String) -> Self {
        Identifier::from(UAString::from(v))
    }
}

impl From<UAString> for Identifier {
    fn from(v: UAString) -> Self {
        Identifier::String(v)
    }
}

impl From<Guid> for Identifier {
    fn from(v: Guid) -> Self {
        Identifier::Guid(v)
    }
}

impl From<ByteString> for Identifier {
    fn from(v: ByteString) -> Self {
        Identifier::ByteString(v)
    }
}

macro_rules! impl_identifier_ref {
    ($x:ident, $t:ty, $h:ident, $eq_p:pat, $h_expr:expr) => {
        impl_identifier_ref!($x, $t, $h, $eq_p, $h_expr, $x);
    };
    ($x:ident, $t:ty, $h:ident, $eq_p:pat, $h_expr:expr, $eq_expr:expr) => {
        impl PartialEq<Identifier> for $t {
            fn eq(&self, other: &Identifier) -> bool {
                match other {
                    $eq_p => $eq_expr == self,
                    _ => false,
                }
            }
        }

        impl IdentifierRef for $t {
            fn hash_as_identifier<H: Hasher>(&self, state: &mut H) {
                $h.hash(state);
                let $x = self;
                $h_expr.hash(state);
            }
        }
    };
}

impl_identifier_ref!(x, u32, IDENTIFIER_HASH_NUMERIC, Identifier::Numeric(x), x);
impl_identifier_ref!(
    x,
    &u32,
    IDENTIFIER_HASH_NUMERIC,
    Identifier::Numeric(x),
    x,
    &x
);
impl_identifier_ref!(
    x,
    UAString,
    IDENTIFIER_HASH_STRING,
    Identifier::String(x),
    x.as_ref()
);
impl_identifier_ref!(
    x,
    &UAString,
    IDENTIFIER_HASH_STRING,
    Identifier::String(x),
    x.as_ref(),
    &x
);
impl_identifier_ref!(
    x,
    String,
    IDENTIFIER_HASH_STRING,
    Identifier::String(x),
    x.as_str(),
    x.as_ref()
);
impl_identifier_ref!(x, &str, IDENTIFIER_HASH_STRING, Identifier::String(x), x);
impl_identifier_ref!(x, &String, IDENTIFIER_HASH_STRING, Identifier::String(x), x);
impl_identifier_ref!(x, Guid, IDENTIFIER_HASH_GUID, Identifier::Guid(x), x);
impl_identifier_ref!(
    x,
    ByteString,
    IDENTIFIER_HASH_BYTE_STRING,
    Identifier::ByteString(x),
    x
);
impl_identifier_ref!(x, &Guid, IDENTIFIER_HASH_GUID, Identifier::Guid(x), x, &x);
impl_identifier_ref!(
    x,
    &ByteString,
    IDENTIFIER_HASH_BYTE_STRING,
    Identifier::ByteString(x),
    x,
    &x
);
impl_identifier_ref!(
    x,
    &[u8],
    IDENTIFIER_HASH_BYTE_STRING,
    Identifier::ByteString(x),
    x
);
impl_identifier_ref!(x, GuidRef<'_>, IDENTIFIER_HASH_GUID, Identifier::Guid(x), x);

impl IdentifierRef for Identifier {
    fn hash_as_identifier<H: Hasher>(&self, state: &mut H) {
        self.hash(state);
    }
}

impl PartialEq<Identifier> for &Identifier {
    fn eq(&self, other: &Identifier) -> bool {
        (*self).eq(other)
    }
}

impl IdentifierRef for &Identifier {
    fn hash_as_identifier<H: Hasher>(&self, state: &mut H) {
        self.hash(state);
    }
}
