use std::{fmt, str::FromStr};

use crate::{ByteString, Guid, UAString};

/// The kind of identifier, numeric, string, guid or byte
#[derive(Eq, PartialEq, Clone, Debug, Hash)]
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

impl From<i32> for Identifier {
    fn from(v: i32) -> Self {
        Identifier::Numeric(v as u32)
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
