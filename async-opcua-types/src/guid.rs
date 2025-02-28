// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2024 Adam Lock

//! Contains the implementation of `Guid`.

use std::{
    fmt,
    io::{Read, Write},
    str::FromStr,
};

use uuid::Uuid;

use crate::encoding::*;

/// A Guid is a 16 byte Globally Unique Identifier.
#[derive(Eq, PartialEq, Clone, Hash)]
pub struct Guid {
    uuid: Uuid,
}

impl From<Guid> for Uuid {
    fn from(value: Guid) -> Self {
        value.uuid
    }
}

impl UaNullable for Guid {
    fn is_ua_null(&self) -> bool {
        self.uuid.is_nil()
    }
}

#[cfg(feature = "json")]
mod json {
    use std::io::{Read, Write};
    use std::str::FromStr;

    use crate::{json::*, Error};

    use super::Guid;

    impl JsonEncodable for Guid {
        fn encode(
            &self,
            stream: &mut JsonStreamWriter<&mut dyn Write>,
            _ctx: &crate::json::Context<'_>,
        ) -> super::EncodingResult<()> {
            Ok(stream.string_value(&self.uuid.to_string())?)
        }
    }

    impl JsonDecodable for Guid {
        fn decode(
            stream: &mut JsonStreamReader<&mut dyn Read>,
            _ctx: &Context<'_>,
        ) -> super::EncodingResult<Self> {
            let s = stream.next_str()?;
            let guid = Guid::from_str(s).map_err(Error::decoding)?;
            Ok(guid)
        }
    }
}

#[cfg(feature = "xml")]
mod xml {
    use crate::xml::*;
    use std::{
        io::{Read, Write},
        str::FromStr,
    };

    use super::Guid;

    impl XmlType for Guid {
        const TAG: &'static str = "Guid";
    }

    impl XmlEncodable for Guid {
        fn encode(
            &self,
            writer: &mut XmlStreamWriter<&mut dyn Write>,
            ctx: &crate::xml::Context<'_>,
        ) -> EncodingResult<()> {
            writer.encode_child("String", &self.to_string(), ctx)
        }
    }

    impl XmlDecodable for Guid {
        fn decode(
            reader: &mut XmlStreamReader<&mut dyn Read>,
            ctx: &crate::xml::Context<'_>,
        ) -> EncodingResult<Self> {
            let val: Option<String> = reader.decode_single_child("String", ctx)?;
            let Some(val) = val else {
                return Ok(Guid::null());
            };
            Guid::from_str(&val).map_err(Error::decoding)
        }
    }
}

impl fmt::Display for Guid {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.uuid)
    }
}

impl fmt::Debug for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.uuid.hyphenated())
    }
}

impl BinaryEncodable for Guid {
    fn byte_len(&self, _ctx: &crate::Context<'_>) -> usize {
        16
    }

    fn encode<S: Write + ?Sized>(
        &self,
        stream: &mut S,
        _ctx: &crate::Context<'_>,
    ) -> EncodingResult<()> {
        process_encode_io_result(stream.write_all(self.uuid.as_bytes()))
    }
}

impl BinaryDecodable for Guid {
    fn decode<S: Read + ?Sized>(stream: &mut S, _ctx: &crate::Context<'_>) -> EncodingResult<Self> {
        let mut bytes = [0u8; 16];
        process_decode_io_result(stream.read_exact(&mut bytes))?;
        Ok(Guid {
            uuid: Uuid::from_bytes(bytes),
        })
    }
}

impl FromStr for Guid {
    type Err = <Uuid as FromStr>::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Uuid::from_str(s).map(|uuid| Guid { uuid })
    }
}

impl From<Uuid> for Guid {
    fn from(uuid: Uuid) -> Self {
        Self { uuid }
    }
}

impl Default for Guid {
    fn default() -> Self {
        Guid::null()
    }
}

impl Guid {
    /// Return a null guid, i.e. 00000000-0000-0000-0000-000000000000
    pub fn null() -> Guid {
        Guid { uuid: Uuid::nil() }
    }

    /// Creates a random Guid
    pub fn new() -> Guid {
        Guid {
            uuid: Uuid::new_v4(),
        }
    }

    /// Returns the bytes of the Guid
    pub fn as_bytes(&self) -> &[u8; 16] {
        self.uuid.as_bytes()
    }

    /// Creates a guid from a byte array.
    pub fn from_bytes(bytes: [u8; 16]) -> Guid {
        Guid {
            uuid: Uuid::from_bytes(bytes),
        }
    }

    /// Creates an UUID from a byte slice of exactly 16 bytes.
    pub fn from_slice(bytes: &[u8]) -> Result<Guid, uuid::Error> {
        Ok(Guid {
            uuid: Uuid::from_slice(bytes)?,
        })
    }
}
