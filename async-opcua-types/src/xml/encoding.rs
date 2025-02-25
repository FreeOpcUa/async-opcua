use std::io::{Read, Write};

use opcua_xml::{XmlReadError, XmlStreamReader, XmlStreamWriter, XmlWriteError};

use crate::{Context, Error};

impl From<XmlReadError> for Error {
    fn from(value: XmlReadError) -> Self {
        Self::decoding(value)
    }
}

impl From<XmlWriteError> for Error {
    fn from(value: XmlWriteError) -> Self {
        Self::encoding(value)
    }
}

pub trait XmlDecodable {
    fn decode(
        read: &mut XmlStreamReader<&mut dyn Read>,
        context: &Context<'_>,
    ) -> Result<Self, Error>
    where
        Self: Sized;
}

pub trait XmlEncodable {
    fn encode(
        &self,
        writer: &mut XmlStreamWriter<&mut dyn Write>,
        context: &Context<'_>,
    ) -> Result<(), Error>;
}
