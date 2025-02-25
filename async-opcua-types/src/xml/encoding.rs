use std::{
    io::{Read, Write},
    str::{from_utf8, Utf8Error},
};

use opcua_xml::{XmlReadError, XmlStreamReader, XmlStreamWriter, XmlWriteError};

use crate::{Context, EncodingResult, Error};

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

impl From<Utf8Error> for Error {
    fn from(value: Utf8Error) -> Self {
        Self::decoding(value)
    }
}

/// Trait for types that can be decoded from XML.
pub trait XmlDecodable {
    /// Decode a value from an XML stream.
    fn decode(
        read: &mut XmlStreamReader<&mut dyn Read>,
        context: &Context<'_>,
    ) -> Result<Self, Error>
    where
        Self: Sized;
}

/// Trait for types that can be encoded to XML.
pub trait XmlEncodable {
    /// Encode a value to an XML stream.
    fn encode(
        &self,
        writer: &mut XmlStreamWriter<&mut dyn Write>,
        context: &Context<'_>,
    ) -> EncodingResult<()>;
}

/// Extensions for XmlStreamWriter.
pub trait XmlWriteExt {
    /// Encode a value as a child element.
    fn encode_child<T: XmlEncodable + ?Sized>(
        &mut self,
        tag: &str,
        value: &T,
        context: &Context<'_>,
    ) -> EncodingResult<()>;
}

impl XmlWriteExt for XmlStreamWriter<&mut dyn Write> {
    fn encode_child<T: XmlEncodable + ?Sized>(
        &mut self,
        tag: &str,
        value: &T,
        context: &Context<'_>,
    ) -> EncodingResult<()> {
        self.write_start(tag)?;
        value.encode(self, context)?;
        self.write_end(tag)?;

        Ok(())
    }
}

/// Extensions for XmlStreamReader.
pub trait XmlReadExt {
    /// Iterate over children, calling the provided callback for each tag.
    /// The callback must consume the tag.
    fn iter_children(
        &mut self,
        cb: impl FnMut(String, &mut Self, &Context<'_>) -> EncodingResult<()>,
        context: &Context<'_>,
    ) -> EncodingResult<()>;

    /// Call a callback for a single child element. This will consume the
    /// current node.
    fn get_single_child<T>(
        &mut self,
        tag: &str,
        cb: impl FnMut(&mut Self, &Context<'_>) -> Result<T, Error>,
        context: &Context<'_>,
    ) -> EncodingResult<Option<T>>;

    /// Decode a single child element. This will consume the
    /// current node.
    fn decode_single_child<T: XmlDecodable>(
        &mut self,
        tag: &str,
        context: &Context<'_>,
    ) -> Result<Option<T>, Error>;
}

impl XmlReadExt for XmlStreamReader<&mut dyn Read> {
    fn iter_children(
        &mut self,
        mut process: impl FnMut(String, &mut Self, &Context<'_>) -> EncodingResult<()>,
        context: &Context<'_>,
    ) -> EncodingResult<()> {
        loop {
            match self.next_event()? {
                opcua_xml::events::Event::Start(s) => {
                    let name = from_utf8(s.name().0)?;
                    process(name.to_owned(), self, context)?;
                }
                opcua_xml::events::Event::End(_) => {
                    return Ok(());
                }
                opcua_xml::events::Event::Eof => {
                    return Err(Error::decoding(XmlReadError::UnexpectedEof));
                }
                _ => (),
            }
        }
    }

    fn get_single_child<T>(
        &mut self,
        tag: &str,
        cb: impl FnOnce(&mut Self, &Context<'_>) -> Result<T, Error>,
        context: &Context<'_>,
    ) -> EncodingResult<Option<T>> {
        let mut cb = Some(cb);
        let mut res = None;
        self.iter_children(
            |key, reader, ctx| {
                if tag == key {
                    if let Some(cb) = cb.take() {
                        res = Some(cb(reader, ctx)?);
                    }
                } else {
                    reader.skip_value()?;
                }
                Ok(())
            },
            context,
        )?;
        Ok(res)
    }

    fn decode_single_child<T: XmlDecodable>(
        &mut self,
        tag: &str,
        context: &Context<'_>,
    ) -> EncodingResult<Option<T>> {
        self.get_single_child(tag, |reader, ctx| T::decode(reader, ctx), context)
    }
}
