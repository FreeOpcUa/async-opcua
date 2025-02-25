use super::encoding::{XmlDecodable, XmlEncodable};
use crate::{Context, Error};
use opcua_xml::{XmlStreamReader, XmlStreamWriter};
use std::io::{Read, Write};

macro_rules! xml_enc_number {
    ($t:ty) => {
        impl XmlEncodable for $t {
            fn encode(
                &self,
                writer: &mut XmlStreamWriter<&mut dyn Write>,
                _context: &Context<'_>,
            ) -> Result<(), Error> {
                writer.write_text(&self.to_string())?;
                Ok(())
            }
        }

        impl XmlDecodable for $t {
            fn decode(
                read: &mut XmlStreamReader<&mut dyn Read>,
                _context: &Context<'_>,
            ) -> Result<Self, Error> {
                Ok(read.consume_content()?)
            }
        }
    };
}

const VALUE_INFINITY: &str = "INF";
const VALUE_NEG_INFINITY: &str = "-INF";
const VALUE_NAN: &str = "NaN";

macro_rules! xml_enc_float {
    ($t:ty) => {
        impl XmlEncodable for $t {
            fn encode(
                &self,
                writer: &mut XmlStreamWriter<&mut dyn Write>,
                _context: &Context<'_>,
            ) -> Result<(), Error> {
                if self.is_infinite() {
                    if self.is_sign_positive() {
                        writer.write_text(VALUE_INFINITY)?;
                    } else {
                        writer.write_text(VALUE_NEG_INFINITY)?;
                    }
                } else if self.is_nan() {
                    writer.write_text(VALUE_NAN)?;
                } else {
                    writer.write_text(&self.to_string())?;
                }
                Ok(())
            }
        }

        impl XmlDecodable for $t {
            fn decode(
                read: &mut XmlStreamReader<&mut dyn Read>,
                _context: &Context<'_>,
            ) -> Result<Self, Error> {
                let val = read.consume_as_text()?;
                match val.as_str() {
                    VALUE_INFINITY => Ok(Self::INFINITY),
                    VALUE_NEG_INFINITY => Ok(Self::NEG_INFINITY),
                    VALUE_NAN => Ok(Self::NAN),
                    _ => Ok(val.parse()?),
                }
            }
        }
    };
}

xml_enc_number!(u8);
xml_enc_number!(u16);
xml_enc_number!(u32);
xml_enc_number!(u64);
xml_enc_number!(i8);
xml_enc_number!(i16);
xml_enc_number!(i32);
xml_enc_number!(i64);
xml_enc_float!(f32);
xml_enc_float!(f64);

impl XmlDecodable for String {
    fn decode(
        read: &mut XmlStreamReader<&mut dyn Read>,
        _context: &Context<'_>,
    ) -> Result<Self, Error>
    where
        Self: Sized,
    {
        Ok(read.consume_as_text()?)
    }
}

impl XmlEncodable for String {
    fn encode(
        &self,
        writer: &mut XmlStreamWriter<&mut dyn Write>,
        _context: &Context<'_>,
    ) -> Result<(), Error> {
        writer.write_text(self)?;
        Ok(())
    }
}

impl XmlDecodable for bool {
    fn decode(
        read: &mut XmlStreamReader<&mut dyn Read>,
        _context: &Context<'_>,
    ) -> Result<Self, Error>
    where
        Self: Sized,
    {
        let val = read.consume_as_text()?;
        match val.as_str() {
            "true" | "1" => Ok(true),
            "false" | "0" => Ok(false),
            _ => Err(Error::decoding(format!("Invalid boolean value: {val}"))),
        }
    }
}

impl XmlEncodable for bool {
    fn encode(
        &self,
        writer: &mut XmlStreamWriter<&mut dyn Write>,
        _context: &Context<'_>,
    ) -> Result<(), Error> {
        writer.write_text(if *self { "true" } else { "false" })?;
        Ok(())
    }
}

impl<T> XmlDecodable for Box<T>
where
    T: XmlDecodable,
{
    fn decode(
        read: &mut XmlStreamReader<&mut dyn Read>,
        context: &Context<'_>,
    ) -> Result<Self, Error> {
        Ok(Box::new(T::decode(read, context)?))
    }
}

impl<T> XmlEncodable for Box<T>
where
    T: XmlEncodable,
{
    fn encode(
        &self,
        writer: &mut XmlStreamWriter<&mut dyn Write>,
        context: &Context<'_>,
    ) -> Result<(), Error> {
        self.as_ref().encode(writer, context)
    }
}
