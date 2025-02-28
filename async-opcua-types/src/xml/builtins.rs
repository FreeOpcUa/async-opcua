use super::{
    encoding::{XmlDecodable, XmlEncodable, XmlType},
    XmlReadExt, XmlWriteExt,
};
use crate::{Context, Error};
use opcua_xml::{XmlStreamReader, XmlStreamWriter};
use std::io::{Read, Write};

macro_rules! xml_enc_number {
    ($t:ty, $name:expr) => {
        impl XmlType for $t {
            const TAG: &'static str = $name;
        }

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
    ($t:ty, $name:expr) => {
        impl XmlType for $t {
            const TAG: &'static str = $name;
        }

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

xml_enc_number!(u8, "Byte");
xml_enc_number!(u16, "UInt16");
xml_enc_number!(u32, "UInt32");
xml_enc_number!(u64, "UInt64");
xml_enc_number!(i8, "SByte");
xml_enc_number!(i16, "Int16");
xml_enc_number!(i32, "Int32");
xml_enc_number!(i64, "Int64");
xml_enc_float!(f32, "Float");
xml_enc_float!(f64, "Double");

impl XmlType for String {
    const TAG: &'static str = "String";
}

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

impl XmlType for str {
    const TAG: &'static str = "String";
}

impl XmlEncodable for str {
    fn encode(
        &self,
        writer: &mut XmlStreamWriter<&mut dyn Write>,
        _context: &Context<'_>,
    ) -> Result<(), Error> {
        writer.write_text(self)?;
        Ok(())
    }
}

impl XmlType for bool {
    const TAG: &'static str = "Boolean";
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

impl<T> XmlType for Box<T>
where
    T: XmlType,
{
    const TAG: &'static str = T::TAG;
    fn tag(&self) -> &str {
        self.as_ref().tag()
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

impl<T> XmlType for Vec<T>
where
    T: XmlType,
{
    // Could be ListOf... but there's no static way to do so, and it isn't
    // strictly necessary.
    const TAG: &'static str = T::TAG;
    fn tag(&self) -> &str {
        self.first().map(|v| v.tag()).unwrap_or(Self::TAG)
    }
}

impl<T> XmlDecodable for Vec<T>
where
    T: XmlDecodable + Default,
{
    fn decode(
        read: &mut XmlStreamReader<&mut dyn Read>,
        context: &Context<'_>,
    ) -> Result<Self, Error> {
        let mut vec = Vec::new();
        read.iter_children_include_empty(
            |_, reader, context| {
                let Some(reader) = reader else {
                    vec.push(T::default());
                    return Ok(());
                };
                vec.push(T::decode(reader, context)?);
                Ok(())
            },
            context,
        )?;
        Ok(vec)
    }
}

impl<T> XmlEncodable for Vec<T>
where
    T: XmlEncodable,
{
    fn encode(
        &self,
        writer: &mut XmlStreamWriter<&mut dyn Write>,
        context: &Context<'_>,
    ) -> super::EncodingResult<()> {
        for item in self {
            if item.is_ua_null() {
                writer.write_empty(item.tag())?;
            } else {
                writer.encode_child(item.tag(), item, context)?;
            }
        }
        Ok(())
    }
}

impl<T> XmlType for Option<T>
where
    T: XmlType,
{
    const TAG: &'static str = T::TAG;
    fn tag(&self) -> &str {
        self.as_ref().map(|v| v.tag()).unwrap_or(Self::TAG)
    }
}

impl<T> XmlDecodable for Option<T>
where
    T: XmlDecodable,
{
    fn decode(
        read: &mut XmlStreamReader<&mut dyn Read>,
        context: &Context<'_>,
    ) -> Result<Self, Error> {
        // Effectively we treat missing fields as None, so here we just pass along
        // to the decoder, since getting here means the field is present.
        Ok(Some(T::decode(read, context)?))
    }
}

impl<T> XmlEncodable for Option<T>
where
    T: XmlEncodable,
{
    fn encode(
        &self,
        writer: &mut XmlStreamWriter<&mut dyn Write>,
        context: &Context<'_>,
    ) -> super::EncodingResult<()> {
        if let Some(value) = self {
            value.encode(writer, context)?;
        }
        Ok(())
    }
}
