use std::io::Write;

use quick_xml::{
    events::{BytesEnd, BytesStart, BytesText, Event},
    ElementWriter,
};
use thiserror::Error;

/// XML stream writer specialized for working with OPC-UA XML.
pub struct XmlStreamWriter<T> {
    writer: quick_xml::Writer<T>,
}

#[derive(Debug, Error)]
/// Error returned when writing XML.
pub enum XmlWriteError {
    #[error("{0}")]
    /// Invalid XML input.
    Xml(#[from] quick_xml::Error),
    #[error("Failed to write to stream: {0}")]
    /// Failed to write XML to stream.
    Io(#[from] std::io::Error),
}

impl<T: Write> XmlStreamWriter<T> {
    /// Create a new writer with the given inner Write implementation.
    pub fn new(writer: T) -> Self {
        Self {
            writer: quick_xml::Writer::new(writer),
        }
    }

    /// Write an event to the stream.
    pub fn write_event(&mut self, element: Event<'_>) -> Result<(), XmlWriteError> {
        self.writer.write_event(element)?;
        Ok(())
    }

    /// Write a start tag to the stream.
    pub fn write_start(&mut self, tag: &str) -> Result<(), XmlWriteError> {
        self.writer
            .write_event(Event::Start(BytesStart::new(tag)))?;
        Ok(())
    }

    /// Write an end tag to the stream.
    pub fn write_end(&mut self, tag: &str) -> Result<(), XmlWriteError> {
        self.writer.write_event(Event::End(BytesEnd::new(tag)))?;
        Ok(())
    }

    /// Write an empty tag to the stream.
    pub fn write_empty(&mut self, tag: &str) -> Result<(), XmlWriteError> {
        self.writer
            .write_event(Event::Empty(BytesStart::new(tag)))?;
        Ok(())
    }

    /// Write node contents to the stream.
    pub fn write_text(&mut self, text: &str) -> Result<(), XmlWriteError> {
        self.writer.write_event(Event::Text(BytesText::new(text)))?;
        Ok(())
    }

    /// Get a flexible event builder from quick-xml.
    pub fn create_element<'a>(&'a mut self, name: &'a str) -> ElementWriter<'a, T> {
        self.writer.create_element(name)
    }
}

impl XmlStreamWriter<&mut dyn Write> {
    /// Write the given bytes raw to the stream.
    /// This may produce invalid XML, if the data is not valid and properly escaped.
    pub fn write_raw(&mut self, data: &[u8]) -> Result<(), XmlWriteError> {
        self.writer.get_mut().write_all(data)?;
        Ok(())
    }
}
