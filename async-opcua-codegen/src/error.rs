use std::{
    fmt::Display,
    num::{ParseFloatError, ParseIntError},
    str::ParseBoolError,
};

use thiserror::Error;

#[derive(Error, Debug, Clone)]
pub enum CodeGenErrorKind {
    #[error("Failed to load XML: {0}")]
    Xml(#[from] opcua_xml::XmlError),
    #[error("Missing required field: {0}")]
    MissingRequiredValue(&'static str),
    #[error("Wrong format on field. Expected {0}, got {1}")]
    WrongFormat(String, String),
    #[error("Failed to parse {0} as integer.")]
    ParseInt(String, ParseIntError),
    #[error("Failed to parse {0} as bool.")]
    ParseBool(String, ParseBoolError),
    #[error("Failed to parse {0} as float.")]
    ParseFloat(String, ParseFloatError),
    #[error("{0}")]
    Other(String),
    #[error("Failed to generate code: {0}")]
    Syn(#[from] syn::Error),
    #[error("{0}: {1}")]
    Io(String, String),
}

#[derive(Error, Debug, Clone)]
pub struct CodeGenError {
    #[source]
    pub kind: Box<CodeGenErrorKind>,
    pub context: Option<String>,
    pub file: Option<String>,
}

impl Display for CodeGenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Code generation failed: {}", self.kind)?;
        if let Some(context) = &self.context {
            write!(f, ", while {context}")?;
        }
        if let Some(file) = &self.file {
            write!(f, ", while loading file {file}")?;
        }
        Ok(())
    }
}

impl From<ParseIntError> for CodeGenError {
    fn from(value: ParseIntError) -> Self {
        Self::new(CodeGenErrorKind::ParseInt("content".to_owned(), value))
    }
}

impl From<ParseBoolError> for CodeGenError {
    fn from(value: ParseBoolError) -> Self {
        Self::new(CodeGenErrorKind::ParseBool("content".to_owned(), value))
    }
}

impl From<ParseFloatError> for CodeGenError {
    fn from(value: ParseFloatError) -> Self {
        Self::new(CodeGenErrorKind::ParseFloat("content".to_owned(), value))
    }
}

impl From<opcua_xml::XmlError> for CodeGenError {
    fn from(value: opcua_xml::XmlError) -> Self {
        Self::new(value.into())
    }
}

impl From<syn::Error> for CodeGenError {
    fn from(value: syn::Error) -> Self {
        Self::new(value.into())
    }
}

impl CodeGenError {
    pub fn io(msg: &str, e: std::io::Error) -> Self {
        Self::new(CodeGenErrorKind::Io(msg.to_owned(), e.to_string()))
    }

    pub fn other(msg: impl Into<String>) -> Self {
        Self::new(CodeGenErrorKind::Other(msg.into()))
    }

    pub fn parse_int(field: impl Into<String>, error: ParseIntError) -> Self {
        Self::new(CodeGenErrorKind::ParseInt(field.into(), error))
    }

    pub fn wrong_format(format: impl Into<String>, value: impl Into<String>) -> Self {
        Self::new(CodeGenErrorKind::WrongFormat(format.into(), value.into()))
    }

    pub fn missing_required_value(name: &'static str) -> Self {
        Self::new(CodeGenErrorKind::MissingRequiredValue(name))
    }

    pub fn with_context(mut self, context: impl Into<String>) -> Self {
        self.context = Some(context.into());
        self
    }

    pub fn in_file(mut self, file: impl Into<String>) -> Self {
        self.file = Some(file.into());
        self
    }

    pub fn new(kind: CodeGenErrorKind) -> Self {
        Self {
            kind: Box::new(kind),
            context: None,
            file: None,
        }
    }
}
