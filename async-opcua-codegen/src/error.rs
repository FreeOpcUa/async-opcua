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
/// A general error type produced by code generation.
pub struct CodeGenError {
    #[source]
    kind: Box<CodeGenErrorKind>,
    context: Option<String>,
    file: Option<String>,
}

impl CodeGenError {
    /// The inner error kind.
    pub fn kind(&self) -> &CodeGenErrorKind {
        &self.kind
    }
    /// Optional context, indicating exactly where this error happened.
    pub fn context(&self) -> Option<&str> {
        self.context.as_deref()
    }
    /// The file that produced this error.
    pub fn file(&self) -> Option<&str> {
        self.file.as_deref()
    }
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
    /// Create a code gen error for some IO error.
    pub fn io(msg: &str, e: std::io::Error) -> Self {
        Self::new(CodeGenErrorKind::Io(msg.to_owned(), e.to_string()))
    }

    /// Create some general code gen error.
    pub fn other(msg: impl Into<String>) -> Self {
        Self::new(CodeGenErrorKind::Other(msg.into()))
    }

    /// Create a code gen error for a [ParseIntError].
    pub fn parse_int(field: impl Into<String>, error: ParseIntError) -> Self {
        Self::new(CodeGenErrorKind::ParseInt(field.into(), error))
    }

    /// Create a code gen error indicating that a value did not match the expected format.
    pub fn wrong_format(format: impl Into<String>, value: impl Into<String>) -> Self {
        Self::new(CodeGenErrorKind::WrongFormat(format.into(), value.into()))
    }

    /// Create a code gen error indicating that a required value is missing.
    pub fn missing_required_value(name: &'static str) -> Self {
        Self::new(CodeGenErrorKind::MissingRequiredValue(name))
    }

    /// Add context to the code gen error. This should indicate where
    /// the error occured.
    pub fn with_context(mut self, context: impl Into<String>) -> Self {
        self.context = Some(context.into());
        self
    }

    /// Add context of which _file_ caused the code gen error.
    pub fn in_file(mut self, file: impl Into<String>) -> Self {
        self.file = Some(file.into());
        self
    }

    /// Create a new code gen error from a [CodeGenErrorKind].
    pub fn new(kind: CodeGenErrorKind) -> Self {
        Self {
            kind: Box::new(kind),
            context: None,
            file: None,
        }
    }
}
