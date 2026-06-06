//! This module defines common methods for loading input formats,
//! such as NodeSet2 XML files, Binary Schema Definition files, and XML Schema Definition files.
//! It also defines a schema cache, which can be used to store loaded schemas,
//! and cache certain computations that may be reused.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

use pathdiff::diff_paths;
use tracing::warn;

use crate::CodeGenError;

mod binary_schema;
mod nodeset;
mod xml_schema;

pub use binary_schema::BinarySchemaInput;
pub use nodeset::{NodeSetInput, RawEncodingIds, TypeInfo};
pub use xml_schema::XmlSchemaInput;

/// Instance of a schema cache for a single type of schema, e.g. NodeSet2 files.
struct SchemaCacheInst<T> {
    aliases: HashMap<String, usize>,
    items: Vec<T>,
}

impl<T> SchemaCacheInst<T> {
    pub fn new() -> Self {
        Self {
            aliases: HashMap::new(),
            items: Vec::new(),
        }
    }

    pub fn insert(&mut self, key: String, value: T) -> usize {
        let idx = self.items.len();
        self.items.push(value);
        self.aliases.insert(key, idx);
        idx
    }

    pub fn get(&self, key: &str) -> Option<&T> {
        let idx = self.aliases.get(key)?;
        self.items.get(*idx)
    }

    pub fn add_file_aliases(&mut self, file_path: &Path, index: usize) {
        self.aliases
            .insert(file_path.to_string_lossy().into_owned(), index);
        let path = Path::new(file_path);
        if let Some(file_name) = path.file_name() {
            self.aliases
                .insert(file_name.to_string_lossy().to_string(), index);
        }
        if let Some(file_name) = path.with_extension("").file_name() {
            self.aliases
                .insert(file_name.to_string_lossy().to_string(), index);
        }
    }
}

/// Utility type for storing schemas.
/// This handles loading, parsing, and reuse of schemas during a code
/// generation run.
pub struct SchemaCache {
    root_path: PathBuf,
    nodesets: SchemaCacheInst<NodeSetInput>,
    binary_schemas: SchemaCacheInst<BinarySchemaInput>,
    xml_schemas: SchemaCacheInst<XmlSchemaInput>,
}

impl SchemaCache {
    /// Create a new schema cache with the given root path.
    pub fn new(root_path: &Path) -> Self {
        Self {
            root_path: root_path.to_owned(),
            nodesets: SchemaCacheInst::new(),
            binary_schemas: SchemaCacheInst::new(),
            xml_schemas: SchemaCacheInst::new(),
        }
    }

    fn auto_load_file(&mut self, path: &Path) -> Result<(), CodeGenError> {
        if let Some(ext) = path.extension() {
            // The rest of the schema cache expects a relative path, but here we're operating
            // on the full, absolute path.
            // Using relative paths makes it so that you get the same result from codegen, no matter
            // where you run it from, so long as the config file is in the same place.
            let relative_path = diff_paths(path, &self.root_path).ok_or_else(|| {
                CodeGenError::other(format!(
                    "Failed to get relative path for {}",
                    path.to_string_lossy()
                ))
            })?;
            match ext.to_string_lossy().as_ref() {
                "xsd" => self.load_xml_schema(&relative_path)?,
                "bsd" => self.load_binary_schema(&relative_path)?,
                "xml" => self.load_nodeset(&relative_path)?,
                _ => {}
            }
        }
        Ok(())
    }

    /// Check if all dependencies are satisfied, meaning that
    /// for each NodeSet2 xml file, their dependent nodesets and
    /// XML schema files are present.
    pub fn validate(&self) -> Result<(), CodeGenError> {
        for nodeset in &self.nodesets.items {
            nodeset.validate(self)?;
        }

        Ok(())
    }

    /// Automatically load schemas at the given path.
    pub fn auto_load_schemas(&mut self, path: &Path) -> Result<(), CodeGenError> {
        let path_buf = Path::new(&self.root_path).join(path);
        let path: &Path = path_buf.as_ref();
        if path.is_dir() {
            for entry in std::fs::read_dir(path).map_err(|e| {
                CodeGenError::other(format!(
                    "Failed to list files in path {}, {e}",
                    path.to_string_lossy()
                ))
            })? {
                let Ok(entry) = entry else {
                    warn!("Failed to read entry: {:?}", entry);
                    continue;
                };
                let path = entry.path();
                self.auto_load_file(&path)?;
            }
        } else if path.is_file() {
            self.auto_load_file(path)?;
        } else {
            return Err(CodeGenError::other(format!(
                "Path {} not found",
                path.to_string_lossy()
            )));
        }
        Ok(())
    }

    /// Load a NodeSet2.xml file from the given path, and add it to the cache.
    pub fn load_nodeset(&mut self, file_path: &Path) -> Result<(), CodeGenError> {
        let nodeset = NodeSetInput::load(&self.root_path, file_path)?;
        let idx = self.nodesets.insert(nodeset.uri().to_owned(), nodeset);
        self.nodesets.add_file_aliases(file_path, idx);
        Ok(())
    }

    /// Load a binary schema (.bsd) file from the given path, and add it to the cache.
    pub fn load_binary_schema(&mut self, file_path: &Path) -> Result<(), CodeGenError> {
        let schema = BinarySchemaInput::load(&self.root_path, file_path)?;
        let idx = self
            .binary_schemas
            .insert(schema.namespace().to_owned(), schema);
        self.binary_schemas.add_file_aliases(file_path, idx);
        Ok(())
    }
    /// Load an XML schema (.xsd) file from the given path, and add it to the cache.
    pub fn load_xml_schema(&mut self, file_path: &Path) -> Result<(), CodeGenError> {
        let schema = XmlSchemaInput::load(&self.root_path, file_path)?;
        let idx = self
            .xml_schemas
            .insert(schema.namespace().to_owned(), schema);
        self.xml_schemas.add_file_aliases(file_path, idx);
        Ok(())
    }
    /// Get a NodeSet2 file with a key, which may be path, filename, or namespace.
    pub fn get_nodeset(&self, key: &str) -> Result<&NodeSetInput, CodeGenError> {
        self.nodesets
            .get(key)
            .ok_or_else(|| CodeGenError::other(format!("Missing required nodeset with key {key}")))
    }

    /// Get a Binary schema (.bsd) file with a key, which may be path, filename, or namespace.
    pub fn get_binary_schema(&self, key: &str) -> Result<&BinarySchemaInput, CodeGenError> {
        self.binary_schemas.get(key).ok_or_else(|| {
            CodeGenError::other(format!("Missing required binary schema with key {key}"))
        })
    }

    /// Get an XML schema (.xsd) file with a key, which may be path, filename, or namespace.
    pub fn get_xml_schema(&self, key: &str) -> Result<&XmlSchemaInput, CodeGenError> {
        self.xml_schemas.get(key).ok_or_else(|| {
            CodeGenError::other(format!("Missing required xml schema with key {key}"))
        })
    }
}
