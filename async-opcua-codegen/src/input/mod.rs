use std::{collections::HashMap, path::Path};

use pathdiff::diff_paths;
use tracing::warn;

use crate::CodeGenError;

mod binary_schema;
mod nodeset;
mod xml_schema;

pub use binary_schema::BinarySchemaInput;
pub use nodeset::{NodeSetInput, RawEncodingIds, TypeInfo};
pub use xml_schema::XmlSchemaInput;

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

    pub fn add_file_aliases(&mut self, file_path: &str, index: usize) {
        self.aliases.insert(file_path.to_owned(), index);
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

pub struct SchemaCache {
    root_path: String,
    nodesets: SchemaCacheInst<NodeSetInput>,
    binary_schemas: SchemaCacheInst<BinarySchemaInput>,
    xml_schemas: SchemaCacheInst<XmlSchemaInput>,
}

impl SchemaCache {
    pub fn new(root_path: &str) -> Self {
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
            let path_str = relative_path.to_string_lossy();
            match ext.to_string_lossy().as_ref() {
                "xsd" => self.load_xml_schema(&path_str)?,
                "bsd" => self.load_binary_schema(&path_str)?,
                "xml" => {
                    // Check if there is a file on the form <filename>.documentation.csv
                    let docs_path = if path.with_extension("documentation.csv").exists() {
                        Some(
                            relative_path
                                .with_extension("documentation.csv")
                                .to_string_lossy()
                                .into_owned(),
                        )
                    } else {
                        None
                    };
                    self.load_nodeset(&path_str, docs_path.as_deref())?
                }
                _ => {}
            }
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), CodeGenError> {
        for nodeset in &self.nodesets.items {
            nodeset.validate(self)?;
        }

        Ok(())
    }

    pub fn auto_load_schemas(&mut self, path: &str) -> Result<(), CodeGenError> {
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

    pub fn load_nodeset(
        &mut self,
        file_path: &str,
        docs_path: Option<&str>,
    ) -> Result<(), CodeGenError> {
        let nodeset = NodeSetInput::load(&self.root_path, file_path, docs_path)?;
        let idx = self.nodesets.insert(nodeset.uri.clone(), nodeset);
        self.nodesets.add_file_aliases(file_path, idx);
        Ok(())
    }

    pub fn load_binary_schema(&mut self, file_path: &str) -> Result<(), CodeGenError> {
        let schema = BinarySchemaInput::load(&self.root_path, file_path)?;
        let idx = self.binary_schemas.insert(schema.namespace.clone(), schema);
        self.binary_schemas.add_file_aliases(file_path, idx);
        Ok(())
    }

    pub fn load_xml_schema(&mut self, file_path: &str) -> Result<(), CodeGenError> {
        let schema = XmlSchemaInput::load(&self.root_path, file_path)?;
        let idx = self.xml_schemas.insert(schema.namespace.clone(), schema);
        self.xml_schemas.add_file_aliases(file_path, idx);
        Ok(())
    }

    pub fn get_nodeset(&self, key: &str) -> Result<&NodeSetInput, CodeGenError> {
        self.nodesets.get(key).ok_or_else(|| {
            CodeGenError::other(format!("Missing required nodeset with key {}", key))
        })
    }

    pub fn get_binary_schema(&self, key: &str) -> Result<&BinarySchemaInput, CodeGenError> {
        self.binary_schemas.get(key).ok_or_else(|| {
            CodeGenError::other(format!("Missing required binary schema with key {}", key))
        })
    }

    pub fn get_xml_schema(&self, key: &str) -> Result<&XmlSchemaInput, CodeGenError> {
        self.xml_schemas.get(key).ok_or_else(|| {
            CodeGenError::other(format!("Missing required xml schema with key {}", key))
        })
    }
}
