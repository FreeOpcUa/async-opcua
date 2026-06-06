//! Runtime loading of OPC UA NodeSet2 files into an in-memory node manager.

use std::{
    error::Error,
    fmt,
    path::{Path, PathBuf},
};

use opcua_nodes::{NodeSet2Import, NodeSetImport};
use opcua_xml::{
    schema::ua_node_set::{NodeSet2, UANode},
    NodeSetCollection, OpcUaXmlParser, XmlError,
};

use crate::node_manager::memory::{InMemoryNodeManagerBuilder, SimpleNodeManagerBuilder};

/// Loads one or more NodeSet2 XML files for server startup.
#[derive(Debug, Clone)]
pub struct NodeSetLoader {
    preferred_locale: String,
}

impl Default for NodeSetLoader {
    fn default() -> Self {
        Self::new("en")
    }
}

impl NodeSetLoader {
    /// Create a loader using the preferred locale for localized text selection.
    pub fn new(preferred_locale: impl Into<String>) -> Self {
        Self {
            preferred_locale: preferred_locale.into(),
        }
    }

    /// Parse NodeSet2 files, cross-resolve aliases/references, and create imports.
    ///
    /// # Errors
    ///
    /// Returns an error if no paths are supplied, XML parsing fails, or an import
    /// cannot be created from a parsed file.
    pub fn load_files<I, P>(&self, paths: I) -> Result<LoadedNodeSets, NodeSetLoaderError>
    where
        I: IntoIterator<Item = P>,
        P: AsRef<Path>,
    {
        let paths = collect_paths(paths)?;
        let collection = OpcUaXmlParser::parse_nodeset_files(&paths)?;
        validate_collection_references(&collection)?;

        let namespace_uris = collection.namespace_uris().to_vec();
        let imports = paths
            .iter()
            .map(|path| self.import_file(path))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(LoadedNodeSets {
            namespace_uris,
            imports,
        })
    }

    /// Parse NodeSet2 files on a blocking worker thread.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`NodeSetLoader::load_files`], or a task join
    /// error if the blocking worker cannot complete.
    pub async fn load_files_async<I, P>(
        &self,
        paths: I,
    ) -> Result<LoadedNodeSets, NodeSetLoaderError>
    where
        I: IntoIterator<Item = P>,
        P: AsRef<Path>,
    {
        let paths = collect_paths(paths)?;
        let preferred_locale = self.preferred_locale.clone();
        tokio::task::spawn_blocking(move || Self::new(preferred_locale).load_files(paths))
            .await
            .map_err(NodeSetLoaderError::Join)?
    }

    fn import_file(
        &self,
        path: &Path,
    ) -> Result<Box<dyn NodeSetImport + Send + Sync>, NodeSetLoaderError> {
        NodeSet2Import::new(&self.preferred_locale, path, Vec::new())
            .map(|import| Box::new(import) as Box<dyn NodeSetImport + Send + Sync>)
            .map_err(|err| NodeSetLoaderError::Import {
                path: path.to_path_buf(),
                message: err.to_string(),
            })
    }
}

/// NodeSet imports prepared for registration in an in-memory node manager.
pub struct LoadedNodeSets {
    namespace_uris: Vec<String>,
    imports: Vec<Box<dyn NodeSetImport + Send + Sync>>,
}

impl LoadedNodeSets {
    /// Namespace URIs discovered across all parsed NodeSets.
    pub fn namespace_uris(&self) -> &[String] {
        &self.namespace_uris
    }

    /// NodeSet imports suitable for [`crate::address_space::AddressSpace::import_node_set`].
    pub fn imports(&self) -> &[Box<dyn NodeSetImport + Send + Sync>] {
        &self.imports
    }

    /// Consume this value and return the underlying imports.
    pub fn into_imports(self) -> Vec<Box<dyn NodeSetImport + Send + Sync>> {
        self.imports
    }

    /// Consume this value and create a simple in-memory node manager builder.
    pub fn into_node_manager(
        self,
        name: &str,
    ) -> InMemoryNodeManagerBuilder<SimpleNodeManagerBuilder> {
        let imports = self
            .imports
            .into_iter()
            .map(|import| import as Box<dyn NodeSetImport>)
            .collect();
        InMemoryNodeManagerBuilder::new(SimpleNodeManagerBuilder::new_imports(imports, name))
    }
}

/// Convenience helper for creating a node manager builder from NodeSet2 files.
///
/// # Errors
///
/// Returns an error if the NodeSet files cannot be loaded.
pub fn node_manager_from_nodeset_files<I, P>(
    paths: I,
    name: &str,
) -> Result<InMemoryNodeManagerBuilder<SimpleNodeManagerBuilder>, NodeSetLoaderError>
where
    I: IntoIterator<Item = P>,
    P: AsRef<Path>,
{
    NodeSetLoader::default()
        .load_files(paths)
        .map(|loaded| loaded.into_node_manager(name))
}

/// Async convenience helper for creating a node manager builder from NodeSet2 files.
///
/// # Errors
///
/// Returns an error if the NodeSet files cannot be loaded or the blocking task
/// cannot complete.
pub async fn node_manager_from_nodeset_files_async<I, P>(
    paths: I,
    name: &str,
) -> Result<InMemoryNodeManagerBuilder<SimpleNodeManagerBuilder>, NodeSetLoaderError>
where
    I: IntoIterator<Item = P>,
    P: AsRef<Path>,
{
    NodeSetLoader::default()
        .load_files_async(paths)
        .await
        .map(|loaded| loaded.into_node_manager(name))
}

/// Error returned while loading runtime NodeSets.
#[derive(Debug)]
pub enum NodeSetLoaderError {
    /// No NodeSet2 paths were supplied.
    NoPaths,
    /// Parsing or cross-resolution through `NodeSetCollection` failed.
    Xml(XmlError),
    /// Creating an address-space import from a parsed file failed.
    Import {
        /// NodeSet2 file path.
        path: PathBuf,
        /// Import failure message.
        message: String,
    },
    /// Blocking loader task failed.
    Join(tokio::task::JoinError),
}

impl fmt::Display for NodeSetLoaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoPaths => f.write_str("no NodeSet2 file paths supplied"),
            Self::Xml(err) => write!(f, "{err}"),
            Self::Import { path, message } => {
                write!(f, "failed to import NodeSet {}: {message}", path.display())
            }
            Self::Join(err) => write!(f, "NodeSet loading task failed: {err}"),
        }
    }
}

impl Error for NodeSetLoaderError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Xml(err) => Some(err),
            Self::Join(err) => Some(err),
            Self::NoPaths | Self::Import { .. } => None,
        }
    }
}

impl From<XmlError> for NodeSetLoaderError {
    fn from(value: XmlError) -> Self {
        Self::Xml(value)
    }
}

fn collect_paths<I, P>(paths: I) -> Result<Vec<PathBuf>, NodeSetLoaderError>
where
    I: IntoIterator<Item = P>,
    P: AsRef<Path>,
{
    let paths = paths
        .into_iter()
        .map(|path| path.as_ref().to_path_buf())
        .collect::<Vec<_>>();
    if paths.is_empty() {
        return Err(NodeSetLoaderError::NoPaths);
    }
    Ok(paths)
}

fn validate_collection_references(collection: &NodeSetCollection) -> Result<(), XmlError> {
    for (node_set_index, node_set) in collection.node_sets().iter().enumerate() {
        validate_node_set_references(collection, node_set_index, node_set)?;
    }
    Ok(())
}

fn validate_node_set_references(
    collection: &NodeSetCollection,
    node_set_index: usize,
    node_set: &NodeSet2,
) -> Result<(), XmlError> {
    let Some(node_set) = node_set.node_set.as_ref() else {
        return Ok(());
    };

    for node in &node_set.nodes {
        let base = node.base();
        collection.expand_node_id(node_set_index, &base.node_id)?;

        let Some(references) = base.references.as_ref() else {
            continue;
        };
        for reference in &references.references {
            collection.expand_node_id(node_set_index, &reference.reference_type)?;
            collection.expand_node_id(node_set_index, &reference.node_id)?;
            let _ = collection.resolve_reference(node_set_index, &reference.node_id);
        }

        validate_node_specific_references(collection, node_set_index, node)?;
    }

    Ok(())
}

fn validate_node_specific_references(
    collection: &NodeSetCollection,
    node_set_index: usize,
    node: &UANode,
) -> Result<(), XmlError> {
    match node {
        UANode::Variable(node) => {
            collection.expand_node_id(node_set_index, &node.data_type)?;
        }
        UANode::VariableType(node) => {
            collection.expand_node_id(node_set_index, &node.data_type)?;
        }
        UANode::Method(node) => {
            if let Some(method_declaration_id) = &node.method_declaration_id {
                collection.expand_node_id(node_set_index, method_declaration_id)?;
            }
        }
        UANode::DataType(node) => {
            if let Some(definition) = &node.definition {
                for field in &definition.fields {
                    collection.expand_node_id(node_set_index, &field.data_type)?;
                }
            }
        }
        UANode::Object(_) | UANode::View(_) | UANode::ObjectType(_) | UANode::ReferenceType(_) => {}
    }
    Ok(())
}
