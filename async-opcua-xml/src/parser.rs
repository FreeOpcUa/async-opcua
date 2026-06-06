//! Unified parser logic for OPC UA XML documents (NodeSets, BSD TypeDictionaries, XSD Schemas).

use std::{
    collections::{HashMap, HashSet},
    fs, io,
    path::{Path, PathBuf},
};

use roxmltree::Document;

use crate::schema::opc_binary_schema::{load_bsd_file, ImportDirective, TypeDictionary};
use crate::schema::ua_node_set::{
    load_nodeset2_file, DataTypeDefinition, NodeId, NodeSet2, UANode,
};
use crate::schema::xml_schema::{load_xsd_schema, XmlSchema};
use crate::{XmlError, XmlErrorInner};

/// Namespace URI for the OPC UA base namespace, which is implicit for `ns=0` NodeIds.
pub const OPC_UA_NAMESPACE_URI: &str = "http://opcfoundation.org/UA/";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Location of a node inside a [`NodeSetCollection`].
pub struct NodeLocation {
    /// Index of the containing NodeSet in [`NodeSetCollection::node_sets`].
    pub node_set_index: usize,
    /// Index of the node inside the containing `UANodeSet`.
    pub node_index: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Namespace-expanded NodeId in the context of a specific NodeSet.
pub struct ExpandedNodeId {
    /// Namespace URI, when the local namespace index can be resolved.
    pub namespace_uri: Option<String>,
    /// Local namespace index from the source NodeSet.
    pub namespace_index: u16,
    /// Identifier part of the NodeId, for example `i=85` or `s=Device1`.
    pub identifier: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum NodeNamespace {
    Uri(String),
    Index(u16),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct NodeKey {
    namespace: NodeNamespace,
    identifier: String,
}

#[derive(Debug)]
/// Parsed collection of one or more NodeSet2 files with namespace-aware lookup.
pub struct NodeSetCollection {
    node_sets: Vec<NodeSet2>,
    namespace_uris: Vec<String>,
    namespace_lookup: HashMap<String, usize>,
    aliases: Vec<HashMap<String, String>>,
    nodes_by_id: HashMap<NodeKey, NodeLocation>,
}

impl NodeSetCollection {
    /// Build a collection from parsed NodeSet2 documents.
    pub fn new(node_sets: Vec<NodeSet2>) -> Result<Self, XmlError> {
        let aliases = node_sets.iter().map(Self::aliases_for).collect::<Vec<_>>();
        let (namespace_uris, namespace_lookup) = Self::collect_namespaces(&node_sets);
        let mut collection = Self {
            node_sets,
            namespace_uris,
            namespace_lookup,
            aliases,
            nodes_by_id: HashMap::new(),
        };
        collection.index_nodes()?;
        Ok(collection)
    }

    /// Parsed NodeSet2 documents in load order.
    pub fn node_sets(&self) -> &[NodeSet2] {
        &self.node_sets
    }

    /// Known namespace URIs across all loaded NodeSets.
    pub fn namespace_uris(&self) -> &[String] {
        &self.namespace_uris
    }

    /// Get a node by location.
    pub fn node(&self, location: NodeLocation) -> Option<&UANode> {
        self.node_sets
            .get(location.node_set_index)
            .and_then(|node_set| node_set.node_set.as_ref())
            .and_then(|node_set| node_set.nodes.get(location.node_index))
    }

    /// Find a node by namespace URI and identifier, for example `("urn:di", "i=1001")`.
    pub fn find_node(&self, namespace_uri: &str, identifier: &str) -> Option<&UANode> {
        self.node_location(namespace_uri, identifier)
            .and_then(|location| self.node(location))
    }

    /// Find a node location by namespace URI and identifier.
    pub fn node_location(&self, namespace_uri: &str, identifier: &str) -> Option<NodeLocation> {
        let key = NodeKey {
            namespace: NodeNamespace::Uri(namespace_uri.to_owned()),
            identifier: identifier.to_owned(),
        };
        self.nodes_by_id.get(&key).copied()
    }

    /// Resolve a NodeId string in the namespace/alias context of a source NodeSet.
    pub fn expand_node_id(
        &self,
        source_node_set_index: usize,
        node_id: &NodeId,
    ) -> Result<ExpandedNodeId, XmlError> {
        let (namespace_index, identifier) =
            self.parse_node_id_in_context(source_node_set_index, &node_id.0)?;
        Ok(ExpandedNodeId {
            namespace_uri: self
                .namespace_uri_for(source_node_set_index, namespace_index)
                .map(ToOwned::to_owned),
            namespace_index,
            identifier,
        })
    }

    /// Resolve a reference target in the namespace/alias context of a source NodeSet.
    pub fn resolve_reference(
        &self,
        source_node_set_index: usize,
        node_id: &NodeId,
    ) -> Option<&UANode> {
        self.node_key(source_node_set_index, node_id)
            .ok()
            .and_then(|key| self.nodes_by_id.get(&key).copied())
            .and_then(|location| self.node(location))
    }

    /// Find a parsed DataTypeDefinition by namespace URI and identifier.
    pub fn data_type_definition(
        &self,
        namespace_uri: &str,
        identifier: &str,
    ) -> Option<&DataTypeDefinition> {
        match self.find_node(namespace_uri, identifier)? {
            UANode::DataType(data_type) => data_type.definition.as_ref(),
            _ => None,
        }
    }

    fn index_nodes(&mut self) -> Result<(), XmlError> {
        for (node_set_index, node_set) in self.node_sets.iter().enumerate() {
            let Some(node_set) = node_set.node_set.as_ref() else {
                continue;
            };
            for (node_index, node) in node_set.nodes.iter().enumerate() {
                let key = self.node_key(node_set_index, &node.base().node_id)?;
                self.nodes_by_id.entry(key).or_insert(NodeLocation {
                    node_set_index,
                    node_index,
                });
            }
        }
        Ok(())
    }

    fn aliases_for(node_set: &NodeSet2) -> HashMap<String, String> {
        node_set
            .node_set
            .as_ref()
            .and_then(|node_set| node_set.aliases.as_ref())
            .map(|aliases| {
                aliases
                    .aliases
                    .iter()
                    .map(|alias| (alias.alias.clone(), alias.id.0.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    fn collect_namespaces(node_sets: &[NodeSet2]) -> (Vec<String>, HashMap<String, usize>) {
        let mut namespace_uris = Vec::new();
        let mut namespace_lookup = HashMap::new();
        Self::insert_namespace(
            &mut namespace_uris,
            &mut namespace_lookup,
            OPC_UA_NAMESPACE_URI,
        );
        for node_set in node_sets {
            let Some(uris) = node_set
                .node_set
                .as_ref()
                .and_then(|node_set| node_set.namespace_uris.as_ref())
            else {
                continue;
            };
            for uri in &uris.uris {
                Self::insert_namespace(&mut namespace_uris, &mut namespace_lookup, uri);
            }
        }
        (namespace_uris, namespace_lookup)
    }

    fn insert_namespace(
        namespace_uris: &mut Vec<String>,
        namespace_lookup: &mut HashMap<String, usize>,
        uri: &str,
    ) {
        if namespace_lookup.contains_key(uri) {
            return;
        }
        let index = namespace_uris.len();
        namespace_uris.push(uri.to_owned());
        namespace_lookup.insert(uri.to_owned(), index);
    }

    fn node_key(
        &self,
        source_node_set_index: usize,
        node_id: &NodeId,
    ) -> Result<NodeKey, XmlError> {
        let (namespace_index, identifier) =
            self.parse_node_id_in_context(source_node_set_index, &node_id.0)?;
        let namespace = self
            .namespace_uri_for(source_node_set_index, namespace_index)
            .map(|uri| NodeNamespace::Uri(uri.to_owned()))
            .unwrap_or(NodeNamespace::Index(namespace_index));
        Ok(NodeKey {
            namespace,
            identifier,
        })
    }

    fn parse_node_id_in_context(
        &self,
        source_node_set_index: usize,
        node_id: &str,
    ) -> Result<(u16, String), XmlError> {
        let resolved = self
            .aliases
            .get(source_node_set_index)
            .and_then(|aliases| aliases.get(node_id))
            .map(String::as_str)
            .unwrap_or(node_id);

        let Some(rest) = resolved.strip_prefix("ns=") else {
            return Ok((0, resolved.to_owned()));
        };
        let Some((namespace, identifier)) = rest.split_once(';') else {
            return Err(other_error(&format!(
                "invalid NodeId namespace syntax: {resolved}"
            )));
        };
        let namespace_index = namespace.parse().map_err(|e| XmlError {
            span: 0..0,
            error: XmlErrorInner::Other(format!(
                "invalid NodeId namespace index in {resolved}: {e}"
            )),
        })?;
        Ok((namespace_index, identifier.to_owned()))
    }

    fn namespace_uri_for(
        &self,
        source_node_set_index: usize,
        namespace_index: u16,
    ) -> Option<&str> {
        if namespace_index == 0 {
            return Some(OPC_UA_NAMESPACE_URI);
        }
        let local_index = usize::from(namespace_index.saturating_sub(1));
        let local_uri = self
            .node_sets
            .get(source_node_set_index)
            .and_then(|node_set| node_set.node_set.as_ref())
            .and_then(|node_set| node_set.namespace_uris.as_ref())
            .and_then(|uris| uris.uris.get(local_index))?;
        self.namespace_lookup
            .get(local_uri)
            .and_then(|global_index| self.namespace_uris.get(*global_index))
            .map(String::as_str)
    }
}

#[derive(Debug, Default)]
/// Parsed XML schemas with namespace lookup.
pub struct XmlSchemaCollection {
    schemas: Vec<XmlSchema>,
    schema_by_namespace: HashMap<String, usize>,
}

impl XmlSchemaCollection {
    /// Parsed XSD schemas in load order.
    pub fn schemas(&self) -> &[XmlSchema] {
        &self.schemas
    }

    /// Find an XML schema by target namespace.
    pub fn find_schema(&self, namespace: &str) -> Option<&XmlSchema> {
        self.schema_by_namespace
            .get(namespace)
            .and_then(|index| self.schemas.get(*index))
    }

    fn add_schema(&mut self, schema: XmlSchema) {
        if let Some(namespace) = schema.target_namespace.as_ref() {
            if self.schema_by_namespace.contains_key(namespace) {
                return;
            }
            self.schema_by_namespace
                .insert(namespace.clone(), self.schemas.len());
        }
        self.schemas.push(schema);
    }
}

#[derive(Debug)]
/// Resolved BSD import target.
pub enum ResolvedSchemaImport<'a> {
    /// Import resolved to another BSD type dictionary.
    TypeDictionary(&'a TypeDictionary),
    /// Import resolved to an XSD schema.
    XmlSchema(&'a XmlSchema),
}

#[derive(Debug, Default)]
/// Parsed BSD type dictionaries and XSD schemas with namespace lookup.
pub struct TypeDictionaryCollection {
    dictionaries: Vec<TypeDictionary>,
    dictionary_by_namespace: HashMap<String, usize>,
    xml_schemas: XmlSchemaCollection,
}

impl TypeDictionaryCollection {
    /// Parsed BSD type dictionaries in load order.
    pub fn type_dictionaries(&self) -> &[TypeDictionary] {
        &self.dictionaries
    }

    /// Parsed XSD schemas imported by the dictionaries.
    pub fn xml_schemas(&self) -> &[XmlSchema] {
        self.xml_schemas.schemas()
    }

    /// Find a BSD type dictionary by target namespace.
    pub fn find_type_dictionary(&self, namespace: &str) -> Option<&TypeDictionary> {
        self.dictionary_by_namespace
            .get(namespace)
            .and_then(|index| self.dictionaries.get(*index))
    }

    /// Find an imported XSD schema by target namespace.
    pub fn find_xml_schema(&self, namespace: &str) -> Option<&XmlSchema> {
        self.xml_schemas.find_schema(namespace)
    }

    /// Resolve a BSD import by namespace against loaded BSD and XSD imports.
    pub fn resolve_import(&self, import: &ImportDirective) -> Option<ResolvedSchemaImport<'_>> {
        let namespace = import.namespace.as_ref()?;
        self.find_type_dictionary(namespace)
            .map(ResolvedSchemaImport::TypeDictionary)
            .or_else(|| {
                self.find_xml_schema(namespace)
                    .map(ResolvedSchemaImport::XmlSchema)
            })
    }

    fn add_type_dictionary(&mut self, dictionary: TypeDictionary) {
        if self
            .dictionary_by_namespace
            .contains_key(&dictionary.target_namespace)
        {
            return;
        }
        self.dictionary_by_namespace
            .insert(dictionary.target_namespace.clone(), self.dictionaries.len());
        self.dictionaries.push(dictionary);
    }

    fn add_xml_schema(&mut self, schema: XmlSchema) {
        self.xml_schemas.add_schema(schema);
    }
}

/// Parser for OPC UA XML files
pub struct OpcUaXmlParser;

impl OpcUaXmlParser {
    /// Parse a NodeSet2 XML document from a string.
    pub fn parse_nodeset(data: &str) -> Result<NodeSet2, XmlError> {
        load_nodeset2_file(data)
    }

    /// Parse multiple NodeSet2 XML documents and build a namespace-aware collection.
    pub fn parse_nodesets<I, S>(documents: I) -> Result<NodeSetCollection, XmlError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        documents
            .into_iter()
            .map(|document| Self::parse_nodeset(document.as_ref()))
            .collect::<Result<Vec<_>, _>>()
            .and_then(NodeSetCollection::new)
    }

    /// Parse a NodeSet2 XML document from a file.
    pub fn parse_nodeset_file<P: AsRef<Path>>(path: P) -> Result<NodeSet2, XmlError> {
        let path = path.as_ref();
        let content = read_file(path, "reading NodeSet")?;
        Self::parse_nodeset(&content)
    }

    /// Parse multiple NodeSet2 XML files and build a namespace-aware collection.
    pub fn parse_nodeset_files<I, P>(paths: I) -> Result<NodeSetCollection, XmlError>
    where
        I: IntoIterator<Item = P>,
        P: AsRef<Path>,
    {
        paths
            .into_iter()
            .map(Self::parse_nodeset_file)
            .collect::<Result<Vec<_>, _>>()
            .and_then(NodeSetCollection::new)
    }

    /// Parse a Binary Schema Definition (BSD) type dictionary from a string.
    pub fn parse_bsd(data: &str) -> Result<TypeDictionary, XmlError> {
        load_bsd_file(data)
    }

    /// Parse a Binary Schema Definition (BSD) type dictionary from a file.
    pub fn parse_bsd_file<P: AsRef<Path>>(path: P) -> Result<TypeDictionary, XmlError> {
        let path = path.as_ref();
        let content = read_file(path, "reading BSD")?;
        Self::parse_bsd(&content)
    }

    /// Parse a BSD file and recursively load local BSD/XSD imports.
    pub fn parse_bsd_file_with_imports<P: AsRef<Path>>(
        path: P,
    ) -> Result<TypeDictionaryCollection, XmlError> {
        let mut collection = TypeDictionaryCollection::default();
        let mut visited = HashSet::new();
        Self::load_schema_file_with_imports(path.as_ref(), &mut collection, &mut visited)?;
        Ok(collection)
    }

    /// Parse an XML Schema Definition (XSD) schema from a string.
    pub fn parse_xsd(data: &str) -> Result<XmlSchema, XmlError> {
        load_xsd_schema(data)
    }

    /// Parse an XML Schema Definition (XSD) schema from a file.
    pub fn parse_xsd_file<P: AsRef<Path>>(path: P) -> Result<XmlSchema, XmlError> {
        let path = path.as_ref();
        let content = read_file(path, "reading XSD")?;
        Self::parse_xsd(&content)
    }

    /// Parse an XSD file and recursively load local XSD imports.
    pub fn parse_xsd_file_with_imports<P: AsRef<Path>>(
        path: P,
    ) -> Result<XmlSchemaCollection, XmlError> {
        let mut collection = XmlSchemaCollection::default();
        let mut visited = HashSet::new();
        Self::load_xsd_file_with_imports(path.as_ref(), &mut collection, &mut visited)?;
        Ok(collection)
    }

    fn load_schema_file_with_imports(
        path: &Path,
        collection: &mut TypeDictionaryCollection,
        visited: &mut HashSet<PathBuf>,
    ) -> Result<(), XmlError> {
        let key = visited_key(path);
        if !visited.insert(key) {
            return Ok(());
        }

        let content = read_file(path, "reading imported schema")?;
        match root_element_name(&content)?.as_str() {
            "TypeDictionary" => {
                let dictionary = Self::parse_bsd(&content)?;
                let imports = dictionary
                    .imports
                    .iter()
                    .filter_map(|import| import.location.clone())
                    .collect::<Vec<_>>();
                collection.add_type_dictionary(dictionary);
                for location in imports {
                    Self::load_schema_import(path, &location, collection, visited)?;
                }
                Ok(())
            }
            "schema" => {
                let schema = Self::parse_xsd(&content)?;
                let imports = schema
                    .imports
                    .iter()
                    .filter_map(|import| import.schema_location.clone())
                    .collect::<Vec<_>>();
                collection.add_xml_schema(schema);
                for location in imports {
                    Self::load_schema_import(path, &location, collection, visited)?;
                }
                Ok(())
            }
            other => Err(other_error(&format!(
                "unsupported imported XML root element {other} in {}",
                path.display()
            ))),
        }
    }

    fn load_xsd_file_with_imports(
        path: &Path,
        collection: &mut XmlSchemaCollection,
        visited: &mut HashSet<PathBuf>,
    ) -> Result<(), XmlError> {
        let key = visited_key(path);
        if !visited.insert(key) {
            return Ok(());
        }

        let content = read_file(path, "reading imported XSD")?;
        let root = root_element_name(&content)?;
        if root != "schema" {
            return Err(other_error(&format!(
                "unsupported XSD root element {root} in {}",
                path.display()
            )));
        }

        let schema = Self::parse_xsd(&content)?;
        let imports = schema
            .imports
            .iter()
            .filter_map(|import| import.schema_location.clone())
            .collect::<Vec<_>>();
        collection.add_schema(schema);
        for location in imports {
            if is_remote_location(&location) {
                continue;
            }
            let import_path = resolve_import_path(path, &location);
            Self::load_xsd_file_with_imports(&import_path, collection, visited)?;
        }
        Ok(())
    }

    fn load_schema_import(
        source_path: &Path,
        location: &str,
        collection: &mut TypeDictionaryCollection,
        visited: &mut HashSet<PathBuf>,
    ) -> Result<(), XmlError> {
        if is_remote_location(location) {
            return Ok(());
        }
        let import_path = resolve_import_path(source_path, location);
        Self::load_schema_file_with_imports(&import_path, collection, visited)
    }
}

fn read_file(path: &Path, action: &str) -> Result<String, XmlError> {
    fs::read_to_string(path).map_err(|e| io_error(path, action, e))
}

fn io_error(path: &Path, action: &str, error: io::Error) -> XmlError {
    XmlError {
        span: 0..0,
        error: XmlErrorInner::Other(format!("{action} {}: {error}", path.display())),
    }
}

fn other_error(message: &str) -> XmlError {
    XmlError {
        span: 0..0,
        error: XmlErrorInner::Other(message.to_owned()),
    }
}

fn root_element_name(document: &str) -> Result<String, XmlError> {
    let document = Document::parse(document).map_err(|e| XmlError {
        span: 0..1,
        error: XmlErrorInner::Xml(e),
    })?;
    document
        .root()
        .children()
        .find(|node| node.is_element())
        .map(|node| node.tag_name().name().to_owned())
        .ok_or_else(|| other_error("missing XML document element"))
}

fn resolve_import_path(source_path: &Path, location: &str) -> PathBuf {
    let import_path = Path::new(location);
    if import_path.is_absolute() {
        return import_path.to_path_buf();
    }
    source_path
        .parent()
        .map(|parent| parent.join(import_path))
        .unwrap_or_else(|| import_path.to_path_buf())
}

fn visited_key(path: &Path) -> PathBuf {
    match fs::canonicalize(path) {
        Ok(path) => path,
        Err(_) => path.to_path_buf(),
    }
}

fn is_remote_location(location: &str) -> bool {
    location.contains("://") || location.starts_with("urn:")
}

#[cfg(test)]
mod tests {
    use std::{error::Error, fs};

    use crate::schema::ua_node_set::UANode;

    use super::OpcUaXmlParser;

    const BASE_NODESET: &str = r#"
<UANodeSet>
  <NamespaceUris>
    <Uri>urn:base</Uri>
  </NamespaceUris>
  <Aliases>
    <Alias Alias="HasSubtype">i=45</Alias>
  </Aliases>
  <UADataType NodeId="ns=1;i=1001" BrowseName="1:BaseStruct">
    <DisplayName>BaseStruct</DisplayName>
    <Definition Name="1:BaseStruct">
      <Field Name="BaseValue" DataType="i=6" />
    </Definition>
  </UADataType>
</UANodeSet>
"#;

    const COMPANION_NODESET: &str = r#"
<UANodeSet xmlns:di="http://opcfoundation.org/UA/DI/">
  <NamespaceUris>
    <Uri>urn:base</Uri>
    <Uri>urn:companion</Uri>
  </NamespaceUris>
  <Aliases>
    <Alias Alias="HasSubtype">i=45</Alias>
  </Aliases>
  <UADataType NodeId="ns=2;i=2001" BrowseName="2:CustomUnion" di:Extra="ignored">
    <DisplayName>CustomUnion</DisplayName>
    <References>
      <Reference ReferenceType="HasSubtype" IsForward="false">ns=1;i=1001</Reference>
    </References>
    <Definition Name="2:CustomUnion" IsUnion="true">
      <Field Name="IntChoice" DataType="i=6" />
      <Field Name="TextChoice" DataType="i=12" />
      <di:VendorExtension>ignored</di:VendorExtension>
    </Definition>
    <di:DocumentationExtension>ignored</di:DocumentationExtension>
  </UADataType>
  <UADataType NodeId="ns=2;i=2002" BrowseName="2:SparseOptionSet">
    <DisplayName>SparseOptionSet</DisplayName>
    <Definition Name="2:SparseOptionSet" IsOptionSet="true">
      <Field Name="BitZero" Value="0" />
      <Field Name="BitFive" Value="5" />
    </Definition>
  </UADataType>
</UANodeSet>
"#;

    #[test]
    fn nodeset_collection_resolves_cross_namespace_references_and_custom_definitions(
    ) -> Result<(), Box<dyn Error>> {
        let collection = OpcUaXmlParser::parse_nodesets([BASE_NODESET, COMPANION_NODESET])?;

        let union_location = collection
            .node_location("urn:companion", "i=2001")
            .ok_or("missing companion union")?;
        let union = collection
            .node(union_location)
            .ok_or("missing companion union node")?;
        let base_ref = match union {
            UANode::DataType(data_type) => data_type
                .base
                .base
                .references
                .as_ref()
                .and_then(|refs| refs.references.first())
                .ok_or("missing base reference")?,
            _ => return Err("expected data type".into()),
        };

        let resolved = collection
            .resolve_reference(union_location.node_set_index, &base_ref.node_id)
            .ok_or("unresolved base reference")?;
        assert_eq!(resolved.base().browse_name.0, "1:BaseStruct");

        let union_definition = collection
            .data_type_definition("urn:companion", "i=2001")
            .ok_or("missing union definition")?;
        assert!(union_definition.is_union);
        assert_eq!(union_definition.fields.len(), 2);

        let option_set_definition = collection
            .data_type_definition("urn:companion", "i=2002")
            .ok_or("missing option set definition")?;
        assert!(option_set_definition.is_option_set);
        assert_eq!(option_set_definition.fields[1].value, 5);

        Ok(())
    }

    #[test]
    fn bsd_file_loading_resolves_bsd_and_xsd_imports() -> Result<(), Box<dyn Error>> {
        let dir = std::env::temp_dir().join(format!(
            "async_opcua_xml_parser_imports_{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir)?;

        let root_bsd = dir.join("Root.Types.bsd");
        let base_bsd = dir.join("Base.Types.bsd");
        let helper_xsd = dir.join("Helper.Types.xsd");
        let nested_xsd = dir.join("Nested.Types.xsd");

        fs::write(
            &root_bsd,
            r#"<opc:TypeDictionary xmlns:opc="http://opcfoundation.org/BinarySchema/" TargetNamespace="urn:root">
  <opc:Import Namespace="urn:base" Location="Base.Types.bsd" />
  <opc:Import Namespace="urn:helper" Location="Helper.Types.xsd" />
  <opc:StructuredType Name="RootStruct">
    <opc:Field Name="Base" TypeName="base:BaseStruct" />
  </opc:StructuredType>
</opc:TypeDictionary>"#,
        )?;
        fs::write(
            &base_bsd,
            r#"<opc:TypeDictionary xmlns:opc="http://opcfoundation.org/BinarySchema/" TargetNamespace="urn:base">
  <opc:StructuredType Name="BaseStruct">
    <opc:Field Name="Value" TypeName="opc:Int32" />
  </opc:StructuredType>
</opc:TypeDictionary>"#,
        )?;
        fs::write(
            &helper_xsd,
            r#"<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema" targetNamespace="urn:helper">
  <xs:import namespace="urn:nested" schemaLocation="Nested.Types.xsd" />
  <xs:simpleType name="HelperEnum">
    <xs:restriction base="xs:string">
      <xs:enumeration value="A" />
    </xs:restriction>
  </xs:simpleType>
</xs:schema>"#,
        )?;
        fs::write(
            &nested_xsd,
            r#"<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema" targetNamespace="urn:nested">
  <xs:simpleType name="NestedEnum">
    <xs:restriction base="xs:string">
      <xs:enumeration value="B" />
    </xs:restriction>
  </xs:simpleType>
</xs:schema>"#,
        )?;

        let collection = OpcUaXmlParser::parse_bsd_file_with_imports(&root_bsd)?;
        assert!(collection.find_type_dictionary("urn:root").is_some());
        assert!(collection.find_type_dictionary("urn:base").is_some());
        assert!(collection.find_xml_schema("urn:helper").is_some());
        assert!(collection.find_xml_schema("urn:nested").is_some());

        fs::remove_dir_all(&dir)?;
        Ok(())
    }
}
