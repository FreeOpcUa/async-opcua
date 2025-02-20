use std::{
    path::Path,
    str::FromStr,
    sync::{Arc, OnceLock},
};

use hashbrown::HashMap;
use log::warn;
use opcua_types::{
    Context, DataTypeDefinition, DataValue, DecodingOptions, EnumDefinition, EnumField, Error,
    LocalizedText, NodeClass, NodeId, QualifiedName, StructureDefinition, StructureField,
    StructureType, TypeLoader, TypeLoaderCollection, Variant,
};
use opcua_xml::{
    load_nodeset2_file,
    schema::ua_node_set::{
        self, ArrayDimensions, ListOfReferences, UADataType, UAMethod, UANodeSet, UAObject,
        UAObjectType, UAReferenceType, UAVariable, UAVariableType, UAView,
    },
    XmlError,
};
use regex::Regex;

use crate::{
    Base, DataType, EventNotifier, ImportedItem, ImportedReference, Method, NodeSetImport, Object,
    ObjectType, ReferenceType, Variable, VariableType, View,
};

/// [`NodeSetImport`] implementation for dynamically loading NodeSet2 files at
/// runtime. Note that structures must be loaded with a type loader. By default
/// the type loader for the base types is registered, but if your NodeSet2 file uses custom types
/// you will have to add an [`TypeLoader`] using [`NodeSet2Import::add_type_loader`].
pub struct NodeSet2Import {
    type_loaders: TypeLoaderCollection,
    dependent_namespaces: Vec<String>,
    preferred_locale: String,
    aliases: HashMap<String, String>,
    file: UANodeSet,
}

static QUALIFIED_NAME_REGEX: OnceLock<Regex> = OnceLock::new();

fn qualified_name_regex() -> &'static Regex {
    QUALIFIED_NAME_REGEX.get_or_init(|| Regex::new(r"^((?P<ns>[0-9]+):)?(?P<name>.*)$").unwrap())
}

#[derive(thiserror::Error, Debug)]
/// Error when loading NodeSet2 XML.
pub enum LoadXmlError {
    /// The XML file failed to parse.
    #[error("{0}")]
    Xml(#[from] XmlError),
    /// The file failed to load.
    #[error("{0}")]
    Io(#[from] std::io::Error),
    /// The nodeset section is missing from the file. It is most likely invalid.
    #[error("Missing <NodeSet> section from file")]
    MissingNodeSet,
}

impl NodeSet2Import {
    /// Create a new NodeSet2 importer.
    /// The `dependent_namespaces` array contains namespaces that this nodeset requires, in order,
    /// but that are _not_ included in the nodeset file itself.
    /// It does not need to include the base namespace, but it may.
    ///
    /// # Example
    ///
    /// ```ignore
    /// NodeSet2Import::new(
    ///     "en",
    ///     "My.ISA95.Extension.NodeSet2.xml",
    ///     // Since we depend on ISA95, we need to include the ISA95 namespace.
    ///     // Typically, the NodeSet will reference ns=1 as ISA95, and ns=2 as its own
    ///     // namespace, this will allow us to interpret ns=1 correctly. Without this,
    ///     // we would panic when failing to look up ns=2.
    ///     vec!["http://www.OPCFoundation.org/UA/2013/01/ISA95"]
    /// )
    /// ```
    pub fn new(
        preferred_locale: &str,
        path: impl AsRef<Path>,
        dependent_namespaces: Vec<String>,
    ) -> Result<Self, LoadXmlError> {
        let content = std::fs::read_to_string(path)?;
        Self::new_str(preferred_locale, &content, dependent_namespaces)
    }

    /// Create a new NodeSet2 importer from an already loaded `NodeSet2.xml` file.
    ///
    /// See documentation of [NodeSet2Import::new].
    pub fn new_str(
        preferred_locale: &str,
        nodeset: &str,
        dependent_namespaces: Vec<String>,
    ) -> Result<Self, LoadXmlError> {
        let nodeset = load_nodeset2_file(nodeset)?;
        let nodeset = nodeset.node_set.ok_or(LoadXmlError::MissingNodeSet)?;

        Ok(Self::new_nodeset(
            preferred_locale,
            nodeset,
            dependent_namespaces,
        ))
    }

    /// Create a new importer with a pre-loaded nodeset.
    /// The `dependent_namespaces` array contains namespaces that this nodeset requires, in order,
    /// but that are _not_ included in the nodeset file itself.
    /// It does not need to include the base namespace, but it may.
    pub fn new_nodeset(
        preferred_locale: &str,
        nodeset: UANodeSet,
        dependent_namespaces: Vec<String>,
    ) -> Self {
        let aliases = nodeset
            .aliases
            .iter()
            .flat_map(|i| i.aliases.iter())
            .map(|alias| (alias.alias.clone(), alias.id.0.clone()))
            .collect();
        Self {
            preferred_locale: preferred_locale.to_owned(),
            type_loaders: TypeLoaderCollection::new(),
            file: nodeset,
            dependent_namespaces,
            aliases,
        }
    }

    /// Add a type loader for importing types from XML.
    ///
    /// Any custom variable Value must be supported by one of the added
    /// type loaders in order for the node set import to work.
    pub fn add_type_loader(&mut self, loader: Arc<dyn TypeLoader>) {
        self.type_loaders.add(loader);
    }

    fn select_localized_text(&self, texts: &[ua_node_set::LocalizedText]) -> Option<LocalizedText> {
        let mut selected_str = None;
        for text in texts {
            if text.locale.0.is_empty() && selected_str.is_none()
                || text.locale.0 == self.preferred_locale
            {
                selected_str = Some(text);
            }
        }
        let selected_str = selected_str.or_else(|| texts.first());
        let selected = selected_str?;
        Some(LocalizedText::new(&selected.locale.0, &selected.text))
    }

    fn make_node_id(
        &self,
        node_id: &ua_node_set::NodeId,
        ctx: &Context<'_>,
    ) -> Result<NodeId, Error> {
        let node_id_str = ctx.resolve_alias(&node_id.0);

        let Some(mut parsed) = NodeId::from_str(node_id_str).ok() else {
            return Err(Error::decoding(format!(
                "Failed to parse node ID: {node_id_str}"
            )));
        };

        parsed.namespace = ctx.resolve_namespace_index(parsed.namespace)?;
        Ok(parsed)
    }

    fn make_qualified_name(
        &self,
        qname: &ua_node_set::QualifiedName,
        ctx: &Context<'_>,
    ) -> Result<QualifiedName, Error> {
        let captures = qualified_name_regex()
            .captures(&qname.0)
            .ok_or_else(|| Error::decoding(format!("Invalid qualified name: {}", qname.0)))?;

        let namespace = if let Some(ns) = captures.name("ns") {
            ns.as_str().trim().parse::<u16>().map_err(|e| {
                Error::decoding(format!(
                    "Failed to parse namespace index from qualified name: {}, {e:?}",
                    qname.0
                ))
            })?
        } else {
            0
        };

        let namespace = ctx.resolve_namespace_index(namespace)?;
        let name = captures.name("name").map(|n| n.as_str()).unwrap_or("");
        Ok(QualifiedName::new(namespace, name))
    }

    fn make_array_dimensions(&self, dims: &ArrayDimensions) -> Result<Option<Vec<u32>>, Error> {
        if dims.0.trim().is_empty() {
            return Ok(None);
        }

        let mut values = Vec::new();
        for it in dims.0.split(',') {
            let Ok(r) = it.trim().parse::<u32>() else {
                return Err(Error::decoding(format!(
                    "Invalid array dimensions: {}",
                    dims.0
                )));
            };
            values.push(r);
        }
        if values.is_empty() {
            Ok(None)
        } else {
            Ok(Some(values))
        }
    }

    fn make_data_type_def(
        &self,
        def: &ua_node_set::DataTypeDefinition,
        ctx: &Context<'_>,
    ) -> Result<DataTypeDefinition, Error> {
        let is_enum = def.fields.first().is_some_and(|f| f.value != -1);
        if is_enum {
            let fields = def
                .fields
                .iter()
                .map(|field| EnumField {
                    value: field.value,
                    display_name: self
                        .select_localized_text(&field.display_names)
                        .unwrap_or_default(),
                    description: self
                        .select_localized_text(&field.descriptions)
                        .unwrap_or_default(),
                    name: field.name.clone().into(),
                })
                .collect();
            Ok(DataTypeDefinition::Enum(EnumDefinition {
                fields: Some(fields),
            }))
        } else {
            let mut any_optional = false;
            let mut fields = Vec::with_capacity(def.fields.len());
            for field in &def.fields {
                any_optional |= field.is_optional;
                fields.push(StructureField {
                    name: field.name.clone().into(),
                    description: self
                        .select_localized_text(&field.descriptions)
                        .unwrap_or_default(),
                    data_type: self.make_node_id(&field.data_type, ctx).unwrap_or_default(),
                    value_rank: field.value_rank.0,
                    array_dimensions: self.make_array_dimensions(&field.array_dimensions)?,
                    max_string_length: field.max_string_length as u32,
                    is_optional: field.is_optional,
                });
            }
            Ok(DataTypeDefinition::Structure(StructureDefinition {
                default_encoding_id: NodeId::null(),
                base_data_type: NodeId::null(),
                structure_type: if def.is_union {
                    StructureType::Union
                } else if any_optional {
                    StructureType::StructureWithOptionalFields
                } else {
                    StructureType::Structure
                },
                fields: Some(fields),
            }))
        }
    }

    fn make_base(
        &self,
        ctx: &Context<'_>,
        base: &ua_node_set::UANodeBase,
        node_class: NodeClass,
    ) -> Result<Base, Error> {
        Ok(Base::new_full(
            self.make_node_id(&base.node_id, ctx)?,
            node_class,
            self.make_qualified_name(&base.browse_name, ctx)?,
            self.select_localized_text(&base.display_names)
                .unwrap_or_default(),
            self.select_localized_text(&base.description),
            Some(base.write_mask.0),
            Some(base.user_write_mask.0),
        ))
    }

    fn make_references(
        &self,
        ctx: &Context<'_>,
        base: &Base,
        refs: &Option<ListOfReferences>,
    ) -> Result<Vec<ImportedReference>, Error> {
        let Some(refs) = refs.as_ref() else {
            return Ok(Vec::new());
        };
        let mut res = Vec::with_capacity(refs.references.len());
        for rf in &refs.references {
            let target_id = self.make_node_id(&rf.node_id, ctx).inspect_err(|e| {
                warn!(
                    "Invalid target ID {} on reference from node {}: {e}",
                    rf.node_id.0, base.node_id
                )
            })?;

            let type_id = self
                .make_node_id(&rf.reference_type, ctx)
                .inspect_err(|e| {
                    warn!(
                        "Invalid reference type ID {} on reference from node {}: {e}",
                        rf.node_id.0, base.node_id
                    )
                })?;
            res.push(ImportedReference {
                target_id,
                type_id,
                is_forward: rf.is_forward,
            });
        }
        Ok(res)
    }

    fn make_object(&self, ctx: &Context<'_>, node: &UAObject) -> Result<ImportedItem, Error> {
        let base = self.make_base(ctx, &node.base.base, NodeClass::Object)?;
        Ok(ImportedItem {
            references: self.make_references(ctx, &base, &node.base.base.references)?,
            node: Object::new_full(
                base,
                EventNotifier::from_bits_truncate(node.event_notifier.0),
            )
            .into(),
        })
    }

    fn make_variable(&self, ctx: &Context<'_>, node: &UAVariable) -> Result<ImportedItem, Error> {
        let base = self.make_base(ctx, &node.base.base, NodeClass::Variable)?;
        Ok(ImportedItem {
            references: self.make_references(ctx, &base, &node.base.base.references)?,
            node: Variable::new_full(
                base,
                self.make_node_id(&node.data_type, ctx)?,
                node.historizing,
                node.value_rank.0,
                node.value
                    .as_ref()
                    .map(|v| {
                        Ok::<DataValue, Error>(DataValue::new_now(Variant::from_nodeset(
                            &v.0, ctx,
                        )?))
                    })
                    .transpose()?
                    .unwrap_or_else(DataValue::null),
                node.access_level.0,
                node.user_access_level.0,
                self.make_array_dimensions(&node.array_dimensions)?,
                Some(node.minimum_sampling_interval.0),
            )
            .into(),
        })
    }

    fn make_method(&self, ctx: &Context<'_>, node: &UAMethod) -> Result<ImportedItem, Error> {
        let base = self.make_base(ctx, &node.base.base, NodeClass::Method)?;
        Ok(ImportedItem {
            references: self.make_references(ctx, &base, &node.base.base.references)?,
            node: Method::new_full(base, node.executable, node.user_executable).into(),
        })
    }

    fn make_view(&self, ctx: &Context<'_>, node: &UAView) -> Result<ImportedItem, Error> {
        let base = self.make_base(ctx, &node.base.base, NodeClass::View)?;
        Ok(ImportedItem {
            references: self.make_references(ctx, &base, &node.base.base.references)?,
            node: View::new_full(
                base,
                EventNotifier::from_bits_truncate(node.event_notifier.0),
                node.contains_no_loops,
            )
            .into(),
        })
    }

    fn make_object_type(
        &self,
        ctx: &Context<'_>,
        node: &UAObjectType,
    ) -> Result<ImportedItem, Error> {
        let base = self.make_base(ctx, &node.base.base, NodeClass::ObjectType)?;
        Ok(ImportedItem {
            references: self.make_references(ctx, &base, &node.base.base.references)?,
            node: ObjectType::new_full(base, node.base.is_abstract).into(),
        })
    }

    fn make_variable_type(
        &self,
        ctx: &Context<'_>,
        node: &UAVariableType,
    ) -> Result<ImportedItem, Error> {
        let base = self.make_base(ctx, &node.base.base, NodeClass::VariableType)?;
        Ok(ImportedItem {
            references: self.make_references(ctx, &base, &node.base.base.references)?,
            node: VariableType::new_full(
                base,
                self.make_node_id(&node.data_type, ctx)?,
                node.base.is_abstract,
                node.value_rank.0,
                node.value
                    .as_ref()
                    .map(|v| Ok::<_, Error>(DataValue::new_now(Variant::from_nodeset(&v.0, ctx)?)))
                    .transpose()?,
                self.make_array_dimensions(&node.array_dimensions)?,
            )
            .into(),
        })
    }

    fn make_data_type(&self, ctx: &Context<'_>, node: &UADataType) -> Result<ImportedItem, Error> {
        let base = self.make_base(ctx, &node.base.base, NodeClass::DataType)?;
        Ok(ImportedItem {
            references: self.make_references(ctx, &base, &node.base.base.references)?,
            node: DataType::new_full(
                base,
                node.base.is_abstract,
                node.definition
                    .as_ref()
                    .map(|v| self.make_data_type_def(v, ctx))
                    .transpose()?,
            )
            .into(),
        })
    }

    fn make_reference_type(
        &self,
        ctx: &Context<'_>,
        node: &UAReferenceType,
    ) -> Result<ImportedItem, Error> {
        let base = self.make_base(ctx, &node.base.base, NodeClass::ReferenceType)?;
        Ok(ImportedItem {
            references: self.make_references(ctx, &base, &node.base.base.references)?,
            node: ReferenceType::new_full(
                base,
                node.symmetric,
                node.base.is_abstract,
                self.select_localized_text(&node.inverse_names),
            )
            .into(),
        })
    }
}

impl NodeSetImport for NodeSet2Import {
    fn register_namespaces(&self, namespaces: &mut opcua_types::NodeSetNamespaceMapper) {
        let nss = self.get_own_namespaces();
        // If the root namespace is in the namespace array, use absolute indexes,
        // else, start at 1
        let mut offset = 1;
        for (idx, ns) in self
            .dependent_namespaces
            .iter()
            .chain(nss.iter())
            .enumerate()
        {
            if ns == "http://opcfoundation.org/UA/" {
                offset = 0;
                continue;
            }
            println!("Adding new namespace: {} {}", idx, ns);
            namespaces.add_namespace(ns, idx as u16 + offset);
        }
    }

    fn get_own_namespaces(&self) -> Vec<String> {
        self.file
            .namespace_uris
            .as_ref()
            .map(|n| n.uris.clone())
            .unwrap_or_default()
    }

    fn load<'a>(
        &'a self,
        namespaces: &'a opcua_types::NodeSetNamespaceMapper,
    ) -> Box<dyn Iterator<Item = crate::ImportedItem> + 'a> {
        let mut ctx = Context::new(
            namespaces.namespaces(),
            &self.type_loaders,
            DecodingOptions::default(),
        );
        ctx.set_aliases(&self.aliases);
        Box::new(self.file.nodes.iter().filter_map(move |raw_node| {
            let r = match raw_node {
                opcua_xml::schema::ua_node_set::UANode::Object(node) => {
                    self.make_object(&ctx, node)
                }
                opcua_xml::schema::ua_node_set::UANode::Variable(node) => {
                    self.make_variable(&ctx, node)
                }
                opcua_xml::schema::ua_node_set::UANode::Method(node) => {
                    self.make_method(&ctx, node)
                }
                opcua_xml::schema::ua_node_set::UANode::View(node) => self.make_view(&ctx, node),
                opcua_xml::schema::ua_node_set::UANode::ObjectType(node) => {
                    self.make_object_type(&ctx, node)
                }
                opcua_xml::schema::ua_node_set::UANode::VariableType(node) => {
                    self.make_variable_type(&ctx, node)
                }
                opcua_xml::schema::ua_node_set::UANode::DataType(node) => {
                    self.make_data_type(&ctx, node)
                }
                opcua_xml::schema::ua_node_set::UANode::ReferenceType(node) => {
                    self.make_reference_type(&ctx, node)
                }
            };
            match r {
                Ok(r) => Some(r),
                Err(e) => {
                    println!("Failed to import node {}: {e}", raw_node.base().node_id.0);
                    None
                }
            }
        }))
    }
}

#[cfg(test)]
mod tests {
    use opcua_types::{
        DataTypeId, EUInformation, ExtensionObject, LocalizedText, NamespaceMap,
        NodeSetNamespaceMapper, QualifiedName, Variant,
    };

    use crate::{NodeBase, NodeSetImport, NodeType};

    use super::NodeSet2Import;

    const TEST_NODESET: &str = r#"
<UANodeSet xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" LastModified="2023-12-15T00:00:00Z" xmlns="http://opcfoundation.org/UA/2011/03/UANodeSet.xsd">
  <NamespaceUris>
    <Uri>http://test.com</Uri>
  </NamespaceUris>
  <Models>
    <Model ModelUri="http://test.com" Version="1.00" PublicationDate="2013-11-06T00:00:00Z">
      <RequiredModel ModelUri="http://opcfoundation.org/UA/" />
    </Model>
  </Models>
  <Aliases>
    <Alias Alias="Int32">i=6</Alias>
    <Alias Alias="HasComponent">i=47</Alias>
    <Alias Alias="HasSubtype">i=45</Alias>
  </Aliases>
  <UAObject NodeId="ns=1;i=1" BrowseName="1:My Root">
    <DisplayName>My Root</DisplayName>
    <Description>My description</Description>
    <References>
      <Reference ReferenceType="HasComponent" IsForward="false">i=85</Reference>
      <Reference ReferenceType="i=40">i=61</Reference>
    </References>
  </UAObject>
  <UAVariable NodeId="ns=1;i=2" BrowseName="1:My Property" DataType="i=887">
    <DisplayName>My Property</DisplayName>
    <Description>My description</Description>
    <References>
      <Reference ReferenceType="i=40">i=68</Reference>
      <Reference ReferenceType="i=46" IsForward="false">ns=1;i=1</Reference>
    </References>
    <Value>
      <ExtensionObject>
        <TypeId><Identifier>i=888</Identifier></TypeId>
        <Body>
          <EUInformation>
            <NamespaceUri>http://unit-namespace.namespace</NamespaceUri>
            <UnitId>15</UnitId>
            <DisplayName>
                <Locale>en</Locale>
                <Text>Degrees Celsius</Text>
            </DisplayName>
          </EUInformation>
        </Body>
      </ExtensionObject>
    </Value>
  </UAVariable>
</UANodeSet>"#;

    #[test]
    fn test_load_xml_nodeset() {
        let import = NodeSet2Import::new_str("en", TEST_NODESET, vec![]).unwrap();
        assert_eq!(
            import.get_own_namespaces(),
            vec!["http://test.com".to_owned()]
        );
        let mut ns = NamespaceMap::new();
        let mut map = NodeSetNamespaceMapper::new(&mut ns);
        import.register_namespaces(&mut map);
        let nodes: Vec<_> = import.load(&map).collect();
        assert_eq!(nodes.len(), 2);
        let node = &nodes[0];
        let NodeType::Object(o) = &node.node else {
            panic!("Unexpected node type");
        };
        assert_eq!(o.display_name(), &LocalizedText::new("", "My Root"));
        assert_eq!(o.browse_name(), &QualifiedName::new(1, "My Root"));
        assert_eq!(node.references.len(), 2);

        let node = &nodes[1];
        let NodeType::Variable(v) = &node.node else {
            panic!("Unexpected node type");
        };
        assert_eq!(v.display_name(), &LocalizedText::new("", "My Property"));
        assert_eq!(v.browse_name(), &QualifiedName::new(1, "My Property"));
        assert_eq!(v.data_type(), DataTypeId::EUInformation);
        assert_eq!(
            v.value.value,
            Some(Variant::ExtensionObject(ExtensionObject::from_message(
                EUInformation {
                    namespace_uri: "http://unit-namespace.namespace".into(),
                    unit_id: 15,
                    display_name: LocalizedText::new("en", "Degrees Celsius"),
                    description: LocalizedText::null()
                }
            )))
        );
    }
}
