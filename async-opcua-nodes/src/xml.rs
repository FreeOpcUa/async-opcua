use std::{
    path::Path,
    str::FromStr,
    sync::{Arc, OnceLock},
};

use hashbrown::{HashMap, HashSet};
use opcua_types::{
    Context, DataTypeDefinition, DataTypeId, DataValue, DecodingOptions, EnumDefinition, EnumField,
    Error, LocalizedText, NodeClass, NodeId, QualifiedName, ReferenceTypeId, StructureDefinition,
    StructureField, StructureType, TypeLoader, TypeLoaderCollection, Variant,
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
use tracing::warn;

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
        default_encoding_id: NodeId,
        base_data_type: NodeId,
        file_data_types: &HashMap<NodeId, &opcua_xml::schema::ua_node_set::UANode>,
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
            // Start with base fields (bottom-up)
            let (fields, any_optional) =
                self.collect_structure_fields(ctx, def, &base_data_type, file_data_types)?;

            Ok(DataTypeDefinition::Structure(StructureDefinition {
                default_encoding_id,
                base_data_type,
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

    fn collect_structure_fields(
        &self,
        ctx: &Context<'_>,
        def: &ua_node_set::DataTypeDefinition,
        parent_id: &NodeId,
        file_data_types: &HashMap<NodeId, &opcua_xml::schema::ua_node_set::UANode>,
    ) -> Result<(Vec<StructureField>, bool), Error> {
        // Determine path up until i=22 (Structure)
        let mut path_elements: Vec<&opcua_xml::schema::ua_node_set::DataTypeDefinition> =
            Vec::new();
        path_elements.push(def);

        // Move upwards
        let mut current_id = parent_id.clone();

        while current_id != DataTypeId::Structure {
            // Find the base DataType node in the loaded file
            let parent_node = file_data_types.get(&current_id).and_then(|n| {
                if let opcua_xml::schema::ua_node_set::UANode::DataType(dt) = n {
                    Some(dt)
                } else {
                    None
                }
            });
            let Some(parent_dt) = parent_node else {
                break;
            };

            let Some(parent_def) = &parent_dt.definition else {
                break;
            };

            path_elements.push(parent_def);

            let base_base_type = parent_dt.base.base.references.as_ref().and_then(|refs| {
                refs.references.iter().find_map(|rf| {
                    // HasSubtype, IsForward=false
                    let type_id = self.make_node_id(&rf.reference_type, ctx).ok()?;
                    if type_id == ReferenceTypeId::HasSubtype && !rf.is_forward {
                        self.make_node_id(&rf.node_id, ctx).ok()
                    } else {
                        None
                    }
                })
            });

            if let Some(base_base_type) = &base_base_type {
                current_id = base_base_type.clone();
            } else {
                break;
            }
        }

        // walk over the reverse array and collect fields (top-down)
        // according to the standard each inherted struct gets all fields from its parent and adds additional fields
        let mut fields: Vec<StructureField> = Vec::new();
        let mut any_optional = false;
        for data_type_definition in path_elements.into_iter().rev() {
            for field in &data_type_definition.fields {
                // In general fields will not contain many entries, so a search on the vector is fine
                if fields.iter().any(|f| f.name.as_ref() == field.name) {
                    // This field is overridden by a child, skip it
                    continue;
                }

                any_optional = any_optional || field.is_optional;
                fields.push(StructureField {
                    name: field.name.clone().into(),
                    description: self
                        .select_localized_text(&field.descriptions)
                        .unwrap_or_default(),
                    data_type: self.make_node_id(&field.data_type, ctx).unwrap_or_default(),
                    value_rank: field.value_rank.0,
                    array_dimensions: self
                        .make_array_dimensions(&field.array_dimensions)
                        .unwrap_or_default(),
                    max_string_length: field.max_string_length as u32,
                    is_optional: field.is_optional,
                });
            }
        }

        Ok((fields, any_optional))
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

    fn make_data_type(
        &self,
        ctx: &Context<'_>,
        node: &UADataType,
        binary_encoding_types: &HashSet<String>,
        file_data_types: &HashMap<NodeId, &opcua_xml::schema::ua_node_set::UANode>,
    ) -> Result<ImportedItem, Error> {
        let base = self.make_base(ctx, &node.base.base, NodeClass::DataType)?;

        let mut base_data_type = NodeId::null();
        let mut default_encoding = NodeId::null();

        let references = self.make_references(ctx, &base, &node.base.base.references)?;

        for reference in references.iter() {
            // 1. Check for HasSubtype (Inward)
            if reference.type_id == ReferenceTypeId::HasSubtype && !reference.is_forward {
                // You want the NodeId of the target (the supertype), not the type_id of the reference
                base_data_type = reference.target_id.clone();
            }
            // 2. Check for HasEncoding (Forward)
            else if reference.type_id == ReferenceTypeId::HasEncoding
                && binary_encoding_types.contains(&reference.target_id.to_string())
            {
                default_encoding = reference.target_id.clone();
            }
        }

        Ok(ImportedItem {
            references,
            node: DataType::new_full(
                base,
                node.base.is_abstract,
                node.definition
                    .as_ref()
                    .map(|v| {
                        self.make_data_type_def(
                            v,
                            default_encoding,
                            base_data_type,
                            file_data_types,
                            ctx,
                        )
                    })
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
            println!("Adding new namespace: {idx} {ns}");
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

        // First pass to find all DataTypes that have a HasEncoding reference to a "Default Binary" encoding object,
        // so we can set the default_encoding_id correctly when loading DataType nodes in the second pass.
        // Likewise, we would need to collect all defined data types upfront.
        let mut binary_encoding_types: HashSet<String> = HashSet::new();
        let mut file_data_types: HashMap<NodeId, &opcua_xml::schema::ua_node_set::UANode> =
            HashMap::new();
        for raw_node in self.file.nodes.iter() {
            match raw_node {
                opcua_xml::schema::ua_node_set::UANode::Object(node) => {
                    if let Some(references) = &node.base.base.references {
                        references.references.iter().for_each(|reference| {
                            if reference.reference_type.0 == "HasTypeDefinition"
                                && reference.node_id.0 == "i=76"
                                && raw_node.base().browse_name.0 == "Default Binary"
                            {
                                binary_encoding_types.insert(raw_node.base().node_id.0.clone());
                            }
                        });
                    }
                }
                opcua_xml::schema::ua_node_set::UANode::DataType(node) => {
                    if let Ok(node_id) = self.make_node_id(&node.base.base.node_id, &ctx) {
                        file_data_types.insert(node_id, raw_node);
                    }
                }
                _ => {}
            }
        }

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
                    self.make_data_type(&ctx, node, &binary_encoding_types, &file_data_types)
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
        DataTypeDefinition, DataTypeId, EUInformation, ExtensionObject, LocalizedText,
        NamespaceMap, NodeId, NodeSetNamespaceMapper, QualifiedName, StructureType, Variant,
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

    /// Abstract base struct + derived struct inheritance:
    ///   AbstractBaseStruct (ns=1;i=110, IsAbstract=true) → Structure (i=22)
    ///   DerivedStruct (ns=1;i=111) → AbstractBaseStruct (ns=1;i=110)
    ///
    /// Expected: DerivedStruct's resolved fields are
    ///   [BaseField, DerivedField1, DerivedField2].
    const TEST_ABSTRACT_BASE_STRUCT_INHERITANCE: &str = r#"
<UANodeSet xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                     xmlns:xsd="http://www.w3.org/2001/XMLSchema"
                     LastModified="2023-12-15T00:00:00Z"
                     xmlns="http://opcfoundation.org/UA/2011/03/UANodeSet.xsd">
    <NamespaceUris>
        <Uri>http://test.com</Uri>
    </NamespaceUris>
    <Aliases>
        <Alias Alias="HasSubtype">i=45</Alias>
        <Alias Alias="Int32">i=6</Alias>
        <Alias Alias="Boolean">i=1</Alias>
    </Aliases>
    <UADataType NodeId="ns=1;i=110" BrowseName="1:AbstractBaseStruct" IsAbstract="true">
        <DisplayName>AbstractBaseStruct</DisplayName>
        <References>
            <Reference ReferenceType="HasSubtype" IsForward="false">i=22</Reference>
        </References>
        <Definition Name="1:AbstractBaseStruct">
            <Field Name="BaseField" DataType="Int32" ValueRank="-1" />
        </Definition>
    </UADataType>
    <UADataType NodeId="ns=1;i=111" BrowseName="1:DerivedStruct">
        <DisplayName>DerivedStruct</DisplayName>
        <References>
            <Reference ReferenceType="HasSubtype" IsForward="false">ns=1;i=110</Reference>
        </References>
        <Definition Name="1:DerivedStruct">
            <Field Name="DerivedField1" DataType="Boolean" ValueRank="-1" />
            <Field Name="DerivedField2" DataType="Int32" ValueRank="-1" />
        </Definition>
    </UADataType>
</UANodeSet>"#;

    /// Struct DataType with:
    ///  - inward HasSubtype  → i=22  (OPC UA "Structure" base type)
    ///  - forward HasEncoding → ns=1;i=11 (a "Default Binary" encoding object)
    ///    Expected: base_data_type = i=22, default_encoding_id = ns=1;i=11
    const TEST_STRUCT_WITH_BASE_AND_BINARY_ENCODING: &str = r#"
<UANodeSet xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
           xmlns:xsd="http://www.w3.org/2001/XMLSchema"
           LastModified="2023-12-15T00:00:00Z"
           xmlns="http://opcfoundation.org/UA/2011/03/UANodeSet.xsd">
  <NamespaceUris>
    <Uri>http://test.com</Uri>
  </NamespaceUris>
  <Aliases>
    <Alias Alias="HasSubtype">i=45</Alias>
    <Alias Alias="HasEncoding">i=38</Alias>
    <Alias Alias="HasTypeDefinition">i=40</Alias>
    <Alias Alias="Int32">i=6</Alias>
  </Aliases>
  <UADataType NodeId="ns=1;i=10" BrowseName="1:MyStruct">
    <DisplayName>MyStruct</DisplayName>
    <References>
      <Reference ReferenceType="HasSubtype" IsForward="false">i=22</Reference>
      <Reference ReferenceType="HasEncoding">ns=1;i=11</Reference>
    </References>
    <Definition Name="1:MyStruct">
      <Field Name="Field1" DataType="Int32" ValueRank="-1" />
      <Field Name="Field2" DataType="Int32" ValueRank="-1" />
    </Definition>
  </UADataType>
  <UAObject NodeId="ns=1;i=11" BrowseName="Default Binary">
    <DisplayName>Default Binary</DisplayName>
    <References>
      <Reference ReferenceType="HasTypeDefinition">i=76</Reference>
    </References>
  </UAObject>
</UANodeSet>"#;

    /// Struct DataType with a HasSubtype reference but NO HasEncoding reference.
    /// Expected: base_data_type = i=22, default_encoding_id = null NodeId
    const TEST_STRUCT_WITH_BASE_NO_ENCODING: &str = r#"
<UANodeSet xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
           xmlns:xsd="http://www.w3.org/2001/XMLSchema"
           LastModified="2023-12-15T00:00:00Z"
           xmlns="http://opcfoundation.org/UA/2011/03/UANodeSet.xsd">
  <NamespaceUris>
    <Uri>http://test.com</Uri>
  </NamespaceUris>
  <Aliases>
    <Alias Alias="HasSubtype">i=45</Alias>
    <Alias Alias="Int32">i=6</Alias>
  </Aliases>
  <UADataType NodeId="ns=1;i=10" BrowseName="1:MyStruct">
    <DisplayName>MyStruct</DisplayName>
    <References>
      <Reference ReferenceType="HasSubtype" IsForward="false">i=22</Reference>
    </References>
    <Definition Name="1:MyStruct">
      <Field Name="Field1" DataType="Int32" ValueRank="-1" />
    </Definition>
  </UADataType>
</UANodeSet>"#;

    /// DataType with a HasEncoding reference, but the encoding object's BrowseName
    /// is "Default XML" – not "Default Binary".
    /// Expected: default_encoding_id = null NodeId  (not detected as binary)
    const TEST_STRUCT_WITH_NON_BINARY_ENCODING_OBJECT: &str = r#"
<UANodeSet xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
           xmlns:xsd="http://www.w3.org/2001/XMLSchema"
           LastModified="2023-12-15T00:00:00Z"
           xmlns="http://opcfoundation.org/UA/2011/03/UANodeSet.xsd">
  <NamespaceUris>
    <Uri>http://test.com</Uri>
  </NamespaceUris>
  <Aliases>
    <Alias Alias="HasSubtype">i=45</Alias>
    <Alias Alias="HasEncoding">i=38</Alias>
    <Alias Alias="HasTypeDefinition">i=40</Alias>
    <Alias Alias="Int32">i=6</Alias>
  </Aliases>
  <UADataType NodeId="ns=1;i=10" BrowseName="1:MyStruct">
    <DisplayName>MyStruct</DisplayName>
    <References>
      <Reference ReferenceType="HasSubtype" IsForward="false">i=22</Reference>
      <Reference ReferenceType="HasEncoding">ns=1;i=11</Reference>
    </References>
    <Definition Name="1:MyStruct">
      <Field Name="Field1" DataType="Int32" ValueRank="-1" />
    </Definition>
  </UADataType>
  <!-- BrowseName is "Default XML", not "Default Binary" → must NOT be detected -->
  <UAObject NodeId="ns=1;i=11" BrowseName="Default XML">
    <DisplayName>Default XML</DisplayName>
    <References>
      <Reference ReferenceType="HasTypeDefinition">i=76</Reference>
    </References>
  </UAObject>
</UANodeSet>"#;

    /// Enum DataType (fields carry a non-negative Value attribute).
    /// Expected: DataTypeDefinition::Enum with three named fields.
    const TEST_ENUM_DATATYPE: &str = r#"
<UANodeSet xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
           xmlns:xsd="http://www.w3.org/2001/XMLSchema"
           LastModified="2023-12-15T00:00:00Z"
           xmlns="http://opcfoundation.org/UA/2011/03/UANodeSet.xsd">
  <NamespaceUris>
    <Uri>http://test.com</Uri>
  </NamespaceUris>
  <Aliases>
    <Alias Alias="HasSubtype">i=45</Alias>
  </Aliases>
  <UADataType NodeId="ns=1;i=20" BrowseName="1:MyEnum">
    <DisplayName>MyEnum</DisplayName>
    <References>
      <Reference ReferenceType="HasSubtype" IsForward="false">i=29</Reference>
    </References>
    <Definition Name="1:MyEnum">
      <Field Name="None" Value="0">
        <DisplayName>
          <Text>None</Text>
        </DisplayName>
      </Field>
      <Field Name="Active" Value="1">
        <DisplayName>
          <Text>Active</Text>
        </DisplayName>
      </Field>
      <Field Name="Error" Value="2">
        <DisplayName>
          <Text>Error</Text>
        </DisplayName>
      </Field>
    </Definition>
  </UADataType>
</UANodeSet>"#;

    /// Struct DataType where one field carries IsOptional="true".
    /// Expected: StructureType::StructureWithOptionalFields
    const TEST_STRUCT_WITH_OPTIONAL_FIELDS: &str = r#"
<UANodeSet xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
           xmlns:xsd="http://www.w3.org/2001/XMLSchema"
           LastModified="2023-12-15T00:00:00Z"
           xmlns="http://opcfoundation.org/UA/2011/03/UANodeSet.xsd">
  <NamespaceUris>
    <Uri>http://test.com</Uri>
  </NamespaceUris>
  <Aliases>
    <Alias Alias="HasSubtype">i=45</Alias>
    <Alias Alias="Int32">i=6</Alias>
  </Aliases>
  <UADataType NodeId="ns=1;i=30" BrowseName="1:MyOptionalStruct">
    <DisplayName>MyOptionalStruct</DisplayName>
    <References>
      <Reference ReferenceType="HasSubtype" IsForward="false">i=22</Reference>
    </References>
    <Definition Name="1:MyOptionalStruct">
      <Field Name="Required" DataType="Int32" ValueRank="-1" />
      <Field Name="Optional" DataType="Int32" ValueRank="-1" IsOptional="true" />
    </Definition>
  </UADataType>
</UANodeSet>"#;

    /// Union DataType (Definition carries IsUnion="true").
    /// Expected: StructureType::Union
    const TEST_UNION_DATATYPE: &str = r#"
<UANodeSet xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
           xmlns:xsd="http://www.w3.org/2001/XMLSchema"
           LastModified="2023-12-15T00:00:00Z"
           xmlns="http://opcfoundation.org/UA/2011/03/UANodeSet.xsd">
  <NamespaceUris>
    <Uri>http://test.com</Uri>
  </NamespaceUris>
  <Aliases>
    <Alias Alias="HasSubtype">i=45</Alias>
    <Alias Alias="Int32">i=6</Alias>
    <Alias Alias="Boolean">i=1</Alias>
  </Aliases>
  <UADataType NodeId="ns=1;i=40" BrowseName="1:MyUnion">
    <DisplayName>MyUnion</DisplayName>
    <References>
      <Reference ReferenceType="HasSubtype" IsForward="false">i=22</Reference>
    </References>
    <Definition Name="1:MyUnion" IsUnion="true">
      <Field Name="IntOption"  DataType="Int32"   ValueRank="-1" />
      <Field Name="BoolOption" DataType="Boolean" ValueRank="-1" />
    </Definition>
  </UADataType>
</UANodeSet>"#;

    /// DataType with no Definition element (abstract / opaque type).
    /// Expected: the node loads successfully; definition() is None.
    const TEST_DATATYPE_NO_DEFINITION: &str = r#"
<UANodeSet xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
           xmlns:xsd="http://www.w3.org/2001/XMLSchema"
           LastModified="2023-12-15T00:00:00Z"
           xmlns="http://opcfoundation.org/UA/2011/03/UANodeSet.xsd">
  <NamespaceUris>
    <Uri>http://test.com</Uri>
  </NamespaceUris>
  <Aliases>
    <Alias Alias="HasSubtype">i=45</Alias>
  </Aliases>
  <UADataType NodeId="ns=1;i=50" BrowseName="1:OpaqueType" IsAbstract="true">
    <DisplayName>OpaqueType</DisplayName>
    <References>
      <Reference ReferenceType="HasSubtype" IsForward="false">i=22</Reference>
    </References>
  </UADataType>
</UANodeSet>"#;

    fn load_single_datatype(nodeset_xml: &str) -> crate::DataType {
        let import = NodeSet2Import::new_str("en", nodeset_xml, vec![]).unwrap();
        let mut ns = NamespaceMap::new();
        let mut map = NodeSetNamespaceMapper::new(&mut ns);
        import.register_namespaces(&mut map);
        let nodes: Vec<_> = import.load(&map).collect();

        let dt_item = nodes
            .into_iter()
            .find(|n| matches!(&n.node, NodeType::DataType(_)))
            .expect("Expected at least one DataType node");

        match dt_item.node {
            NodeType::DataType(dt) => *dt,
            _ => unreachable!(),
        }
    }

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

    /// Verifies that when a DataType has an inward HasSubtype reference and a
    /// forward HasEncoding reference pointing to a "Default Binary" object,
    /// both base_data_type and default_encoding_id are populated correctly in
    /// the resulting StructureDefinition.
    #[test]
    fn test_struct_base_type_and_binary_encoding_are_set() {
        let dt = load_single_datatype(TEST_STRUCT_WITH_BASE_AND_BINARY_ENCODING);

        let definition = dt.data_type_definition();
        let def = definition.as_ref().expect("Expected a DataTypeDefinition");

        let DataTypeDefinition::Structure(struct_def) = def else {
            panic!("Expected StructureDefinition, got {:?}", def);
        };

        // base_data_type must be i=22 (OPC UA "Structure")
        assert_eq!(
            struct_def.base_data_type,
            NodeId::new(0, 22u32),
            "base_data_type should be i=22 (Structure)"
        );

        // default_encoding_id must be the resolved ID of the "Default Binary" object
        assert_eq!(
            struct_def.default_encoding_id,
            NodeId::new(1, 11u32),
            "default_encoding_id should be ns=1;i=11"
        );

        assert_eq!(struct_def.structure_type, StructureType::Structure);
        assert_eq!(struct_def.fields.as_ref().unwrap().len(), 2);
    }

    /// Verifies that when a DataType has a HasSubtype reference but no
    /// HasEncoding reference, default_encoding_id remains a null NodeId.
    #[test]
    fn test_struct_default_encoding_null_when_no_encoding_reference() {
        let dt = load_single_datatype(TEST_STRUCT_WITH_BASE_NO_ENCODING);

        let DataTypeDefinition::Structure(struct_def) = dt
            .data_type_definition()
            .as_ref()
            .expect("Expected a DataTypeDefinition")
        else {
            panic!("Expected StructureDefinition");
        };

        assert_eq!(
            struct_def.base_data_type,
            NodeId::new(0, 22u32),
            "base_data_type should still be i=22"
        );
        assert!(
            struct_def.default_encoding_id.is_null(),
            "default_encoding_id should be null when no encoding reference is present"
        );
    }

    /// Verifies that an encoding Object whose BrowseName is NOT "Default Binary"
    /// (e.g. "Default XML") is NOT added to binary_encoding_types and therefore
    /// default_encoding_id stays null even though a HasEncoding reference exists.
    #[test]
    fn test_struct_default_encoding_null_when_encoding_object_is_not_default_binary() {
        let dt = load_single_datatype(TEST_STRUCT_WITH_NON_BINARY_ENCODING_OBJECT);

        let DataTypeDefinition::Structure(struct_def) = dt
            .data_type_definition()
            .as_ref()
            .expect("Expected a DataTypeDefinition")
        else {
            panic!("Expected StructureDefinition");
        };

        assert!(
            struct_def.default_encoding_id.is_null(),
            "default_encoding_id must be null for non-binary encoding objects"
        );
    }

    /// Verifies that a DataType whose Definition fields carry non-negative
    /// Value attributes is interpreted as an enum and produces an EnumDefinition
    /// with the correct number of fields and their names.
    #[test]
    fn test_enum_datatype_produces_enum_definition() {
        let dt = load_single_datatype(TEST_ENUM_DATATYPE);

        let definition = dt.data_type_definition();
        let def = definition.as_ref().expect("Expected a DataTypeDefinition");

        let DataTypeDefinition::Enum(enum_def) = def else {
            panic!("Expected EnumDefinition, got {:?}", def);
        };

        let fields = enum_def.fields.as_ref().expect("Enum should have fields");
        assert_eq!(fields.len(), 3, "Enum should have 3 fields");

        assert_eq!(fields[0].name.as_ref(), "None");
        assert_eq!(fields[0].value, 0);

        assert_eq!(fields[1].name.as_ref(), "Active");
        assert_eq!(fields[1].value, 1);

        assert_eq!(fields[2].name.as_ref(), "Error");
        assert_eq!(fields[2].value, 2);
    }

    /// Verifies that a Definition with at least one IsOptional="true" field
    /// results in StructureType::StructureWithOptionalFields.
    #[test]
    fn test_struct_with_optional_fields_has_correct_structure_type() {
        let dt = load_single_datatype(TEST_STRUCT_WITH_OPTIONAL_FIELDS);

        let DataTypeDefinition::Structure(struct_def) = dt
            .data_type_definition()
            .as_ref()
            .expect("Expected a DataTypeDefinition")
        else {
            panic!("Expected StructureDefinition");
        };

        assert_eq!(
            struct_def.structure_type,
            StructureType::StructureWithOptionalFields,
            "A definition with an optional field must produce StructureWithOptionalFields"
        );

        let fields = struct_def.fields.as_ref().unwrap();
        assert_eq!(fields.len(), 2);
        assert!(!fields[0].is_optional, "Field1 should not be optional");
        assert!(fields[1].is_optional, "Field2 should be optional");
    }

    /// Verifies that a Definition with IsUnion="true" results in StructureType::Union.
    #[test]
    fn test_union_datatype_has_union_structure_type() {
        let dt = load_single_datatype(TEST_UNION_DATATYPE);

        let DataTypeDefinition::Structure(struct_def) = dt
            .data_type_definition()
            .as_ref()
            .expect("Expected a DataTypeDefinition")
        else {
            panic!("Expected StructureDefinition");
        };

        assert_eq!(
            struct_def.structure_type,
            StructureType::Union,
            "IsUnion=true must produce StructureType::Union"
        );
        assert_eq!(struct_def.fields.as_ref().unwrap().len(), 2);
    }

    /// Verifies that a DataType with no Definition element (abstract/opaque type)
    /// loads successfully and has no DataTypeDefinition.
    #[test]
    fn test_datatype_without_definition_loads_successfully() {
        let dt = load_single_datatype(TEST_DATATYPE_NO_DEFINITION);

        assert!(
            dt.data_type_definition().is_none(),
            "DataType without a Definition element must have no DataTypeDefinition"
        );
        assert!(dt.is_abstract(), "Node was declared IsAbstract=true");
    }

    /// Smoke-test: the "Default Binary" object is still loaded as an Object node
    /// even though it also feeds the binary_encoding_types set.
    #[test]
    fn test_binary_encoding_object_is_still_loaded_as_node() {
        let import =
            NodeSet2Import::new_str("en", TEST_STRUCT_WITH_BASE_AND_BINARY_ENCODING, vec![])
                .unwrap();
        let mut ns = NamespaceMap::new();
        let mut map = NodeSetNamespaceMapper::new(&mut ns);
        import.register_namespaces(&mut map);
        let nodes: Vec<_> = import.load(&map).collect();

        // Expect both the DataType node and the "Default Binary" Object node
        assert_eq!(
            nodes.len(),
            2,
            "Both the DataType and the encoding Object must be loaded"
        );

        let has_encoding_obj = nodes.iter().any(|n| {
            if let NodeType::Object(o) = &n.node {
                o.browse_name() == &QualifiedName::new(0, "Default Binary")
            } else {
                false
            }
        });
        assert!(
            has_encoding_obj,
            "The 'Default Binary' object should appear in the loaded nodes"
        );
    }

    /// Two-level struct inheritance:
    ///   MyChildStruct (ns=1;i=101) → MyBaseStruct (ns=1;i=100) → Structure (i=22)
    ///
    /// Expected: MyChildStruct's resolved fields are
    ///   [BaseField1, BaseField2, ChildField1] (base fields first, child field appended).
    const TEST_STRUCT_INHERITANCE: &str = r#"
<UANodeSet xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
           xmlns:xsd="http://www.w3.org/2001/XMLSchema"
           LastModified="2023-12-15T00:00:00Z"
           xmlns="http://opcfoundation.org/UA/2011/03/UANodeSet.xsd">
  <NamespaceUris>
    <Uri>http://test.com</Uri>
  </NamespaceUris>
  <Aliases>
    <Alias Alias="HasSubtype">i=45</Alias>
    <Alias Alias="Int32">i=6</Alias>
    <Alias Alias="Boolean">i=1</Alias>
  </Aliases>
  <!-- Base struct: extends OPC UA Structure (i=22) -->
  <UADataType NodeId="ns=1;i=100" BrowseName="1:MyBaseStruct">
    <DisplayName>MyBaseStruct</DisplayName>
    <References>
      <Reference ReferenceType="HasSubtype" IsForward="false">i=22</Reference>
    </References>
    <Definition Name="1:MyBaseStruct">
      <Field Name="BaseField1" DataType="Int32"    ValueRank="-1" />
      <Field Name="BaseField2" DataType="Boolean"  ValueRank="-1" />
    </Definition>
  </UADataType>
  <!-- Child struct: extends MyBaseStruct -->
  <UADataType NodeId="ns=1;i=101" BrowseName="1:MyChildStruct">
    <DisplayName>MyChildStruct</DisplayName>
    <References>
      <Reference ReferenceType="HasSubtype" IsForward="false">ns=1;i=100</Reference>
    </References>
    <Definition Name="1:MyChildStruct">
      <Field Name="ChildField1" DataType="Int32" ValueRank="-1" />
    </Definition>
  </UADataType>
</UANodeSet>"#;

    /// Verifies that `collect_structure_fields` walks the full inheritance chain so
    /// that a child struct's resolved field list begins with all ancestor fields
    /// followed by its own fields.
    #[test]
    fn test_recursive_field_collection_inherits_base_fields() {
        let import = NodeSet2Import::new_str("en", TEST_STRUCT_INHERITANCE, vec![]).unwrap();
        let mut ns = NamespaceMap::new();
        let mut map = NodeSetNamespaceMapper::new(&mut ns);
        import.register_namespaces(&mut map);
        let nodes: Vec<_> = import.load(&map).collect();

        // Locate MyChildStruct by browse name
        let child_item = nodes
            .into_iter()
            .find(|n| {
                if let NodeType::DataType(dt) = &n.node {
                    dt.browse_name() == &QualifiedName::new(1, "MyChildStruct")
                } else {
                    false
                }
            })
            .expect("MyChildStruct not found in loaded nodes");

        let child = match child_item.node {
            NodeType::DataType(dt) => *dt,
            _ => unreachable!(),
        };

        let DataTypeDefinition::Structure(struct_def) = child
            .data_type_definition()
            .as_ref()
            .expect("Expected a DataTypeDefinition")
        else {
            panic!("Expected StructureDefinition");
        };

        let fields = struct_def.fields.as_ref().unwrap();
        // Two fields inherited from MyBaseStruct, one own field
        assert_eq!(
            fields.len(),
            3,
            "Child struct should have 3 fields (2 inherited + 1 own)"
        );
        // Base fields must come first, in declaration order
        assert_eq!(fields[0].name.as_ref(), "BaseField1");
        assert_eq!(fields[1].name.as_ref(), "BaseField2");
        // Own field appended last
        assert_eq!(fields[2].name.as_ref(), "ChildField1");
    }

    #[test]
    fn test_abstract_base_struct_fields_are_inherited_in_order() {
        let import =
            NodeSet2Import::new_str("en", TEST_ABSTRACT_BASE_STRUCT_INHERITANCE, vec![]).unwrap();
        let mut ns = NamespaceMap::new();
        let mut map = NodeSetNamespaceMapper::new(&mut ns);
        import.register_namespaces(&mut map);
        let nodes: Vec<_> = import.load(&map).collect();

        let derived_item = nodes
            .into_iter()
            .find(|n| {
                if let NodeType::DataType(dt) = &n.node {
                    dt.browse_name() == &QualifiedName::new(1, "DerivedStruct")
                } else {
                    false
                }
            })
            .expect("DerivedStruct not found in loaded nodes");

        let derived = match derived_item.node {
            NodeType::DataType(dt) => *dt,
            _ => unreachable!(),
        };

        let DataTypeDefinition::Structure(struct_def) = derived
            .data_type_definition()
            .as_ref()
            .expect("Expected a DataTypeDefinition")
        else {
            panic!("Expected StructureDefinition");
        };

        let fields = struct_def.fields.as_ref().unwrap();
        assert_eq!(
            fields.len(),
            3,
            "Derived struct should contain 3 fields (1 inherited + 2 own)"
        );
        assert_eq!(fields[0].name.as_ref(), "BaseField");
        assert_eq!(fields[1].name.as_ref(), "DerivedField1");
        assert_eq!(fields[2].name.as_ref(), "DerivedField2");
    }
}
