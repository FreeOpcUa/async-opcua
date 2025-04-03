//! Contains the [DataTypeTreeBuilder], a utility for
//! constructing a [DataTypeTree] that can be used to support custom types on the
//! server with [DynamicTypeLoader](opcua_types::custom::DynamicTypeLoader).

use std::collections::{HashMap, HashSet};

use futures::TryStreamExt;
use opcua_types::{
    custom::{DataTypeTree, DataTypeVariant, EncodingIds, ParentIds, TypeInfo},
    match_extension_object_owned, AttributeId, BrowseDescription, BrowseDirection,
    BrowseResultMaskFlags, DataTypeDefinition, EnumDefinition, Error, NodeClass, NodeClassMask,
    NodeId, ObjectId, ReadValueId, ReferenceTypeId, StatusCode, StructureDefinition,
    TimestampsToReturn, Variant,
};
use tokio_util::sync::CancellationToken;
use tracing::warn;

use crate::{
    browser::{BrowseFilter, BrowserConfig, NoneBrowserPolicy},
    Session,
};

/// Utility for constructing a [DataTypeTree] instance by
/// browsing the server type hierarchy.
///
/// # Example
///
/// ```ignore
/// // Set a filter restrict which nodes to include in the
/// // data type tree.
/// use std::sync::Arc;
/// use opcua::types::custom::DynamicTypeLoader;
/// use opcua::client::custom_types::DataTypeTreeBuilder;
/// // Note that this must include any data type that your custom types depend on,
/// // including built-in types.
/// let type_tree = DataTypeTreeBuilder::new(|node_id| node_id.namespace <= 2)
///     .build(&session)
///     .await?;
/// session.add_type_loader(Arc::new(DynamicTypeLoader::new(Arc::new(type_tree))));
///
/// // You will also need to load the namespace map.
/// ```
pub struct DataTypeTreeBuilder<T> {
    filter: T,
    config: BrowserConfig,
    token: CancellationToken,
    values_per_read: usize,
}

#[derive(Default)]
struct RawTypeData {
    type_definition: Option<DataTypeDefinition>,
    is_abstract: bool,
    encoding_ids: Option<EncodingIds>,
    name: String,
}

impl<T: FnMut(&NodeId) -> bool> DataTypeTreeBuilder<T> {
    /// Create a new data type tree builder with the given filter method.
    pub fn new(filter: T) -> Self {
        Self {
            filter,
            config: BrowserConfig::default(),
            token: CancellationToken::new(),
            values_per_read: 1000,
        }
    }

    /// Set a new cancellation token for the internal browser.
    pub fn token(mut self, token: CancellationToken) -> Self {
        self.token = token;
        self
    }

    /// Set the configuration for the internal browser.
    pub fn config(mut self, config: BrowserConfig) -> Self {
        self.config = config;
        self
    }

    /// Set the maximum number of values per Read request.
    pub fn values_per_read(mut self, values_per_read: usize) -> Self {
        self.values_per_read = values_per_read;
        self
    }

    fn check_cancelled(&self) -> Result<(), Error> {
        if self.token.is_cancelled() {
            Err(Error::new(
                StatusCode::BadRequestCancelledByClient,
                "Operation was cancelled",
            ))
        } else {
            Ok(())
        }
    }

    async fn browse_type_tree(
        &mut self,
        session: &Session,
        parent_ids: &mut ParentIds,
        structures: &mut HashSet<NodeId>,
        enums: &mut HashSet<NodeId>,
    ) -> Result<(), Error> {
        let policy = BrowseFilter::new_hierarchical()
            .node_class_mask(NodeClassMask::DATA_TYPE | NodeClassMask::VARIABLE)
            .result_mask(
                BrowseResultMaskFlags::IsForward
                    | BrowseResultMaskFlags::ReferenceTypeId
                    | BrowseResultMaskFlags::NodeClass
                    | BrowseResultMaskFlags::DisplayName,
            );
        let initial = policy.new_description_from_node(ObjectId::DataTypesFolder.into());

        let stream = session
            .browser()
            .config(self.config.clone())
            .token(self.token.clone())
            .handler(policy)
            .run(vec![initial]);

        futures::pin_mut!(stream);

        while let Some(rf) = stream.try_next().await? {
            let (parent, refs) = rf.into_results();
            for rf in refs {
                if rf.node_id.server_index != 0 {
                    continue;
                }

                if rf.reference_type_id == ReferenceTypeId::HasSubtype
                    && rf.node_class == NodeClass::DataType
                    && rf.node_id.server_index == 0
                {
                    parent_ids.add_type(rf.node_id.node_id.clone(), parent.clone());
                }

                if rf.node_class == NodeClass::DataType && (self.filter)(&rf.node_id.node_id) {
                    let variant = parent_ids.get_data_type_variant(&rf.node_id.node_id);

                    match variant {
                        Some(DataTypeVariant::Structure) => {
                            structures.insert(rf.node_id.node_id);
                        }
                        Some(DataTypeVariant::Enumeration) => {
                            enums.insert(rf.node_id.node_id);
                        }
                        _ => (),
                    }
                }
            }
        }

        self.check_cancelled()
    }

    async fn read_type_values(
        &self,
        session: &Session,
        structures: &HashSet<NodeId>,
        enums: &HashSet<NodeId>,
        type_data: &mut HashMap<NodeId, RawTypeData>,
    ) -> Result<(), Error> {
        let read_value_ids: Vec<_> = structures
            .iter()
            .chain(enums.iter())
            .flat_map(|s| {
                [
                    ReadValueId::new(s.clone(), AttributeId::IsAbstract),
                    ReadValueId::new(s.clone(), AttributeId::DataTypeDefinition),
                ]
            })
            .collect();

        for chunk in read_value_ids.chunks(self.values_per_read) {
            self.check_cancelled()?;

            let r = session
                .read(chunk, TimestampsToReturn::Neither, 0.0)
                .await
                .map_err(|e| Error::new(e, "Failed to read type definitions"))?;

            for (val, id) in r.into_iter().zip(chunk.iter()) {
                let entry = type_data.entry(id.node_id.clone()).or_default();
                if id.attribute_id == AttributeId::IsAbstract as u32 {
                    entry.is_abstract = val
                        .value
                        .and_then(|v| v.try_cast_to::<bool>().ok())
                        .unwrap_or_default();
                } else if let Some(Variant::ExtensionObject(o)) = val.value {
                    entry.type_definition = match_extension_object_owned!(o,
                        v: EnumDefinition => Some(DataTypeDefinition::Enum(v)),
                        v: StructureDefinition => Some(DataTypeDefinition::Structure(v)),
                        _ => {
                            warn!("Unknown value for data type definition of node {}: {}", id.node_id, o.type_name().unwrap_or(""));
                            None
                        },
                    );
                }
            }
        }

        self.check_cancelled()
    }

    async fn get_encoding_ids(
        &self,
        session: &Session,
        structures: HashSet<NodeId>,
        type_data: &mut HashMap<NodeId, RawTypeData>,
    ) -> Result<(), Error> {
        if structures.is_empty() {
            return Ok(());
        }

        let browse_for_encoding = structures
            .into_iter()
            .map(|s| BrowseDescription {
                node_id: s,
                node_class_mask: NodeClassMask::OBJECT.bits(),
                browse_direction: BrowseDirection::Forward,
                reference_type_id: ReferenceTypeId::HasEncoding.into(),
                include_subtypes: false,
                result_mask: BrowseResultMaskFlags::BrowseName.bits(),
            })
            .collect::<Vec<_>>();

        let stream = session
            .browser()
            .config(self.config.clone())
            .token(self.token.clone())
            .handler(NoneBrowserPolicy)
            .run(browse_for_encoding);

        futures::pin_mut!(stream);

        while let Some(r) = stream.try_next().await? {
            let (typ, refs) = r.into_results();

            let Some(info) = type_data.get_mut(&typ) else {
                continue;
            };

            let encoding_ids = info.encoding_ids.get_or_insert_default();

            for rf in refs {
                match rf.browse_name.name.as_ref() {
                    "Default Binary" => encoding_ids.binary_id = rf.node_id.node_id,
                    "Default XML" => encoding_ids.xml_id = rf.node_id.node_id,
                    "Default JSON" => encoding_ids.json_id = rf.node_id.node_id,
                    _ => (),
                }
            }
        }
        self.check_cancelled()
    }

    /// Read from the server and build a data type tree from the results.
    pub async fn build(mut self, session: &Session) -> Result<DataTypeTree, Error> {
        let mut parent_ids = ParentIds::new();
        let mut structures = HashSet::new();
        let mut enums = HashSet::new();

        // Start by browsing the data type hierarchy.
        self.browse_type_tree(session, &mut parent_ids, &mut structures, &mut enums)
            .await?;

        let mut type_data = HashMap::<NodeId, RawTypeData>::new();

        // Read IsAbstract and DataTypeDefinition for all enums and structs
        // we found on the server.
        self.read_type_values(session, &structures, &enums, &mut type_data)
            .await?;

        // Fetch the encoding IDs of any structures we found.
        self.get_encoding_ids(session, structures, &mut type_data)
            .await?;

        // Finally, use the collected information to build a type tree.
        let mut type_tree = DataTypeTree::new(parent_ids);

        for (id, type_data) in type_data.into_iter() {
            if let Some(def) = type_data.type_definition {
                let info = match TypeInfo::from_type_definition(
                    def,
                    type_data.name,
                    type_data.encoding_ids,
                    type_data.is_abstract,
                    &id,
                    type_tree.parent_ids(),
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        warn!("Failed to build type info from type definition for {id}: {e}");
                        continue;
                    }
                };
                type_tree.add_type(id, info);
            }
        }

        Ok(type_tree)
    }
}
