//! Definition of types representing OPC UA NodeSet2 files.

use chrono::{DateTime, Utc};
use roxmltree::{Document, Node};

use crate::{
    ext::{
        children_with_name, first_child_with_name_opt, value_from_attr, value_from_attr_opt,
        value_from_contents, NodeExt,
    },
    FromValue, XmlError, XmlLoad,
};

use super::opc_ua_types::Variant;

#[derive(Debug)]
/// Struct representing a NodeSet2.xml file.
///
/// NodeSet files are used as a portable format for OPC-UA node hierarchies.
pub struct NodeSet2 {
    /// Full node set.
    pub node_set: Option<UANodeSet>,
    /// Partial node set diff.
    pub node_set_changes: Option<UANodeSetChanges>,
    /// Status of node set changes.
    pub node_set_changes_status: Option<UANodeSetChangesStatus>,
}

/// Load a NodeSet2 file from an XML file. `document` is the content of a NodeSet2.xml file.
pub fn load_nodeset2_file(document: &str) -> Result<NodeSet2, XmlError> {
    let document = Document::parse(document).map_err(|e| XmlError {
        span: 0..1,
        error: crate::error::XmlErrorInner::Xml(e),
    })?;
    let root = document.root();
    Ok(NodeSet2 {
        node_set: first_child_with_name_opt(&root, "UANodeSet")?,
        node_set_changes: first_child_with_name_opt(&root, "UANodeSetChanges")?,
        node_set_changes_status: first_child_with_name_opt(&root, "UANodeSetChangesStatus")?,
    })
}

#[derive(Debug)]
/// A NodeSet2 node.
pub enum UANode {
    /// Object
    Object(UAObject),
    /// Variable, can have value.
    Variable(UAVariable),
    /// Method.
    Method(UAMethod),
    /// View
    View(UAView),
    /// Object type.
    ObjectType(UAObjectType),
    /// Variable type, can have value.
    VariableType(UAVariableType),
    /// Data type
    DataType(UADataType),
    /// Reference type.
    ReferenceType(UAReferenceType),
}

impl UANode {
    pub(crate) fn from_node(node: &Node<'_, '_>) -> Result<Option<Self>, XmlError> {
        Ok(Some(match node.tag_name().name() {
            "UAObject" => Self::Object(XmlLoad::load(node)?),
            "UAVariable" => Self::Variable(XmlLoad::load(node)?),
            "UAMethod" => Self::Method(XmlLoad::load(node)?),
            "UAView" => Self::View(XmlLoad::load(node)?),
            "UAObjectType" => Self::ObjectType(XmlLoad::load(node)?),
            "UAVariableType" => Self::VariableType(XmlLoad::load(node)?),
            "UADataType" => Self::DataType(XmlLoad::load(node)?),
            "UAReferenceType" => Self::ReferenceType(XmlLoad::load(node)?),
            _ => return Ok(None),
        }))
    }

    /// Get the base node, independent of node class.
    pub fn base(&self) -> &UANodeBase {
        match self {
            UANode::Object(n) => &n.base.base,
            UANode::Variable(n) => &n.base.base,
            UANode::Method(n) => &n.base.base,
            UANode::View(n) => &n.base.base,
            UANode::ObjectType(n) => &n.base.base,
            UANode::VariableType(n) => &n.base.base,
            UANode::DataType(n) => &n.base.base,
            UANode::ReferenceType(n) => &n.base.base,
        }
    }
}

#[derive(Debug, Default)]
/// A full OPC-UA node set.
pub struct UANodeSet {
    /// List of namespace URIs covered by this node set.
    pub namespace_uris: Option<UriTable>,
    /// List of server URIs used in this node set.
    pub server_uris: Option<UriTable>,
    /// List of referenced models.
    pub models: Option<ModelTable>,
    /// List of aliases available in this node set.
    pub aliases: Option<AliasTable>,
    /// The full list of nodes.
    pub nodes: Vec<UANode>,
    /// Last modified time.
    pub last_modified: Option<DateTime<Utc>>,
}

impl<'input> XmlLoad<'input> for UANodeSet {
    fn load(node: &Node<'_, 'input>) -> Result<Self, XmlError> {
        // Special case this one, we really want to avoid seeking through the entire
        // document for the optional elements. It's fine elsewhere since most nodes
        // have few children.
        let mut namespace_uris = None;
        let mut server_uris = None;
        let mut models = None;
        let mut aliases = None;
        let mut nodes = Vec::new();
        for child in node.children() {
            match child.tag_name().name() {
                "NamespaceUris" => namespace_uris = Some(XmlLoad::load(&child)?),
                "ServerUris" => server_uris = Some(XmlLoad::load(&child)?),
                "Models" => models = Some(XmlLoad::load(&child)?),
                "Aliases" => aliases = Some(XmlLoad::load(&child)?),
                _ => {
                    if let Some(node) = UANode::from_node(&child)? {
                        nodes.push(node);
                    }
                }
            }
        }

        Ok(Self {
            namespace_uris,
            server_uris,
            models,
            aliases,
            nodes,
            last_modified: value_from_attr_opt(node, "LastModified")?,
        })
    }
}

#[derive(Debug)]
/// Differential update of a node set.
pub struct UANodeSetChanges {
    /// List of namespace URIs in this node set.
    pub namespace_uris: Option<UriTable>,
    /// List of server URIs used in this node set.
    pub server_uris: Option<UriTable>,
    /// List of aliases available in this node set.
    pub aliases: Option<AliasTable>,
    /// New nodes.
    pub nodes_to_add: Option<NodesToAdd>,
    /// New references.
    pub references_to_add: Option<ReferencesToChange>,
    /// Nodes that should be deleted.
    pub nodes_to_delete: Option<NodesToDelete>,
    /// References that should be deleted.
    pub references_to_delete: Option<ReferencesToChange>,
    /// Last modified time.
    pub last_modified: Option<DateTime<Utc>>,
    /// Change transaction ID. Used to identify this change.
    pub transaction_id: String,
    /// If `true`, applications loading this should either accept all nodes in the change set,
    /// or fail completely, applying no changes at all.
    pub accept_all_or_nothing: bool,
}

impl<'input> XmlLoad<'input> for UANodeSetChanges {
    fn load(node: &Node<'_, 'input>) -> Result<Self, XmlError> {
        Ok(Self {
            namespace_uris: first_child_with_name_opt(node, "NamespaceUris")?,
            server_uris: first_child_with_name_opt(node, "ServerUris")?,
            aliases: first_child_with_name_opt(node, "Aliases")?,
            nodes_to_add: first_child_with_name_opt(node, "NodesToAdd")?,
            references_to_add: first_child_with_name_opt(node, "ReferencesToAdd")?,
            nodes_to_delete: first_child_with_name_opt(node, "NodesToDelete")?,
            references_to_delete: first_child_with_name_opt(node, "ReferencesToDelete")?,
            last_modified: value_from_attr_opt(node, "LastModified")?,
            transaction_id: value_from_attr(node, "TransactionId")?,
            accept_all_or_nothing: value_from_attr_opt(node, "AcceptAllOrNothing")?
                .unwrap_or(false),
        })
    }
}

#[derive(Debug)]
/// Status of a node set change.
pub struct UANodeSetChangesStatus {
    /// Status of nodes being added.
    pub nodes_to_add: Option<NodeSetStatusList>,
    /// Status of references being added.
    pub references_to_add: Option<NodeSetStatusList>,
    /// Status of nodes being deleted.
    pub nodes_to_delete: Option<NodeSetStatusList>,
    /// Status of references being deleted.
    pub references_to_delete: Option<NodeSetStatusList>,
    /// Last modified time.
    pub last_modified: Option<DateTime<Utc>>,
    /// Change transaction ID. Used to identify this change.
    pub transaction_id: String,
}

impl<'input> XmlLoad<'input> for UANodeSetChangesStatus {
    fn load(node: &Node<'_, 'input>) -> Result<Self, XmlError> {
        Ok(Self {
            nodes_to_add: first_child_with_name_opt(node, "NodesToAdd")?,
            references_to_add: first_child_with_name_opt(node, "ReferencesToAdd")?,
            nodes_to_delete: first_child_with_name_opt(node, "NodesToDelete")?,
            references_to_delete: first_child_with_name_opt(node, "ReferencesToDelete")?,
            last_modified: value_from_attr_opt(node, "LastModified")?,
            transaction_id: value_from_attr(node, "TransactionId")?,
        })
    }
}

#[derive(Debug)]
/// List of nodes to add.
pub struct NodesToAdd {
    /// Nodes to add.
    pub nodes: Vec<UANode>,
}

impl<'input> XmlLoad<'input> for NodesToAdd {
    fn load(node: &Node<'_, 'input>) -> Result<Self, XmlError> {
        Ok(Self {
            nodes: node
                .children()
                .filter_map(|n| UANode::from_node(&n).transpose())
                .collect::<Result<Vec<_>, _>>()?,
        })
    }
}

#[derive(Debug)]
/// Node that should be deleted.
pub struct NodeToDelete {
    /// Node ID of node being deleted.
    pub node_id: NodeId,
    /// Whether to delete references _to_ this node. References _from_ this node
    /// should always be deleted.
    pub delete_reverse_references: bool,
}

impl<'input> XmlLoad<'input> for NodeToDelete {
    fn load(node: &Node<'_, 'input>) -> Result<Self, XmlError> {
        Ok(Self {
            node_id: NodeId::load(node)?,
            delete_reverse_references: value_from_attr_opt(node, "DeleteReverseReferences")?
                .unwrap_or(true),
        })
    }
}

#[derive(Debug)]
/// List of nodes to delete.
pub struct NodesToDelete {
    /// Nodes to delete.
    pub nodes: Vec<NodeToDelete>,
}

impl<'input> XmlLoad<'input> for NodesToDelete {
    fn load(node: &Node<'_, 'input>) -> Result<Self, XmlError> {
        Ok(Self {
            nodes: children_with_name(node, "Node")?,
        })
    }
}

#[derive(Debug)]
/// Reference being created or deleted.
pub struct ReferenceChange {
    /// Target node ID.
    pub node_id: NodeId,
    /// Source node ID.
    pub source: NodeId,
    /// Reference type ID.
    pub reference_type: NodeId,
    /// Whether this is a forward or inverse reference.
    pub is_forward: bool,
}

impl<'input> XmlLoad<'input> for ReferenceChange {
    fn load(node: &Node<'_, 'input>) -> Result<Self, XmlError> {
        Ok(Self {
            node_id: NodeId::load(node)?,
            source: value_from_attr(node, "Source")?,
            reference_type: value_from_attr(node, "ReferenceType")?,
            is_forward: value_from_attr_opt(node, "IsForward")?.unwrap_or(true),
        })
    }
}

#[derive(Debug)]
/// List of references to add or remove.
pub struct ReferencesToChange {
    /// References to change.
    pub references: Vec<ReferenceChange>,
}

impl<'input> XmlLoad<'input> for ReferencesToChange {
    fn load(node: &Node<'_, 'input>) -> Result<Self, XmlError> {
        Ok(Self {
            references: children_with_name(node, "Reference")?,
        })
    }
}

#[derive(Debug)]
/// Status of a node set change element.
pub struct NodeSetStatus {
    /// Status symbol.
    pub status: String,
    /// Status code.
    pub code: u64,
}

impl<'input> XmlLoad<'input> for NodeSetStatus {
    fn load(node: &Node<'_, 'input>) -> Result<Self, XmlError> {
        Ok(Self {
            status: String::load(node)?,
            code: value_from_attr_opt(node, "Code")?.unwrap_or(0),
        })
    }
}

#[derive(Debug)]
/// List of statuses for a node set change.
pub struct NodeSetStatusList {
    /// Node set statuses.
    pub statuses: Vec<NodeSetStatus>,
}

impl<'input> XmlLoad<'input> for NodeSetStatusList {
    fn load(node: &Node<'_, 'input>) -> Result<Self, XmlError> {
        Ok(Self {
            statuses: children_with_name(node, "Status")?,
        })
    }
}

#[derive(Debug)]
/// List of URIs.
pub struct UriTable {
    /// URIs.
    pub uris: Vec<String>,
}

impl<'input> XmlLoad<'input> for UriTable {
    fn load(node: &Node<'_, 'input>) -> Result<Self, XmlError> {
        Ok(Self {
            uris: node
                .with_name("Uri")
                .map(|v| v.try_contents().map(|v| v.to_owned()))
                .collect::<Result<Vec<_>, _>>()?,
        })
    }
}

macro_rules! value_wrapper {
    ($key:ident, $doc:expr, $ty:ident) => {
        #[derive(Debug, Default, Clone)]
        #[doc = $doc]
        pub struct $key(pub $ty);

        impl FromValue for $key {
            fn from_value(node: &Node<'_, '_>, attr: &str, v: &str) -> Result<Self, XmlError> {
                Ok(Self($ty::from_value(node, attr, v)?))
            }
        }
    };
}

#[derive(Debug, Clone)]
/// Description of a model contained in a nodeset file.
pub struct ModelTableEntry {
    /// Role permissions that apply to this entry.
    pub role_permissions: Option<ListOfRolePermissions>,
    /// List of required models.
    pub required_model: Vec<ModelTableEntry>,
    /// Model URI.
    pub model_uri: String,
    /// Model version.
    pub version: Option<String>,
    /// Model publication date.
    pub publication_date: Option<DateTime<Utc>>,
    /// Default access restrictions for this model.
    pub access_restrictions: AccessRestriction,
}

impl<'input> XmlLoad<'input> for ModelTableEntry {
    fn load(node: &Node<'_, 'input>) -> Result<Self, XmlError> {
        Ok(Self {
            role_permissions: first_child_with_name_opt(node, "RolePermissions")?,
            required_model: children_with_name(node, "RequiredModel")?,
            model_uri: node.try_attribute("ModelUri")?.to_owned(),
            version: node.attribute("Version").map(|v| v.to_owned()),
            publication_date: value_from_attr_opt(node, "PublicationDate")?,
            access_restrictions: value_from_attr_opt(node, "AccessRestrictions")?
                .unwrap_or(AccessRestriction(0)),
        })
    }
}

#[derive(Debug, Clone)]
/// Table containing models defined in a nodeset file.
pub struct ModelTable {
    /// List of models.
    pub models: Vec<ModelTableEntry>,
}

impl<'input> XmlLoad<'input> for ModelTable {
    fn load(node: &Node<'_, 'input>) -> Result<Self, XmlError> {
        Ok(Self {
            models: children_with_name(node, "Model")?,
        })
    }
}

value_wrapper!(NodeId, "An OPC-UA node ID or alias", String);
value_wrapper!(
    QualifiedName,
    "An OPC-UA QualifiedName on the form Name:Index",
    String
);
value_wrapper!(Locale, "A text locale", String);
value_wrapper!(WriteMask, "A node write mask", u32);
value_wrapper!(EventNotifier, "Node event notifier", u8);
value_wrapper!(ValueRank, "Variable value rank", i32);
value_wrapper!(AccessRestriction, "Access restriction flags", u8);
value_wrapper!(
    ArrayDimensions,
    "Array dimensions as a comma separated list of lengths",
    String
);
value_wrapper!(
    Duration,
    "Duration as a floating point number of seconds",
    f64
);
value_wrapper!(AccessLevel, "Access level flags", u8);

impl FromValue for chrono::DateTime<Utc> {
    fn from_value(node: &Node<'_, '_>, attr: &str, v: &str) -> Result<Self, XmlError> {
        let v = chrono::DateTime::parse_from_rfc3339(v)
            .map_err(|e| XmlError::parse_date_time(node, attr, e))?;
        Ok(v.with_timezone(&Utc))
    }
}

#[derive(Debug)]
/// Entry in the alias table.
pub struct NodeIdAlias {
    /// Node ID.
    pub id: NodeId,
    /// Alias name.
    pub alias: String,
}

impl<'input> XmlLoad<'input> for NodeIdAlias {
    fn load(node: &Node<'_, 'input>) -> Result<Self, XmlError> {
        Ok(Self {
            id: NodeId::load(node)?,
            alias: node.try_attribute("Alias")?.to_owned(),
        })
    }
}

#[derive(Debug, Default)]
/// List of aliases used in a nodeset.
pub struct AliasTable {
    /// Alias list.
    pub aliases: Vec<NodeIdAlias>,
}

impl<'input> XmlLoad<'input> for AliasTable {
    fn load(node: &Node<'_, 'input>) -> Result<Self, XmlError> {
        Ok(Self {
            aliases: children_with_name(node, "Alias")?,
        })
    }
}

#[derive(Debug, Default, Clone)]
/// A localized text with a body and a locale.
pub struct LocalizedText {
    /// Localized text body.
    pub text: String,
    /// Localized text locale.
    pub locale: Locale,
}
impl<'input> XmlLoad<'input> for LocalizedText {
    fn load(node: &Node<'_, 'input>) -> Result<Self, XmlError> {
        Ok(Self {
            text: node.text().map(|v| v.to_owned()).unwrap_or_default(),
            locale: value_from_attr_opt(node, "Locale")?.unwrap_or_else(|| Locale("".to_owned())),
        })
    }
}

#[derive(Debug, Clone)]
/// Symbolic name.
pub struct SymbolicName {
    /// Name alternatives.
    pub names: Vec<String>,
}

impl FromValue for SymbolicName {
    fn from_value(_node: &Node<'_, '_>, _attr: &str, v: &str) -> Result<Self, XmlError> {
        Ok(Self {
            names: v.split_whitespace().map(|v| v.to_owned()).collect(),
        })
    }
}

#[derive(Debug)]
/// A reference defined inside a node.
pub struct Reference {
    /// Target node ID.
    pub node_id: NodeId,
    /// Reference type ID.
    pub reference_type: NodeId,
    /// Whether this is a forward or inverse reference.
    pub is_forward: bool,
}

impl<'input> XmlLoad<'input> for Reference {
    fn load(node: &Node<'_, 'input>) -> Result<Self, XmlError> {
        Ok(Self {
            node_id: value_from_contents(node)?,
            reference_type: value_from_attr(node, "ReferenceType")?,
            is_forward: value_from_attr_opt(node, "IsForward")?.unwrap_or(true),
        })
    }
}

#[derive(Debug)]
/// List of references in a node definition.
pub struct ListOfReferences {
    /// References.
    pub references: Vec<Reference>,
}
impl<'input> XmlLoad<'input> for ListOfReferences {
    fn load(node: &Node<'_, 'input>) -> Result<Self, XmlError> {
        Ok(Self {
            references: children_with_name(node, "Reference")?,
        })
    }
}

#[derive(Debug, Clone)]
/// Role permission for a node.
pub struct RolePermission {
    /// Role ID.
    pub node_id: NodeId,
    /// Permission flags.
    pub permissions: u64,
}

impl<'input> XmlLoad<'input> for RolePermission {
    fn load(node: &Node<'_, 'input>) -> Result<Self, XmlError> {
        Ok(Self {
            node_id: value_from_contents(node)?,
            permissions: value_from_attr_opt(node, "Permissions")?.unwrap_or(0),
        })
    }
}

#[derive(Debug, Clone)]
/// List of role permissions.
pub struct ListOfRolePermissions {
    /// Role permissions.
    pub role_permissions: Vec<RolePermission>,
}
impl<'input> XmlLoad<'input> for ListOfRolePermissions {
    fn load(node: &Node<'_, 'input>) -> Result<Self, XmlError> {
        Ok(Self {
            role_permissions: children_with_name(node, "RolePermission")?,
        })
    }
}

#[derive(Debug)]
/// Status of a node set.
pub enum ReleaseStatus {
    /// Node set has been released.
    Released,
    /// Node set is a draft.
    Draft,
    /// Node set has been deprecated.
    Deprecated,
}

impl FromValue for ReleaseStatus {
    fn from_value(node: &Node<'_, '_>, attr: &str, v: &str) -> Result<Self, XmlError> {
        match v {
            "Released" => Ok(Self::Released),
            "Draft" => Ok(Self::Draft),
            "Deprecated" => Ok(Self::Deprecated),
            r => Err(XmlError::other(
                node,
                &format!("Unexpected value for {attr}: {r}"),
            )),
        }
    }
}

#[derive(Debug)]
/// Common fields for nodeset nodes.
pub struct UANodeBase {
    /// Display name alternatives.
    pub display_names: Vec<LocalizedText>,
    /// Description alternatives.
    pub description: Vec<LocalizedText>,
    /// Category alternatives.
    pub category: Vec<String>,
    /// Documentation about this node.
    pub documentation: Option<String>,
    /// List of references.
    pub references: Option<ListOfReferences>,
    /// List of required role permissions.
    pub role_permissions: Option<ListOfRolePermissions>,
    /// Node ID of this node.
    pub node_id: NodeId,
    /// Browse name of this node.
    pub browse_name: QualifiedName,
    /// Default write mask.
    pub write_mask: WriteMask,
    /// Default user write mask.
    pub user_write_mask: WriteMask,
    /// Default access restrictions.
    pub access_restrictions: AccessRestriction,
    /// Symbolic name for this node.
    pub symbolic_name: Option<SymbolicName>,
    /// Release status of this node.
    pub release_status: ReleaseStatus,
}

impl<'input> XmlLoad<'input> for UANodeBase {
    fn load(node: &Node<'_, 'input>) -> Result<Self, XmlError> {
        Ok(Self {
            display_names: children_with_name(node, "DisplayName")?,
            description: children_with_name(node, "Description")?,
            category: children_with_name(node, "Category")?,
            documentation: first_child_with_name_opt(node, "Documentation")?,
            references: first_child_with_name_opt(node, "References")?,
            role_permissions: first_child_with_name_opt(node, "RolePermissions")?,
            node_id: value_from_attr(node, "NodeId")?,
            browse_name: value_from_attr(node, "BrowseName")?,
            write_mask: value_from_attr_opt(node, "WriteMask")?.unwrap_or(WriteMask(0)),
            user_write_mask: value_from_attr_opt(node, "UserWriteMask")?.unwrap_or(WriteMask(0)),
            access_restrictions: value_from_attr_opt(node, "AccessRestrictions")?
                .unwrap_or(AccessRestriction(0)),
            symbolic_name: value_from_attr_opt(node, "SymbolicName")?,
            release_status: value_from_attr_opt(node, "ReleaseStatus")?
                .unwrap_or(ReleaseStatus::Released),
        })
    }
}

#[derive(Debug)]
/// Base type for node instances.
pub struct UAInstance {
    /// Common fields.
    pub base: UANodeBase,
    /// Parent node ID, not required.
    pub parent_node_id: Option<NodeId>,
}

impl<'input> XmlLoad<'input> for UAInstance {
    fn load(node: &Node<'_, 'input>) -> Result<Self, XmlError> {
        Ok(Self {
            base: UANodeBase::load(node)?,
            parent_node_id: value_from_attr_opt(node, "ParentNodeId")?,
        })
    }
}

#[derive(Debug)]
/// OPC UA Object in a nodeset.
pub struct UAObject {
    /// Base data.
    pub base: UAInstance,
    /// Default node event notifier.
    pub event_notifier: EventNotifier,
}

impl<'input> XmlLoad<'input> for UAObject {
    fn load(node: &Node<'_, 'input>) -> Result<Self, XmlError> {
        Ok(Self {
            base: UAInstance::load(node)?,
            event_notifier: value_from_attr_opt(node, "EventNotifier")?.unwrap_or(EventNotifier(0)),
        })
    }
}

#[derive(Debug)]
/// Variable initial value.
pub struct Value(pub Variant);

impl<'input> XmlLoad<'input> for Value {
    fn load(node: &Node<'_, 'input>) -> Result<Self, XmlError> {
        Ok(Self(
            node.children()
                .find(|n| !n.tag_name().name().is_empty())
                .map(|n| Variant::load(&n))
                .transpose()?
                .ok_or_else(|| XmlError::other(node, "Empty value, expected variant"))?,
        ))
    }
}

#[derive(Debug)]
/// Variable defined in a nodeset.
pub struct UAVariable {
    /// Base data.
    pub base: UAInstance,
    /// Initial or default value.
    pub value: Option<Value>,
    /// Data type ID.
    pub data_type: NodeId,
    /// Node value rank.
    pub value_rank: ValueRank,
    /// Array dimensions.
    pub array_dimensions: ArrayDimensions,
    /// Default access level.
    pub access_level: AccessLevel,
    /// Default user access level.
    pub user_access_level: AccessLevel,
    /// Default minimum sampling interval.
    pub minimum_sampling_interval: Duration,
    /// Default value of "historizing", whether this node stores its history.
    pub historizing: bool,
}

impl<'input> XmlLoad<'input> for UAVariable {
    fn load(node: &Node<'_, 'input>) -> Result<Self, XmlError> {
        Ok(Self {
            base: UAInstance::load(node)?,
            value: first_child_with_name_opt(node, "Value")?,
            data_type: value_from_attr_opt(node, "DataType")?
                .unwrap_or_else(|| NodeId("i=24".to_owned())),
            value_rank: value_from_attr_opt(node, "ValueRank")?.unwrap_or(ValueRank(-1)),
            array_dimensions: value_from_attr_opt(node, "ArrayDimensions")?
                .unwrap_or_else(|| ArrayDimensions("".to_owned())),
            access_level: value_from_attr_opt(node, "AccessLevel")?.unwrap_or(AccessLevel(1)),
            user_access_level: value_from_attr_opt(node, "UserAccessLevel")?
                .unwrap_or(AccessLevel(1)),
            minimum_sampling_interval: value_from_attr_opt(node, "MinimumSamplingInterval")?
                .unwrap_or(Duration(0.0)),
            historizing: value_from_attr_opt(node, "Historizing")?.unwrap_or(false),
        })
    }
}

#[derive(Debug)]
/// Argument of a method in a node set file.
pub struct UAMethodArgument {
    /// Method argument name.
    pub name: Option<String>,
    /// List of possible descriptions (in different locales).
    pub descriptions: Vec<LocalizedText>,
}

impl<'input> XmlLoad<'input> for UAMethodArgument {
    fn load(node: &Node<'_, 'input>) -> Result<Self, XmlError> {
        Ok(Self {
            name: first_child_with_name_opt(node, "Name")?,
            descriptions: children_with_name(node, "Description")?,
        })
    }
}

#[derive(Debug)]
/// Method defined in a node set file.
pub struct UAMethod {
    /// Base data.
    pub base: UAInstance,
    /// List of method arguments.
    pub arguments: Vec<UAMethodArgument>,
    /// Whether this method is executable.
    pub executable: bool,
    /// Default value of user executable.
    pub user_executable: bool,
    /// ID of another node serving as the method declaration in the type hierarchy.
    pub method_declaration_id: Option<NodeId>,
}

impl<'input> XmlLoad<'input> for UAMethod {
    fn load(node: &Node<'_, 'input>) -> Result<Self, XmlError> {
        Ok(Self {
            base: UAInstance::load(node)?,
            arguments: children_with_name(node, "ArgumentDescription")?,
            executable: value_from_attr_opt(node, "Executable")?.unwrap_or(false),
            user_executable: value_from_attr_opt(node, "UserExecutable")?.unwrap_or(false),
            method_declaration_id: value_from_attr_opt(node, "MethodDeclarationId")?,
        })
    }
}

#[derive(Debug)]
/// Structure translation.
pub struct StructureTranslationType {
    /// Possible translations.
    pub text: Vec<LocalizedText>,
    /// Name of the translation field.
    pub name: String,
}

impl<'input> XmlLoad<'input> for StructureTranslationType {
    fn load(node: &Node<'_, 'input>) -> Result<Self, XmlError> {
        Ok(Self {
            text: children_with_name(node, "Text")?,
            name: value_from_attr(node, "Name")?,
        })
    }
}

#[derive(Debug)]
/// Translation variant.
pub enum TranslationType {
    /// Raw list of alternative translations.
    Text(Vec<LocalizedText>),
    /// Named list of translations.
    Field(Vec<StructureTranslationType>),
    /// No translation.
    None,
}

impl<'input> XmlLoad<'input> for TranslationType {
    fn load(node: &Node<'_, 'input>) -> Result<Self, XmlError> {
        let texts = children_with_name(node, "Text")?;
        if !texts.is_empty() {
            return Ok(Self::Text(texts));
        }
        let fields = children_with_name(node, "Field")?;
        if !fields.is_empty() {
            return Ok(Self::Field(fields));
        }
        Ok(Self::None)
    }
}

#[derive(Debug)]
/// View defined in a node set file.
pub struct UAView {
    /// Base data.
    pub base: UAInstance,
    /// Whether this view contains no loops.
    pub contains_no_loops: bool,
    /// Event notifier.
    pub event_notifier: EventNotifier,
}

impl<'input> XmlLoad<'input> for UAView {
    fn load(node: &Node<'_, 'input>) -> Result<Self, XmlError> {
        Ok(Self {
            base: UAInstance::load(node)?,
            contains_no_loops: value_from_attr_opt(node, "ContainsNoLoops")?.unwrap_or(false),
            event_notifier: value_from_attr(node, "EventNotifier")?,
        })
    }
}

#[derive(Debug)]
/// Base type for node set types.
pub struct UAType {
    /// Base data.
    pub base: UANodeBase,
    /// Whether this type is abstract, i.e. it cannot be used in the instance hierarchy.
    pub is_abstract: bool,
}

impl<'input> XmlLoad<'input> for UAType {
    fn load(node: &Node<'_, 'input>) -> Result<Self, XmlError> {
        Ok(Self {
            base: UANodeBase::load(node)?,
            is_abstract: value_from_attr_opt(node, "IsAbstract")?.unwrap_or(false),
        })
    }
}

#[derive(Debug)]
/// Object type defined in a node set file.
pub struct UAObjectType {
    /// Base data.
    pub base: UAType,
}

impl<'input> XmlLoad<'input> for UAObjectType {
    fn load(node: &Node<'_, 'input>) -> Result<Self, XmlError> {
        Ok(Self {
            base: UAType::load(node)?,
        })
    }
}

#[derive(Debug)]
/// Variable type defined in a node set file.
pub struct UAVariableType {
    /// Base data.
    pub base: UAType,
    /// Default value of instances of this type.
    pub value: Option<Value>,
    /// Data type, implementing types may use a subtype of this.
    pub data_type: NodeId,
    /// Value rank.
    pub value_rank: ValueRank,
    /// Array dimensions.
    pub array_dimensions: ArrayDimensions,
}

impl<'input> XmlLoad<'input> for UAVariableType {
    fn load(node: &Node<'_, 'input>) -> Result<Self, XmlError> {
        Ok(Self {
            base: UAType::load(node)?,
            value: first_child_with_name_opt(node, "Value")?,
            data_type: value_from_attr_opt(node, "DataType")?
                .unwrap_or_else(|| NodeId("i=24".to_owned())),
            value_rank: value_from_attr_opt(node, "ValueRank")?.unwrap_or(ValueRank(-1)),
            array_dimensions: value_from_attr_opt(node, "ArrayDimensions")?
                .unwrap_or_else(|| ArrayDimensions("".to_owned())),
        })
    }
}

#[derive(Debug)]
/// Purpose of a data type in a node set.
pub enum DataTypePurpose {
    /// Normal OPC-UA type.
    Normal,
    /// Only used as part of service calls, not intended to be in ExtensionObjects.
    ServicesOnly,
    /// Used for code generation.
    CodeGenerator,
}

impl FromValue for DataTypePurpose {
    fn from_value(node: &Node<'_, '_>, attr: &str, v: &str) -> Result<Self, XmlError> {
        match v {
            "Normal" => Ok(Self::Normal),
            "ServicesOnly" => Ok(Self::ServicesOnly),
            "CodeGenerator" => Ok(Self::CodeGenerator),
            r => Err(XmlError::other(
                node,
                &format!("Unexpected value for {attr}: {r}"),
            )),
        }
    }
}

#[derive(Debug, Clone)]
/// Field in a data type definition.
pub struct DataTypeField {
    /// Possible display name translations.
    pub display_names: Vec<LocalizedText>,
    /// Possible description translations.
    pub descriptions: Vec<LocalizedText>,
    /// Field name, required.
    pub name: String,
    /// Field symbolic name.
    pub symbolic_name: Option<SymbolicName>,
    /// Field data type, required.
    pub data_type: NodeId,
    /// Value rank, default -1.
    pub value_rank: ValueRank,
    /// Array dimensions.
    pub array_dimensions: ArrayDimensions,
    /// Max string length, can be 0 for no limit.
    pub max_string_length: u64,
    /// Value, only applies to enum fields.
    pub value: i64,
    /// Whether this is an optional structure field.
    pub is_optional: bool,
    /// Whether to allow sub types of the field.
    pub allow_sub_types: bool,
}

impl<'input> XmlLoad<'input> for DataTypeField {
    fn load(node: &Node<'_, 'input>) -> Result<Self, XmlError> {
        Ok(Self {
            display_names: children_with_name(node, "DisplayName")?,
            descriptions: children_with_name(node, "Description")?,
            name: value_from_attr(node, "Name")?,
            symbolic_name: value_from_attr_opt(node, "SymbolicName")?,
            data_type: value_from_attr_opt(node, "DataType")?
                .unwrap_or_else(|| NodeId("i=24".to_owned())),
            value_rank: value_from_attr_opt(node, "ValueRank")?.unwrap_or(ValueRank(-1)),
            array_dimensions: value_from_attr_opt(node, "ArrayDimensions")?
                .unwrap_or_else(|| ArrayDimensions("".to_owned())),
            max_string_length: value_from_attr_opt(node, "MaxStringLength")?.unwrap_or(0),
            value: value_from_attr_opt(node, "Value")?.unwrap_or(-1),
            is_optional: value_from_attr_opt(node, "IsOptional")?.unwrap_or(false),
            allow_sub_types: value_from_attr_opt(node, "AllowSubTypes")?.unwrap_or(false),
        })
    }
}

#[derive(Debug, Clone)]
/// Data type definition.
pub struct DataTypeDefinition {
    /// Fields in this data type.
    pub fields: Vec<DataTypeField>,
    /// Qualified name of this data type.
    pub name: QualifiedName,
    /// Symbolic name.
    pub symbolic_name: SymbolicName,
    /// Whether this defines a union.
    pub is_union: bool,
    /// Whether this defines an option set.
    pub is_option_set: bool,
}

impl<'input> XmlLoad<'input> for DataTypeDefinition {
    fn load(node: &Node<'_, 'input>) -> Result<Self, XmlError> {
        Ok(Self {
            fields: children_with_name(node, "Field")?,
            name: value_from_attr(node, "Name")?,
            symbolic_name: value_from_attr_opt(node, "SymbolicName")?
                .unwrap_or_else(|| SymbolicName { names: Vec::new() }),
            is_union: value_from_attr_opt(node, "IsUnion")?.unwrap_or(false),
            is_option_set: value_from_attr_opt(node, "IsOptionSet")?.unwrap_or(false),
        })
    }
}

#[derive(Debug)]
/// Data type defined in a node set file.
pub struct UADataType {
    /// Base data.
    pub base: UAType,
    /// Data type definition.
    pub definition: Option<DataTypeDefinition>,
    /// Purpose of this data type.
    pub purpose: DataTypePurpose,
}

impl<'input> XmlLoad<'input> for UADataType {
    fn load(node: &Node<'_, 'input>) -> Result<Self, XmlError> {
        Ok(Self {
            base: UAType::load(node)?,
            definition: first_child_with_name_opt(node, "Definition")?,
            purpose: value_from_attr_opt(node, "Purpose")?.unwrap_or(DataTypePurpose::Normal),
        })
    }
}

#[derive(Debug)]
/// Reference type defined in a ndoe set file.
pub struct UAReferenceType {
    /// Base data.
    pub base: UAType,
    /// Possible inverse name translations.
    pub inverse_names: Vec<LocalizedText>,
    /// Whether this uses the same name for forward and inverse references.
    pub symmetric: bool,
}

impl<'input> XmlLoad<'input> for UAReferenceType {
    fn load(node: &Node<'_, 'input>) -> Result<Self, XmlError> {
        Ok(Self {
            base: UAType::load(node)?,
            inverse_names: children_with_name(node, "InverseName")?,
            symmetric: value_from_attr_opt(node, "Symmetric")?.unwrap_or(false),
        })
    }
}
