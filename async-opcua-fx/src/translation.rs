//! NodeId translation helpers for OPC UA FX connection model data.

use crate::{NodeIdTranslationDataType, PortableNodeIdentifier};
use opcua_types::{NamespaceMap, NodeId, StatusCode};

/// Finds the portable node identifier for a placeholder [`NodeId`].
pub fn translate<'a>(
    table: &'a [NodeIdTranslationDataType],
    placeholder: &NodeId,
) -> Option<&'a PortableNodeIdentifier> {
    table
        .iter()
        .find(|entry| entry.node_placeholder == *placeholder)
        .map(|entry| &entry.portable_node)
}

/// Resolves a portable node identifier to a concrete local [`NodeId`].
///
/// # Errors
///
/// Returns [`StatusCode::BadNodeIdUnknown`] when a portable node namespace URI
/// is not present in `namespaces`, [`StatusCode::BadNotSupported`] for alias
/// and browse-path identifiers, and [`StatusCode::BadInvalidArgument`] for a
/// null portable node identifier.
pub fn resolve_portable_node(
    portable: &PortableNodeIdentifier,
    namespaces: &NamespaceMap,
) -> Result<NodeId, StatusCode> {
    match portable {
        PortableNodeIdentifier::Node(portable_node) => {
            let namespace_uri: &str = portable_node.namespace_uri.as_ref();
            if namespace_uri.is_empty() {
                return Ok(portable_node.identifier.clone());
            }

            let namespace = namespaces
                .get_index(namespace_uri)
                .ok_or(StatusCode::BadNodeIdUnknown)?;

            Ok(NodeId {
                namespace,
                identifier: portable_node.identifier.identifier.clone(),
            })
        }
        PortableNodeIdentifier::Alias(_) | PortableNodeIdentifier::IdentifierBrowsePath(_) => {
            // ponytail: alias-table and browse-path resolution require an
            // address-space-backed resolver, not only a NamespaceMap.
            Err(StatusCode::BadNotSupported)
        }
        PortableNodeIdentifier::Null => Err(StatusCode::BadInvalidArgument),
    }
}

/// Translates a placeholder [`NodeId`] and resolves it to a concrete local node.
pub fn translate_to_node_id(
    table: &[NodeIdTranslationDataType],
    placeholder: &NodeId,
    namespaces: &NamespaceMap,
) -> Option<NodeId> {
    translate(table, placeholder)
        .and_then(|portable| resolve_portable_node(portable, namespaces).ok())
}
