//! Utils for working with opaque node IDs containing binary encoded data.

use opcua_types::{ByteString, Identifier, NodeId};
use serde::{de::DeserializeOwned, Serialize};

/// Convert some value that implements [Serialize] to a bytestring node ID, using
/// `postcard` binary encoding.
pub fn as_opaque_node_id<T: Serialize>(value: &T, namespace: u16) -> Option<NodeId> {
    let v = postcard::to_stdvec(&value).ok()?;
    Some(NodeId {
        namespace,
        identifier: Identifier::ByteString(ByteString { value: Some(v) }),
    })
}

/// Deserialize some node ID that was originally created using [as_opaque_node_id].
pub fn from_opaque_node_id<T: DeserializeOwned>(id: &NodeId) -> Option<T> {
    let v = match &id.identifier {
        Identifier::ByteString(b) => b.value.as_ref()?,
        _ => return None,
    };
    postcard::from_bytes(v).ok()
}
