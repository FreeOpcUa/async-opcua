use std::hash::Hasher;

use hashbrown::Equivalent;

use crate::{
    DataTypeId, Identifier, MethodId, NodeId, ObjectId, ObjectTypeId, ReferenceTypeId, VariableId,
    VariableTypeId,
};

// Cheap comparisons intended for use when comparing node IDs to constants.
impl PartialEq<(u16, &str)> for NodeId {
    fn eq(&self, other: &(u16, &str)) -> bool {
        self.namespace == other.0
            && match &self.identifier {
                Identifier::String(s) => s.as_ref() == other.1,
                _ => false,
            }
    }
}

impl PartialEq<(u16, &[u8; 16])> for NodeId {
    fn eq(&self, other: &(u16, &[u8; 16])) -> bool {
        self.namespace == other.0
            && match &self.identifier {
                Identifier::Guid(s) => s.as_bytes() == other.1,
                _ => false,
            }
    }
}

impl PartialEq<(u16, &[u8])> for NodeId {
    fn eq(&self, other: &(u16, &[u8])) -> bool {
        self.namespace == other.0
            && match &self.identifier {
                Identifier::ByteString(s) => {
                    s.value.as_ref().is_some_and(|v| v.as_slice() == other.1)
                }
                _ => false,
            }
    }
}

impl PartialEq<(u16, u32)> for NodeId {
    fn eq(&self, other: &(u16, u32)) -> bool {
        self.namespace == other.0
            && match &self.identifier {
                Identifier::Numeric(s) => s == &other.1,
                _ => false,
            }
    }
}

impl PartialEq<ObjectId> for NodeId {
    fn eq(&self, other: &ObjectId) -> bool {
        *self == (0u16, *other as u32)
    }
}

impl PartialEq<ObjectTypeId> for NodeId {
    fn eq(&self, other: &ObjectTypeId) -> bool {
        *self == (0u16, *other as u32)
    }
}

impl PartialEq<ReferenceTypeId> for NodeId {
    fn eq(&self, other: &ReferenceTypeId) -> bool {
        *self == (0u16, *other as u32)
    }
}

impl PartialEq<VariableId> for NodeId {
    fn eq(&self, other: &VariableId) -> bool {
        *self == (0u16, *other as u32)
    }
}

impl PartialEq<VariableTypeId> for NodeId {
    fn eq(&self, other: &VariableTypeId) -> bool {
        *self == (0u16, *other as u32)
    }
}

impl PartialEq<DataTypeId> for NodeId {
    fn eq(&self, other: &DataTypeId) -> bool {
        *self == (0u16, *other as u32)
    }
}

/// Trait that indicates that a type can be used as a reference to an identifier.
/// Contains a special hash method that includes the descriminator for the identifier
/// variant, which means that it hashes to the same value as the equivalent identifier.
pub trait IdentifierRef: PartialEq<Identifier> {
    /// Hash the value as if it was in an identifier. This _must_ result
    /// in the same hash as the equivalent identifier.
    fn hash_as_identifier<H: Hasher>(&self, state: &mut H);
}

#[derive(Debug, Clone, PartialEq, Eq, Copy)]
/// Cheap reference to a node ID of a specific type.
pub struct NodeIdRef<T> {
    /// Namespace index of the node ID.
    pub namespace: u16,
    /// Identifier of the node ID.
    pub identifier: T,
}

impl<T> PartialEq<NodeIdRef<T>> for NodeId
where
    T: PartialEq<Identifier>,
{
    fn eq(&self, other: &NodeIdRef<T>) -> bool {
        self.namespace == other.namespace && other.identifier == self.identifier
    }
}

impl<T> PartialEq<NodeId> for NodeIdRef<T>
where
    T: PartialEq<Identifier>,
{
    fn eq(&self, other: &NodeId) -> bool {
        self.namespace == other.namespace && self.identifier == other.identifier
    }
}

impl<T> std::hash::Hash for NodeIdRef<T>
where
    T: IdentifierRef,
{
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.namespace.hash(state);
        self.identifier.hash_as_identifier(state);
    }
}

impl<T> Equivalent<NodeId> for NodeIdRef<T>
where
    NodeIdRef<T>: PartialEq<NodeId>,
{
    fn equivalent(&self, key: &NodeId) -> bool {
        self == key
    }
}

impl<T> From<(u16, T)> for NodeIdRef<T>
where
    T: IdentifierRef,
{
    fn from(value: (u16, T)) -> Self {
        Self {
            namespace: value.0,
            identifier: value.1,
        }
    }
}

/// Trait that allows converting a type into a `NodeIdRef`.
/// This is used instead of `Into` to allow for simple function signatures.
///
/// This trait is implemented for copyable types that can be compared to node IDs,
/// such as the core `ObjectId`, `VariableId`, etc. enums, and tuples
/// `(u16, T)`, where `T` is an `IdentifierRef`, which can be compared to an `Identifier`.
/// This includes types such as `&[u8]`, `&str`, `&Guid`, and `u32`.
///
/// It is also implemented for `&NodeId`.
pub trait IntoNodeIdRef<'a> {
    /// The inner identifier type.
    type TIdentifier: IdentifierRef + Clone + Copy + 'a;
    /// Get a reference to this as a `NodeIdRef`.
    fn into_node_id_ref(self) -> NodeIdRef<Self::TIdentifier>;
}

impl<'a, T> IntoNodeIdRef<'a> for NodeIdRef<T>
where
    T: IdentifierRef + Clone + Copy + 'a,
{
    type TIdentifier = T;

    fn into_node_id_ref(self) -> NodeIdRef<Self::TIdentifier> {
        self
    }
}

impl<'a, T> IntoNodeIdRef<'a> for (u16, T)
where
    T: IdentifierRef + Clone + Copy + 'a,
{
    type TIdentifier = T;

    fn into_node_id_ref(self) -> NodeIdRef<Self::TIdentifier> {
        NodeIdRef {
            namespace: self.0,
            identifier: self.1,
        }
    }
}

impl<'a> IntoNodeIdRef<'a> for &'a NodeId {
    type TIdentifier = &'a Identifier;

    fn into_node_id_ref(self) -> NodeIdRef<Self::TIdentifier> {
        NodeIdRef {
            namespace: self.namespace,
            identifier: &self.identifier,
        }
    }
}

macro_rules! enum_as_node_id_ref {
    ($t:ty) => {
        impl IntoNodeIdRef<'_> for $t {
            type TIdentifier = u32;

            fn into_node_id_ref(self) -> NodeIdRef<Self::TIdentifier> {
                NodeIdRef {
                    namespace: 0,
                    identifier: self as u32,
                }
            }
        }
    };
}

enum_as_node_id_ref!(ObjectId);
enum_as_node_id_ref!(ObjectTypeId);
enum_as_node_id_ref!(ReferenceTypeId);
enum_as_node_id_ref!(VariableId);
enum_as_node_id_ref!(VariableTypeId);
enum_as_node_id_ref!(DataTypeId);
enum_as_node_id_ref!(MethodId);
