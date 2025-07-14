use crate::{
    DataTypeId, Identifier, NodeId, ObjectId, ObjectTypeId, ReferenceTypeId, VariableId,
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
