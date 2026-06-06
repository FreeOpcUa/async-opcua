use crate::match_extension_object_owned;

use super::{
    extension_object::ExtensionObject, status_code::StatusCode, DataTypeAttributes,
    GenericAttributes, MethodAttributes, ObjectAttributes, ObjectTypeAttributes,
    ReferenceTypeAttributes, VariableAttributes, VariableTypeAttributes, ViewAttributes,
};

#[derive(Clone, Debug)]
/// Enum over different attribute collections for AddNodes.
pub enum AddNodeAttributes {
    /// Object attributes.
    Object(ObjectAttributes),
    /// Variable attributes.
    Variable(VariableAttributes),
    /// Method attributes.
    Method(MethodAttributes),
    /// ObjectType attributes.
    ObjectType(ObjectTypeAttributes),
    /// VariableType attributes.
    VariableType(VariableTypeAttributes),
    /// ReferenceType attributes.
    ReferenceType(ReferenceTypeAttributes),
    /// DataType attributes.
    DataType(DataTypeAttributes),
    /// View attributes.
    View(ViewAttributes),
    /// Generic attributes.
    Generic(GenericAttributes),
    /// No extra attributes.
    None,
}

impl AddNodeAttributes {
    /// Get Self from an extension object body.
    pub fn from_extension_object(obj: ExtensionObject) -> Result<Self, StatusCode> {
        if obj.is_null() {
            return Ok(Self::None);
        }
        match_extension_object_owned!(obj,
            v: ObjectAttributes => Ok(Self::Object(v)),
            v: MethodAttributes => Ok(Self::Method(v)),
            v: VariableAttributes => Ok(Self::Variable(v)),
            v: ViewAttributes => Ok(Self::View(v)),
            v: ObjectTypeAttributes => Ok(Self::ObjectType(v)),
            v: VariableTypeAttributes => Ok(Self::VariableType(v)),
            v: ReferenceTypeAttributes => Ok(Self::ReferenceType(v)),
            v: DataTypeAttributes => Ok(Self::DataType(v)),
            v: GenericAttributes => Ok(Self::Generic(v)),
            _ => Err(StatusCode::BadNodeAttributesInvalid),
        )
    }

    /// Convert this into an extension object.
    pub fn as_extension_object(&self) -> ExtensionObject {
        match self.clone() {
            AddNodeAttributes::Object(o) => ExtensionObject::from_message(o),
            AddNodeAttributes::Variable(o) => ExtensionObject::from_message(o),
            AddNodeAttributes::Method(o) => ExtensionObject::from_message(o),
            AddNodeAttributes::ObjectType(o) => ExtensionObject::from_message(o),
            AddNodeAttributes::VariableType(o) => ExtensionObject::from_message(o),
            AddNodeAttributes::ReferenceType(o) => ExtensionObject::from_message(o),
            AddNodeAttributes::DataType(o) => ExtensionObject::from_message(o),
            AddNodeAttributes::View(o) => ExtensionObject::from_message(o),
            AddNodeAttributes::Generic(o) => ExtensionObject::from_message(o),
            AddNodeAttributes::None => ExtensionObject::null(),
        }
    }
}
