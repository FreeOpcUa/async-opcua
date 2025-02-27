use std::{collections::HashMap, sync::Arc};

use crate::{
    DataTypeDefinition, EnumField, Error, NodeId, StatusCode, StructureField, StructureType,
    Variant, VariantScalarTypeId, VariantTypeId,
};

#[derive(Debug)]
/// Parsed type information about an enum variant.
pub struct EnumTypeInfo {
    /// Enum fields.
    pub variants: HashMap<i64, EnumField>,
}

#[derive(Debug)]
/// Parsed type information about a struct field.
pub struct ParsedStructureField {
    /// Field name.
    pub name: String,
    /// Field data type ID.
    pub type_id: NodeId,
    /// Field value rank.
    pub value_rank: i32,
    /// Field array dimensions.
    pub array_dimensions: Option<Vec<u32>>,
    /// Whether this field is optional.
    pub is_optional: bool,
    /// Variant type used to store this field.
    pub scalar_type: VariantScalarTypeId,
}

impl ParsedStructureField {
    /// Parse this from a structure field.
    pub fn from_field(f: StructureField, scalar_type: VariantScalarTypeId) -> Result<Self, String> {
        if f.name.is_empty() || f.name.is_null() {
            return Err("Field has null name".to_owned());
        }
        Ok(Self {
            name: f.name.as_ref().to_owned(),
            type_id: f.data_type,
            value_rank: f.value_rank,
            array_dimensions: f.array_dimensions,
            is_optional: f.is_optional,
            scalar_type,
        })
    }

    /// Validate that `value` could be this field.
    pub fn validate(&self, value: &Variant) -> Result<(), Error> {
        let ty = match value.type_id() {
            VariantTypeId::Empty => {
                if !self.is_optional {
                    return Err(Error::new(
                        StatusCode::BadInvalidArgument,
                        format!("Got null value for non-nullable field {}", self.name),
                    ));
                } else {
                    return Ok(());
                }
            }
            VariantTypeId::Scalar(ty) => ty,
            VariantTypeId::Array(ty, dims) => {
                let rank = dims.map(|d| d.len()).unwrap_or(1);
                if rank as i32 != self.value_rank {
                    return Err(Error::new(
                        StatusCode::BadInvalidArgument,
                    format!("Invalid dimensions, array dimensions {:?} length must match field value rank {}",
                        dims, self.value_rank)));
                }
                ty
            }
        };
        if ty != self.scalar_type {
            return Err(Error::new(
                StatusCode::BadInvalidArgument,
                format!(
                    "Invalid type for field {}. Got {}, expected {}",
                    self.name, ty, self.scalar_type
                ),
            ));
        }
        Ok(())
    }
}

#[derive(Debug)]
/// Parsed info about a structure type.
pub struct StructTypeInfo {
    /// Structure variant. Structure, StructureWithOptionalFields, or Union.
    pub structure_type: StructureType,
    /// List of structure fields. The order is significant.
    pub fields: Vec<ParsedStructureField>,
    /// Field index by name.
    pub index_by_name: HashMap<String, usize>,
    /// Collection of encoding IDs.
    pub encoding_ids: EncodingIds,
    /// Whether this type is abstract and cannot be instantiated.
    pub is_abstract: bool,
    /// Structure node ID.
    pub node_id: NodeId,
    /// Structure name.
    pub name: String,
}

impl StructTypeInfo {
    /// Get a field by index.
    pub fn get_field(&self, idx: usize) -> Option<&ParsedStructureField> {
        self.fields.get(idx)
    }

    /// Get a field by name.
    pub fn get_field_by_name(&self, idx: &str) -> Option<&ParsedStructureField> {
        self.index_by_name
            .get(idx)
            .and_then(|i| self.fields.get(*i))
    }

    /// Return whether this struct is supported by the current version of the library.
    /// Types that are not supported will panic on encoding, and be skipped when decoding.
    ///
    /// Currently this is only structures and unions with subtyped values.
    pub fn is_supported(&self) -> bool {
        !matches!(
            self.structure_type,
            StructureType::StructureWithSubtypedValues | StructureType::UnionWithSubtypedValues
        )
    }
}

#[derive(Debug, Default)]
/// Encoding IDs for a structure type.
pub struct EncodingIds {
    /// Binary encoding ID.
    pub binary_id: NodeId,
    /// Json encoding ID.
    pub json_id: NodeId,
    /// XML encoding ID.
    pub xml_id: NodeId,
}

#[derive(Debug)]
pub struct GenericTypeInfo {
    pub is_abstract: bool,
}

impl GenericTypeInfo {
    pub fn new(is_abstract: bool) -> Self {
        Self { is_abstract }
    }
}

#[derive(Debug)]
/// Structure describing a data type on the server.
pub enum TypeInfo {
    /// Description of an enum data type.
    Enum(Arc<EnumTypeInfo>),
    /// Description of a structure data type.
    Struct(Arc<StructTypeInfo>),
    /// Description of a primitive data type.
    Primitive(Arc<GenericTypeInfo>),
}

#[derive(Debug)]
/// Reference to a `TypeInfo`.
pub enum TypeInfoRef<'a> {
    /// Description of an enum data type.
    Enum(&'a Arc<EnumTypeInfo>),
    /// Description of a structure data type.
    Struct(&'a Arc<StructTypeInfo>),
    /// Description of a primitive data type.
    Primitive(&'a Arc<GenericTypeInfo>),
}

impl From<StructTypeInfo> for TypeInfo {
    fn from(value: StructTypeInfo) -> Self {
        Self::Struct(Arc::new(value))
    }
}

impl From<EnumTypeInfo> for TypeInfo {
    fn from(value: EnumTypeInfo) -> Self {
        Self::Enum(Arc::new(value))
    }
}

impl From<GenericTypeInfo> for TypeInfo {
    fn from(value: GenericTypeInfo) -> Self {
        Self::Primitive(Arc::new(value))
    }
}

#[derive(Debug)]
/// Map from child to parent node ID.
pub struct ParentIds {
    parent_ids: HashMap<NodeId, NodeId>,
}

impl Default for ParentIds {
    fn default() -> Self {
        Self::new()
    }
}

/// Variant of a data type.
pub enum DataTypeVariant {
    /// Data type is an enumeration.
    Enumeration,
    /// Data type is a structure.
    Structure,
    /// Data type is some primitive.
    Primitive,
}

impl ParentIds {
    /// Create a new empty parent ID map.
    pub fn new() -> Self {
        Self {
            parent_ids: HashMap::new(),
        }
    }

    /// Add a child, parent type pair.
    pub fn add_type(&mut self, node_id: NodeId, parent_id: NodeId) {
        self.parent_ids.insert(node_id, parent_id);
    }

    /// Get the data type variant, essentially checking if it needs special treatment,
    /// by traversing up the hierarchy until we hit a known type.
    pub fn get_data_type_variant(&self, id: &NodeId) -> Option<DataTypeVariant> {
        if let Ok(t) = id.as_data_type_id() {
            match t {
                crate::DataTypeId::Boolean
                | crate::DataTypeId::SByte
                | crate::DataTypeId::Byte
                | crate::DataTypeId::Int16
                | crate::DataTypeId::UInt16
                | crate::DataTypeId::Int32
                | crate::DataTypeId::UInt32
                | crate::DataTypeId::Int64
                | crate::DataTypeId::UInt64
                | crate::DataTypeId::Float
                | crate::DataTypeId::Double
                | crate::DataTypeId::String
                | crate::DataTypeId::DateTime
                | crate::DataTypeId::Guid
                | crate::DataTypeId::ByteString
                | crate::DataTypeId::XmlElement
                | crate::DataTypeId::NodeId
                | crate::DataTypeId::ExpandedNodeId
                | crate::DataTypeId::StatusCode
                | crate::DataTypeId::QualifiedName
                | crate::DataTypeId::LocalizedText
                | crate::DataTypeId::DataValue
                | crate::DataTypeId::DiagnosticInfo
                | crate::DataTypeId::BaseDataType => return Some(DataTypeVariant::Primitive),
                crate::DataTypeId::Structure | crate::DataTypeId::Decimal => {
                    return Some(DataTypeVariant::Structure)
                }
                crate::DataTypeId::Enumeration => return Some(DataTypeVariant::Enumeration),
                _ => (),
            }
        }

        let parent = self.parent_ids.get(id)?;
        self.get_data_type_variant(parent)
    }

    /// Get the variant type for the given `id` by recursively traversing up
    /// the hierarchy until we hit a known type.
    pub fn get_builtin_type(&self, id: &NodeId) -> Option<VariantScalarTypeId> {
        if let Ok(t) = id.as_data_type_id() {
            match t {
                crate::DataTypeId::Boolean => return Some(VariantScalarTypeId::Boolean),
                crate::DataTypeId::SByte => return Some(VariantScalarTypeId::SByte),
                crate::DataTypeId::Byte => return Some(VariantScalarTypeId::Byte),
                crate::DataTypeId::Int16 => return Some(VariantScalarTypeId::Int16),
                crate::DataTypeId::UInt16 => return Some(VariantScalarTypeId::UInt16),
                crate::DataTypeId::Int32 => return Some(VariantScalarTypeId::Int32),
                crate::DataTypeId::UInt32 => return Some(VariantScalarTypeId::UInt32),
                crate::DataTypeId::Int64 => return Some(VariantScalarTypeId::Int64),
                crate::DataTypeId::UInt64 => return Some(VariantScalarTypeId::UInt64),
                crate::DataTypeId::Float => return Some(VariantScalarTypeId::Float),
                crate::DataTypeId::Double => return Some(VariantScalarTypeId::Double),
                crate::DataTypeId::String => return Some(VariantScalarTypeId::String),
                crate::DataTypeId::DateTime => return Some(VariantScalarTypeId::DateTime),
                crate::DataTypeId::Guid => return Some(VariantScalarTypeId::Guid),
                crate::DataTypeId::ByteString => return Some(VariantScalarTypeId::ByteString),
                crate::DataTypeId::XmlElement => return Some(VariantScalarTypeId::XmlElement),
                crate::DataTypeId::NodeId => return Some(VariantScalarTypeId::NodeId),
                crate::DataTypeId::ExpandedNodeId => {
                    return Some(VariantScalarTypeId::ExpandedNodeId)
                }
                crate::DataTypeId::StatusCode => return Some(VariantScalarTypeId::StatusCode),
                crate::DataTypeId::QualifiedName => {
                    return Some(VariantScalarTypeId::QualifiedName)
                }
                crate::DataTypeId::LocalizedText => {
                    return Some(VariantScalarTypeId::LocalizedText)
                }
                // ExtensionObject in this context just means "Structure", which is what
                // the base type in the type hierarchy is.
                crate::DataTypeId::Structure | crate::DataTypeId::Decimal => {
                    return Some(VariantScalarTypeId::ExtensionObject)
                }
                crate::DataTypeId::DataValue => return Some(VariantScalarTypeId::DataValue),
                crate::DataTypeId::DiagnosticInfo => {
                    return Some(VariantScalarTypeId::DiagnosticInfo)
                }
                crate::DataTypeId::Enumeration => return Some(VariantScalarTypeId::Int32),
                // Not sure if this is actually correct, it's the only thing that really makes sense.
                crate::DataTypeId::BaseDataType => return Some(VariantScalarTypeId::Variant),
                _ => (),
            }
        }
        let parent = self.parent_ids.get(id)?;
        self.get_builtin_type(parent)
    }
}

impl TypeInfo {
    /// Build a TypeInfo from the data type definition of the data type.
    pub fn from_type_definition(
        value: DataTypeDefinition,
        name: String,
        encoding_ids: Option<EncodingIds>,
        is_abstract: bool,
        node_id: &NodeId,
        parent_ids: &ParentIds,
    ) -> Result<Self, String> {
        match value {
            DataTypeDefinition::Structure(d) => {
                let Some(encoding_ids) = encoding_ids else {
                    return Err("Missing encoding IDs for structured type".to_owned());
                };
                let mut fields =
                    Vec::with_capacity(d.fields.as_ref().map(|f| f.len()).unwrap_or_default());
                let mut fields_by_name = HashMap::with_capacity(fields.len());
                for (idx, v) in d.fields.into_iter().flatten().enumerate() {
                    let Some(builtin) = parent_ids.get_builtin_type(&v.data_type) else {
                        return Err(format!(
                            "Failed to resolve type id {} to scalar type",
                            node_id
                        ));
                    };
                    let f = ParsedStructureField::from_field(v, builtin)?;
                    fields_by_name.insert(f.name.clone(), idx);
                    fields.push(f);
                }

                Ok(Self::Struct(Arc::new(StructTypeInfo {
                    structure_type: d.structure_type,
                    fields,
                    encoding_ids,
                    is_abstract,
                    node_id: node_id.clone(),
                    index_by_name: fields_by_name,
                    name,
                })))
            }
            DataTypeDefinition::Enum(d) => Ok(Self::Enum(Arc::new(EnumTypeInfo {
                variants: d
                    .fields
                    .into_iter()
                    .flatten()
                    .map(|v| (v.value, v))
                    .collect(),
            }))),
        }
    }
}

#[derive(Debug)]
/// Data type tree, used for loading custom types at runtime.
pub struct DataTypeTree {
    struct_types: HashMap<NodeId, Arc<StructTypeInfo>>,
    enum_types: HashMap<NodeId, Arc<EnumTypeInfo>>,
    other_types: HashMap<NodeId, Arc<GenericTypeInfo>>,
    parent_ids: ParentIds,
    encoding_to_data_type: HashMap<NodeId, NodeId>,
}

impl DataTypeTree {
    /// Create a new data type tree with the given parent IDs.
    ///
    /// Parent IDs should be populated before starting to populate the type tree.
    pub fn new(parent_ids: ParentIds) -> Self {
        Self {
            struct_types: HashMap::new(),
            enum_types: HashMap::new(),
            other_types: HashMap::new(),
            parent_ids,
            encoding_to_data_type: HashMap::new(),
        }
    }

    /// Add a type to the tree.
    pub fn add_type(&mut self, id: NodeId, info: impl Into<TypeInfo>) {
        let info = info.into();
        match info {
            TypeInfo::Enum(arc) => {
                self.enum_types.insert(id.clone(), arc);
            }
            TypeInfo::Struct(arc) => {
                self.encoding_to_data_type
                    .insert(arc.encoding_ids.binary_id.clone(), id.clone());
                self.encoding_to_data_type
                    .insert(arc.encoding_ids.json_id.clone(), id.clone());
                self.encoding_to_data_type
                    .insert(arc.encoding_ids.xml_id.clone(), id.clone());
                self.struct_types.insert(id.clone(), arc);
            }
            TypeInfo::Primitive(arc) => {
                self.other_types.insert(id.clone(), arc);
            }
        }
    }

    /// Get a type from the tree.
    pub fn get_type<'a>(&'a self, id: &NodeId) -> Option<TypeInfoRef<'a>> {
        if let Some(d) = self.struct_types.get(id) {
            Some(TypeInfoRef::Struct(d))
        } else if let Some(d) = self.enum_types.get(id) {
            Some(TypeInfoRef::Enum(d))
        } else {
            self.other_types.get(id).map(TypeInfoRef::Primitive)
        }
    }

    /// Get a struct type from the tree.
    pub fn get_struct_type(&self, id: &NodeId) -> Option<&Arc<StructTypeInfo>> {
        self.struct_types.get(id)
    }

    /// Get a mutable reference to the parent ID map.
    pub fn parent_ids_mut(&mut self) -> &mut ParentIds {
        &mut self.parent_ids
    }

    /// Get a reference to the parent ID map.
    pub fn parent_ids(&self) -> &ParentIds {
        &self.parent_ids
    }

    /// Get the inner map from encoding to data type ID.
    pub fn encoding_to_data_type(&self) -> &HashMap<NodeId, NodeId> {
        &self.encoding_to_data_type
    }
}
