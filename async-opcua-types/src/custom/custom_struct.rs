use std::{io::Write, sync::Arc};

use crate::{
    write_i32, write_u32, Array, BinaryDecodable, BinaryEncodable, ByteString, Context, DataValue,
    DateTime, DiagnosticInfo, EncodingResult, Error, ExpandedMessageInfo, ExpandedNodeId,
    ExtensionObject, Guid, LocalizedText, NodeId, QualifiedName, StatusCode, StructureType,
    TypeLoader, UAString, UaNullable, Variant, XmlElement,
};

use super::type_tree::{DataTypeTree, ParsedStructureField, StructTypeInfo};

#[derive(Debug, Clone)]
/// A type representing an OPC-UA structure decoded dynamically.
/// This can use runtime information to properly encode and decode
/// binary information. In order to make the type encodable, it
/// contains references to a [StructTypeInfo] describing the type it contains,
/// as well as the [DataTypeTree] containing any types it references.
///
/// This type can be used to reason about data on a server without explicitly
/// defining the server types in code, which is useful if you want to create
/// a generic client that can work with data from any server.
///
/// Internally it is simply an array of [Variant].
///
/// Note that this type is intended to support all encoding/decoding types
/// in the OPC-UA standard, which is more than what the encoding macros
/// currently do. This includes structurs with optional fields, unions,
/// and multi-dimensional arrays, none of which are used in the core types.
pub struct DynamicStructure {
    pub(super) type_def: Arc<StructTypeInfo>,
    pub(super) discriminant: u32,
    pub(super) type_tree: Arc<DataTypeTree>,
    pub(super) data: Vec<Variant>,
}

impl PartialEq for DynamicStructure {
    fn eq(&self, other: &Self) -> bool {
        self.type_def.node_id == other.type_def.node_id
            && self.discriminant == other.discriminant
            && self.data == other.data
    }
}

impl ExpandedMessageInfo for DynamicStructure {
    fn full_json_type_id(&self) -> ExpandedNodeId {
        ExpandedNodeId::new(self.type_def.encoding_ids.json_id.clone())
    }

    fn full_type_id(&self) -> ExpandedNodeId {
        ExpandedNodeId::new(self.type_def.encoding_ids.binary_id.clone())
    }

    fn full_xml_type_id(&self) -> ExpandedNodeId {
        ExpandedNodeId::new(self.type_def.encoding_ids.xml_id.clone())
    }

    fn full_data_type_id(&self) -> ExpandedNodeId {
        ExpandedNodeId::new(self.type_def.node_id.clone())
    }
}

impl DynamicStructure {
    /// Create a new struct, validating that it matches the provided type definition.
    pub fn new_struct(
        type_def: Arc<StructTypeInfo>,
        type_tree: Arc<DataTypeTree>,
        data: Vec<Variant>,
    ) -> Result<Self, Error> {
        if data.len() != type_def.fields.len() {
            return Err(Error::new(
                StatusCode::BadInvalidArgument,
                format!(
                    "Invalid number of fields, got {}, expected {}",
                    data.len(),
                    type_def.fields.len()
                ),
            ));
        }
        if matches!(type_def.structure_type, StructureType::Union) {
            return Err(Error::new(
                StatusCode::BadInvalidArgument,
                "Cannot construct a union using new_struct, call new_union instead",
            ));
        }

        for (value, field) in data.iter().zip(type_def.fields.iter()) {
            field.validate(value)?;
        }
        Ok(Self {
            type_def,
            discriminant: 0,
            type_tree,
            data,
        })
    }

    /// Create a new union, validating that it matches the provided type definition.
    pub fn new_union(
        type_def: Arc<StructTypeInfo>,
        type_tree: Arc<DataTypeTree>,
        data: Variant,
        discriminant: u32,
    ) -> Result<Self, Error> {
        if discriminant == 0 {
            return Err(Error::new(
                StatusCode::BadInvalidArgument,
                "Discriminant must be non-zero.",
            ));
        }

        if !matches!(type_def.structure_type, StructureType::Union) {
            return Err(Error::new(
                StatusCode::BadInvalidArgument,
                "Cannot construct a struct using new_union, call new_struct instead",
            ));
        }
        let Some(field) = type_def.fields.get(discriminant as usize - 1) else {
            return Err(Error::new(
                StatusCode::BadInvalidArgument,
                format!("Invalid discriminant {}", discriminant),
            ));
        };
        field.validate(&data)?;
        Ok(Self {
            type_def,
            discriminant,
            type_tree,
            data: vec![data],
        })
    }

    /// Create a new union, with value null.
    pub fn new_null_union(type_def: Arc<StructTypeInfo>, type_tree: Arc<DataTypeTree>) -> Self {
        Self {
            type_def,
            type_tree,
            discriminant: 0,
            data: Vec::new(),
        }
    }

    /// Get a reference to the fields in order.
    pub fn values(&self) -> &[Variant] {
        &self.data
    }

    /// Get a reference to the field at `index`
    pub fn get_field(&self, index: usize) -> Option<&Variant> {
        self.data.get(index)
    }

    /// Get a reference to the field with the given name.
    pub fn get_field_by_name(&self, name: &str) -> Option<&Variant> {
        self.type_def
            .index_by_name
            .get(name)
            .and_then(|v| self.data.get(*v))
    }

    fn field_variant_len(
        &self,
        f: &Variant,
        field: &ParsedStructureField,
        ctx: &Context<'_>,
    ) -> usize {
        match f {
            Variant::ExtensionObject(o) => {
                let Some(field_ty) = self.type_tree.get_struct_type(&field.type_id) else {
                    // The field is missing, we'll fail later, probably, but for now just assume that we're encoding
                    // an extension object.
                    return o.byte_len(ctx);
                };

                // If the field is abstract, encode it as an extension object
                if field_ty.is_abstract {
                    return o.byte_len(ctx);
                }
                match &o.body {
                    Some(b) => b.byte_len_dyn(ctx),
                    None => 0,
                }
            }
            r => r.value_byte_len(ctx),
        }
    }

    fn encode_field<S: Write + ?Sized>(
        &self,
        mut stream: &mut S,
        f: &Variant,
        field: &ParsedStructureField,
        ctx: &Context<'_>,
    ) -> EncodingResult<()> {
        match f {
            Variant::ExtensionObject(o) => {
                let Some(field_ty) = self.type_tree.get_struct_type(&field.type_id) else {
                    return Err(Error::encoding(format!(
                        "Dynamic type field missing from type tree: {}",
                        field.type_id
                    )));
                };

                if field_ty.is_abstract {
                    o.encode(stream, ctx)
                } else {
                    let Some(body) = &o.body else {
                        return Err(Error::encoding(
                            "Dynamic type field is missing extension object body",
                        ));
                    };
                    body.encode_binary(&mut stream, ctx)
                }
            }
            Variant::Array(a) => {
                if field.value_rank > 1 {
                    let Some(dims) = &a.dimensions else {
                        return Err(Error::encoding(
                            "ArrayDimensions are required for fields with value rank > 1",
                        ));
                    };
                    // Note array dimensions are encoded as Int32 even though they are presented
                    // as UInt32 through attribute.

                    // Encode dimensions
                    write_i32(stream, dims.len() as i32)?;
                    for dimension in dims {
                        write_i32(stream, *dimension as i32)?;
                    }
                } else {
                    write_i32(stream, a.values.len() as i32)?;
                }

                for value in a.values.iter() {
                    self.encode_field(stream, value, field, ctx)?;
                }
                Ok(())
            }
            Variant::Empty => Err(Error::encoding("Empty variant value in structure")),
            r => r.encode_value(stream, ctx),
        }
    }
}

impl UaNullable for DynamicStructure {
    fn is_ua_null(&self) -> bool {
        if self.type_def.structure_type == StructureType::Union {
            self.discriminant == 0
        } else {
            false
        }
    }
}

impl BinaryEncodable for DynamicStructure {
    fn byte_len(&self, ctx: &crate::Context<'_>) -> usize {
        // Byte length is the sum of the individual structure fields
        let mut size = 0;
        let s = &self.type_def;

        match s.structure_type {
            StructureType::Structure => {
                for (value, field) in self.data.iter().zip(s.fields.iter()) {
                    size += self.field_variant_len(value, field, ctx);
                }
            }
            StructureType::StructureWithOptionalFields => {
                // encoding mask.
                size += 4;
                for (value, field) in self.data.iter().zip(s.fields.iter()) {
                    if !field.is_optional || !matches!(value, Variant::Empty) {
                        size += self.field_variant_len(value, field, ctx);
                    }
                }
            }
            StructureType::Union => {
                // discriminant
                size += 4;
                if self.discriminant != 0 {
                    let (Some(value), Some(field)) = (
                        self.data.first(),
                        s.fields.get(self.discriminant as usize - 1),
                    ) else {
                        return 0;
                    };
                    size += self.field_variant_len(value, field, ctx);
                }
            }
            StructureType::StructureWithSubtypedValues => {
                todo!("StructureWithSubtypedValues is unsupported")
            }
            StructureType::UnionWithSubtypedValues => {
                todo!("UnionWithSubtypedValues is unsupported")
            }
        }

        size
    }

    fn encode<S: std::io::Write + ?Sized>(
        &self,
        stream: &mut S,
        ctx: &crate::Context<'_>,
    ) -> crate::EncodingResult<()> {
        let s = &self.type_def;
        match s.structure_type {
            StructureType::Structure => {
                // Invariant used here: The data list must contain the correct fields with the correct values.
                for (value, field) in self.data.iter().zip(s.fields.iter()) {
                    self.encode_field(stream, value, field, ctx)?;
                }
            }
            StructureType::StructureWithOptionalFields => {
                let mut encoding_mask = 0u32;
                let mut optional_idx = 0;
                for (value, field) in self.data.iter().zip(s.fields.iter()) {
                    if field.is_optional {
                        if !matches!(value, Variant::Empty) {
                            encoding_mask |= 1 << optional_idx;
                        }
                        optional_idx += 1;
                    }
                }
                write_u32(stream, encoding_mask)?;
                for (value, field) in self.data.iter().zip(s.fields.iter()) {
                    if !field.is_optional || !matches!(value, Variant::Empty) {
                        self.encode_field(stream, value, field, ctx)?;
                    }
                }
            }
            StructureType::Union => {
                write_u32(stream, self.discriminant)?;
                if self.discriminant != 0 {
                    let (Some(value), Some(field)) = (
                        self.data.first(),
                        s.fields.get(self.discriminant as usize - 1),
                    ) else {
                        return Err(Error::encoding(
                            "Discriminant was out of range of known fields",
                        ));
                    };

                    self.encode_field(stream, value, field, ctx)?;
                }
            }
            StructureType::StructureWithSubtypedValues => {
                todo!("StructureWithSubtypedValues is unsupported")
            }
            StructureType::UnionWithSubtypedValues => {
                todo!("UnionWithSubtypedValues is unsupported")
            }
        }

        Ok(())
    }
}

/// Type loader that can load types dynamically using data type definitions loaded at
/// runtime.
pub struct DynamicTypeLoader {
    pub(super) type_tree: Arc<DataTypeTree>,
}

impl DynamicTypeLoader {
    /// Create a new type loader that loads types from the given type tree.
    pub fn new(type_tree: Arc<DataTypeTree>) -> Self {
        Self { type_tree }
    }

    fn decode_field_value(
        &self,
        field: &ParsedStructureField,
        stream: &mut dyn std::io::Read,
        ctx: &Context<'_>,
    ) -> EncodingResult<Variant> {
        match field.scalar_type {
            crate::VariantScalarTypeId::Boolean => Ok(Variant::from(
                <bool as BinaryDecodable>::decode(stream, ctx)?,
            )),
            crate::VariantScalarTypeId::SByte => {
                Ok(Variant::from(<i8 as BinaryDecodable>::decode(stream, ctx)?))
            }
            crate::VariantScalarTypeId::Byte => {
                Ok(Variant::from(<u8 as BinaryDecodable>::decode(stream, ctx)?))
            }
            crate::VariantScalarTypeId::Int16 => Ok(Variant::from(
                <i16 as BinaryDecodable>::decode(stream, ctx)?,
            )),
            crate::VariantScalarTypeId::UInt16 => Ok(Variant::from(
                <u16 as BinaryDecodable>::decode(stream, ctx)?,
            )),
            crate::VariantScalarTypeId::Int32 => Ok(Variant::from(
                <i32 as BinaryDecodable>::decode(stream, ctx)?,
            )),
            crate::VariantScalarTypeId::UInt32 => Ok(Variant::from(
                <u32 as BinaryDecodable>::decode(stream, ctx)?,
            )),
            crate::VariantScalarTypeId::Int64 => Ok(Variant::from(
                <i64 as BinaryDecodable>::decode(stream, ctx)?,
            )),
            crate::VariantScalarTypeId::UInt64 => Ok(Variant::from(
                <u64 as BinaryDecodable>::decode(stream, ctx)?,
            )),
            crate::VariantScalarTypeId::Float => Ok(Variant::from(
                <f32 as BinaryDecodable>::decode(stream, ctx)?,
            )),
            crate::VariantScalarTypeId::Double => Ok(Variant::from(
                <f64 as BinaryDecodable>::decode(stream, ctx)?,
            )),
            crate::VariantScalarTypeId::String => Ok(Variant::from(
                <UAString as BinaryDecodable>::decode(stream, ctx)?,
            )),
            crate::VariantScalarTypeId::DateTime => Ok(Variant::from(
                <DateTime as BinaryDecodable>::decode(stream, ctx)?,
            )),
            crate::VariantScalarTypeId::Guid => Ok(Variant::from(
                <Guid as BinaryDecodable>::decode(stream, ctx)?,
            )),
            crate::VariantScalarTypeId::ByteString => Ok(Variant::from(
                <ByteString as BinaryDecodable>::decode(stream, ctx)?,
            )),
            crate::VariantScalarTypeId::XmlElement => Ok(Variant::from(
                <XmlElement as BinaryDecodable>::decode(stream, ctx)?,
            )),
            crate::VariantScalarTypeId::NodeId => Ok(Variant::from(
                <NodeId as BinaryDecodable>::decode(stream, ctx)?,
            )),
            crate::VariantScalarTypeId::ExpandedNodeId => Ok(Variant::from(
                <ExpandedNodeId as BinaryDecodable>::decode(stream, ctx)?,
            )),
            crate::VariantScalarTypeId::StatusCode => Ok(Variant::from(
                <StatusCode as BinaryDecodable>::decode(stream, ctx)?,
            )),
            crate::VariantScalarTypeId::QualifiedName => Ok(Variant::from(
                <QualifiedName as BinaryDecodable>::decode(stream, ctx)?,
            )),
            crate::VariantScalarTypeId::LocalizedText => Ok(Variant::from(
                <LocalizedText as BinaryDecodable>::decode(stream, ctx)?,
            )),
            crate::VariantScalarTypeId::ExtensionObject => {
                let Some(field_ty) = self.type_tree.get_struct_type(&field.type_id) else {
                    return Err(Error::decoding(format!(
                        "Dynamic type field missing from type tree: {}",
                        field.type_id
                    )));
                };

                // If the field is abstract, it's encoded as an extension object,
                // or so we assume.
                if field_ty.is_abstract {
                    Ok(Variant::from(<ExtensionObject as BinaryDecodable>::decode(
                        stream, ctx,
                    )?))
                } else {
                    // Else, load the extension object body directly.
                    Ok(Variant::from(
                        ctx.load_from_binary(&field_ty.node_id, stream)?,
                    ))
                }
            }
            crate::VariantScalarTypeId::DataValue => Ok(Variant::from(
                <DataValue as BinaryDecodable>::decode(stream, ctx)?,
            )),
            crate::VariantScalarTypeId::Variant => Ok(Variant::Variant(Box::new(
                <Variant as BinaryDecodable>::decode(stream, ctx)?,
            ))),
            crate::VariantScalarTypeId::DiagnosticInfo => Ok(Variant::from(
                <DiagnosticInfo as BinaryDecodable>::decode(stream, ctx)?,
            )),
        }
    }

    fn decode_field(
        &self,
        field: &ParsedStructureField,
        stream: &mut dyn std::io::Read,
        ctx: &Context<'_>,
    ) -> EncodingResult<Variant> {
        if field.value_rank > 0 {
            let (len, array_dims) = if field.value_rank > 1 {
                let Some(array_dims) = <Option<Vec<i32>> as BinaryDecodable>::decode(stream, ctx)?
                else {
                    return Err(Error::decoding("Array has invalid ArrayDimensions"));
                };
                if array_dims.len() != field.value_rank as usize {
                    return Err(Error::decoding(
                        "Array has incorrect ArrayDimensions, must match value rank",
                    ));
                }
                let mut len = 1;
                let mut final_dims = Vec::with_capacity(array_dims.len());
                for dim in &array_dims {
                    if *dim <= 0 {
                        return Err(Error::decoding("Array has incorrect ArrayDimensions, all dimensions must be greater than zero"));
                    }
                    len *= *dim as u32;
                    final_dims.push(*dim as u32);
                }
                (len as usize, Some(final_dims))
            } else {
                let len = <u32 as BinaryDecodable>::decode(stream, ctx)?;
                (len as usize, None)
            };

            if len > ctx.options().max_array_length {
                return Err(Error::decoding(format!(
                    "Array length {} exceeds decoding limit {}",
                    len,
                    ctx.options().max_array_length
                )));
            }

            let mut res = Vec::with_capacity(len);
            for _ in 0..len {
                res.push(self.decode_field_value(field, stream, ctx)?);
            }
            if let Some(dims) = array_dims {
                Ok(Variant::Array(Box::new(
                    Array::new_multi(field.scalar_type, res, dims).map_err(Error::decoding)?,
                )))
            } else {
                Ok(Variant::Array(Box::new(
                    Array::new(field.scalar_type, res).map_err(Error::decoding)?,
                )))
            }
        } else {
            self.decode_field_value(field, stream, ctx)
        }
    }

    fn decode_type_inner(
        &self,
        stream: &mut dyn std::io::Read,
        ctx: &Context<'_>,
        t: &Arc<StructTypeInfo>,
    ) -> crate::EncodingResult<Box<dyn crate::DynEncodable>> {
        match t.structure_type {
            StructureType::Structure => {
                let mut values = Vec::with_capacity(t.fields.len());
                for field in &t.fields {
                    values.push(self.decode_field(field, stream, ctx)?);
                }
                Ok(Box::new(DynamicStructure {
                    type_def: t.clone(),
                    discriminant: 0,
                    type_tree: self.type_tree.clone(),
                    data: values,
                }))
            }
            StructureType::StructureWithOptionalFields => {
                let mask = <u32 as BinaryDecodable>::decode(stream, ctx)?;
                let mut values = Vec::with_capacity(t.fields.len());
                let mut optional_idx = 0;
                for field in t.fields.iter() {
                    if field.is_optional {
                        if (1 << optional_idx) & mask != 0 {
                            values.push(self.decode_field(field, stream, ctx)?);
                        } else {
                            values.push(Variant::Empty);
                        }
                        optional_idx += 1;
                    } else {
                        values.push(self.decode_field(field, stream, ctx)?);
                    }
                }
                Ok(Box::new(DynamicStructure {
                    type_def: t.clone(),
                    discriminant: 0,
                    type_tree: self.type_tree.clone(),
                    data: values,
                }))
            }
            StructureType::Union => {
                let discriminant = <u32 as BinaryDecodable>::decode(stream, ctx)?;
                if discriminant == 0 {
                    return Ok(Box::new(DynamicStructure::new_null_union(
                        t.clone(),
                        self.type_tree.clone(),
                    )));
                }
                let Some(field) = t.fields.get(discriminant as usize - 1) else {
                    return Err(Error::decoding(format!(
                        "Invalid discriminant: {}",
                        discriminant
                    )));
                };
                let values = vec![self.decode_field(field, stream, ctx)?];
                Ok(Box::new(DynamicStructure {
                    type_def: t.clone(),
                    discriminant,
                    type_tree: self.type_tree.clone(),
                    data: values,
                }))
            }
            StructureType::StructureWithSubtypedValues => {
                todo!("StructureWithSubtypedValues is unsupported")
            }
            StructureType::UnionWithSubtypedValues => {
                todo!("UnionWithSubtypedValues is unsupported")
            }
        }
    }
}

impl TypeLoader for DynamicTypeLoader {
    fn load_from_binary(
        &self,
        node_id: &NodeId,
        stream: &mut dyn std::io::Read,
        ctx: &Context<'_>,
    ) -> Option<crate::EncodingResult<Box<dyn crate::DynEncodable>>> {
        let ty_node_id = if let Some(mapped) = self.type_tree.encoding_to_data_type().get(node_id) {
            mapped
        } else {
            node_id
        };
        let t = self.type_tree.get_struct_type(ty_node_id)?;

        if !t.is_supported() {
            return None;
        }

        Some(self.decode_type_inner(stream, ctx, t))
    }

    fn priority(&self) -> crate::TypeLoaderPriority {
        crate::TypeLoaderPriority::Dynamic(50)
    }

    #[cfg(feature = "xml")]
    fn load_from_xml(
        &self,
        node_id: &crate::NodeId,
        stream: &mut crate::xml::XmlStreamReader<&mut dyn std::io::Read>,
        ctx: &Context<'_>,
    ) -> Option<crate::EncodingResult<Box<dyn crate::DynEncodable>>> {
        let ty_node_id = if let Some(mapped) = self.type_tree.encoding_to_data_type().get(node_id) {
            mapped
        } else {
            node_id
        };
        let t = self.type_tree.get_struct_type(ty_node_id)?;

        if !t.is_supported() {
            return None;
        }

        Some(self.xml_decode_type_inner(stream, ctx, t))
    }

    #[cfg(feature = "json")]
    fn load_from_json(
        &self,
        node_id: &crate::NodeId,
        stream: &mut crate::json::JsonStreamReader<&mut dyn std::io::Read>,
        ctx: &Context<'_>,
    ) -> Option<crate::EncodingResult<Box<dyn crate::DynEncodable>>> {
        let ty_node_id = if let Some(mapped) = self.type_tree.encoding_to_data_type().get(node_id) {
            mapped
        } else {
            node_id
        };
        let t = self.type_tree.get_struct_type(ty_node_id)?;

        if !t.is_supported() {
            return None;
        }

        Some(self.json_decode_type_inner(stream, ctx, t))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::{
        io::{Cursor, Seek},
        sync::{Arc, LazyLock},
    };

    use opcua_macros::ua_encodable;

    use crate::{
        binary_decode_to_enc, json_decode_to_enc, xml_decode_to_enc, Array, BinaryDecodable,
        BinaryEncodable, ContextOwned, DataTypeDefinition, DataTypeId, DecodingOptions,
        EUInformation, ExpandedMessageInfo, ExtensionObject, LocalizedText, NamespaceMap, NodeId,
        ObjectId, StaticTypeLoader, StructureDefinition, StructureField, TypeLoaderCollection,
        TypeLoaderInstance, UAString, Variant, VariantScalarTypeId,
    };

    use crate::custom::type_tree::{
        DataTypeTree, EncodingIds, GenericTypeInfo, ParentIds, TypeInfo,
    };

    use super::{DynamicStructure, DynamicTypeLoader};

    pub(crate) fn make_type_tree() -> DataTypeTree {
        // Add a few builtins we need.
        let mut type_tree = DataTypeTree::new(ParentIds::new());
        type_tree.add_type(DataTypeId::Int32.into(), GenericTypeInfo::new(false));
        type_tree.add_type(DataTypeId::Boolean.into(), GenericTypeInfo::new(false));
        type_tree.add_type(
            DataTypeId::LocalizedText.into(),
            GenericTypeInfo::new(false),
        );
        type_tree.add_type(DataTypeId::String.into(), GenericTypeInfo::new(false));
        type_tree
    }

    pub(crate) fn add_eu_information(type_tree: &mut DataTypeTree) {
        type_tree.parent_ids_mut().add_type(
            DataTypeId::EUInformation.into(),
            DataTypeId::Structure.into(),
        );
        type_tree.add_type(
            DataTypeId::EUInformation.into(),
            TypeInfo::from_type_definition(
                DataTypeDefinition::Structure(StructureDefinition {
                    default_encoding_id: NodeId::null(),
                    base_data_type: DataTypeId::Structure.into(),
                    structure_type: crate::StructureType::Structure,
                    fields: Some(vec![
                        StructureField {
                            name: "NamespaceUri".into(),
                            data_type: DataTypeId::String.into(),
                            value_rank: -1,
                            ..Default::default()
                        },
                        StructureField {
                            name: "UnitId".into(),
                            data_type: DataTypeId::Int32.into(),
                            value_rank: -1,
                            ..Default::default()
                        },
                        StructureField {
                            name: "DisplayName".into(),
                            data_type: DataTypeId::LocalizedText.into(),
                            value_rank: -1,
                            ..Default::default()
                        },
                        StructureField {
                            name: "Description".into(),
                            data_type: DataTypeId::LocalizedText.into(),
                            value_rank: -1,
                            ..Default::default()
                        },
                    ]),
                }),
                "EUInformation".to_owned(),
                Some(EncodingIds {
                    binary_id: ObjectId::EUInformation_Encoding_DefaultBinary.into(),
                    json_id: ObjectId::EUInformation_Encoding_DefaultJson.into(),
                    xml_id: ObjectId::EUInformation_Encoding_DefaultXml.into(),
                }),
                false,
                &DataTypeId::EUInformation.into(),
                type_tree.parent_ids(),
            )
            .unwrap(),
        );
    }

    #[test]
    fn dynamic_struct_round_trip() {
        let mut type_tree = make_type_tree();
        add_eu_information(&mut type_tree);
        // Add a structure for EUInformation

        let loader = DynamicTypeLoader::new(Arc::new(type_tree));
        let mut loaders = TypeLoaderCollection::new_empty();
        loaders.add_type_loader(loader);
        let ctx = ContextOwned::new(NamespaceMap::new(), loaders, DecodingOptions::test());

        let mut write_buf = Vec::<u8>::new();
        let mut cursor = Cursor::new(&mut write_buf);

        let obj = ExtensionObject::from_message(EUInformation {
            namespace_uri: "my.namespace.uri".into(),
            unit_id: 5,
            display_name: "Degrees Celsius".into(),
            description: "Description".into(),
        });

        // Encode the object, will use the regular encode implementation for EUInformation.
        BinaryEncodable::encode(&obj, &mut cursor, &ctx.context()).unwrap();
        cursor.seek(std::io::SeekFrom::Start(0)).unwrap();

        let obj2: ExtensionObject = BinaryDecodable::decode(&mut cursor, &ctx.context()).unwrap();

        // Decode it back, resulting in a dynamic structure.
        let value = obj2.inner_as::<DynamicStructure>().unwrap();
        assert_eq!(value.data.len(), 4);
        assert_eq!(value.data[0], Variant::from("my.namespace.uri"));
        assert_eq!(value.data[1], Variant::from(5i32));
        assert_eq!(
            value.data[2],
            Variant::from(LocalizedText::from("Degrees Celsius"))
        );
        assert_eq!(
            value.data[3],
            Variant::from(LocalizedText::from("Description"))
        );

        // Re-encode it
        cursor.seek(std::io::SeekFrom::Start(0)).unwrap();
        BinaryEncodable::encode(&obj2, &mut cursor, &ctx.context()).unwrap();

        // Make a new context, this time with the regular decoder for EUInformation
        let ctx = ContextOwned::new_default(NamespaceMap::new(), DecodingOptions::test());
        cursor.seek(std::io::SeekFrom::Start(0)).unwrap();
        let obj3: ExtensionObject = BinaryDecodable::decode(&mut cursor, &ctx.context()).unwrap();

        assert_eq!(obj, obj3);
    }

    #[test]
    fn dynamic_nested_struct_round_trip() {
        let mut type_tree = make_type_tree();
        add_eu_information(&mut type_tree);
        let type_node_id = NodeId::new(1, 5);
        type_tree
            .parent_ids_mut()
            .add_type(type_node_id.clone(), DataTypeId::Structure.into());
        type_tree.add_type(
            type_node_id.clone(),
            TypeInfo::from_type_definition(
                DataTypeDefinition::Structure(StructureDefinition {
                    default_encoding_id: NodeId::null(),
                    base_data_type: DataTypeId::Structure.into(),
                    structure_type: crate::StructureType::Structure,
                    fields: Some(vec![
                        StructureField {
                            name: "Info".into(),
                            data_type: DataTypeId::EUInformation.into(),
                            value_rank: -1,
                            ..Default::default()
                        },
                        StructureField {
                            name: "InfoArray".into(),
                            data_type: DataTypeId::EUInformation.into(),
                            value_rank: 1,
                            ..Default::default()
                        },
                        StructureField {
                            name: "AbstractField".into(),
                            data_type: DataTypeId::BaseDataType.into(),
                            value_rank: -1,
                            ..Default::default()
                        },
                        StructureField {
                            name: "PrimitiveArray".into(),
                            data_type: DataTypeId::Int32.into(),
                            value_rank: 2,
                            ..Default::default()
                        },
                    ]),
                }),
                "MyType".to_owned(),
                Some(EncodingIds {
                    binary_id: NodeId::new(1, 6),
                    json_id: NodeId::new(1, 7),
                    xml_id: NodeId::new(1, 8),
                }),
                false,
                &type_node_id,
                type_tree.parent_ids(),
            )
            .unwrap(),
        );
        let type_tree = Arc::new(type_tree);
        let loader = DynamicTypeLoader::new(type_tree.clone());
        let mut loaders = TypeLoaderCollection::new();
        loaders.add_type_loader(loader);
        let ctx = ContextOwned::new(NamespaceMap::new(), loaders, DecodingOptions::test());

        let obj = DynamicStructure::new_struct(
            type_tree.get_struct_type(&type_node_id).unwrap().clone(),
            type_tree,
            vec![
                Variant::from(ExtensionObject::from_message(EUInformation {
                    namespace_uri: "my.namespace.uri".into(),
                    unit_id: 5,
                    display_name: "Degrees Celsius".into(),
                    description: "Description".into(),
                })),
                Variant::from(vec![
                    ExtensionObject::from_message(EUInformation {
                        namespace_uri: "my.namespace.uri".into(),
                        unit_id: 5,
                        display_name: "Degrees Celsius".into(),
                        description: "Description".into(),
                    }),
                    ExtensionObject::from_message(EUInformation {
                        namespace_uri: "my.namespace.uri.2".into(),
                        unit_id: 6,
                        display_name: "Degrees Celsius 2".into(),
                        description: "Description 2".into(),
                    }),
                ]),
                Variant::Variant(Box::new(Variant::from(123))),
                Variant::from(
                    Array::new_multi(
                        VariantScalarTypeId::Int32,
                        [1i32, 2, 3, 4, 5, 6]
                            .into_iter()
                            .map(Variant::from)
                            .collect::<Vec<_>>(),
                        vec![2, 3],
                    )
                    .unwrap(),
                ),
            ],
        )
        .unwrap();
        let obj = ExtensionObject::from_message(obj);

        let mut write_buf = Vec::<u8>::new();
        let mut cursor = Cursor::new(&mut write_buf);

        BinaryEncodable::encode(&obj, &mut cursor, &ctx.context()).unwrap();
        cursor.seek(std::io::SeekFrom::Start(0)).unwrap();
        let obj2: ExtensionObject = BinaryDecodable::decode(&mut cursor, &ctx.context()).unwrap();

        assert_eq!(obj, obj2);
    }

    pub(crate) fn get_namespaces() -> NamespaceMap {
        let mut namespaces = NamespaceMap::new();
        namespaces.add_namespace(TYPE_NAMESPACE);
        namespaces
    }

    pub(crate) fn get_custom_union() -> ContextOwned {
        let mut type_tree = make_type_tree();
        type_tree
            .parent_ids_mut()
            .add_type(NodeId::new(1, 1), DataTypeId::Structure.into());
        type_tree.add_type(
            NodeId::new(1, 1),
            TypeInfo::from_type_definition(
                DataTypeDefinition::Structure(StructureDefinition {
                    default_encoding_id: NodeId::null(),
                    base_data_type: DataTypeId::Structure.into(),
                    structure_type: crate::StructureType::Union,
                    fields: Some(vec![
                        StructureField {
                            name: "Integer".into(),
                            data_type: DataTypeId::Int32.into(),
                            value_rank: -1,
                            ..Default::default()
                        },
                        StructureField {
                            name: "StringVariant".into(),
                            data_type: DataTypeId::String.into(),
                            value_rank: -1,
                            ..Default::default()
                        },
                    ]),
                }),
                "MyUnion".to_owned(),
                Some(EncodingIds {
                    binary_id: NodeId::new(1, 2),
                    json_id: NodeId::new(1, 3),
                    xml_id: NodeId::new(1, 4),
                }),
                false,
                &NodeId::new(1, 1),
                type_tree.parent_ids(),
            )
            .unwrap(),
        );

        let loader = DynamicTypeLoader::new(Arc::new(type_tree));
        let mut loaders = TypeLoaderCollection::new_empty();
        loaders.add_type_loader(loader);
        let ctx = ContextOwned::new(get_namespaces(), loaders, DecodingOptions::test());

        ctx
    }

    mod opcua {
        pub use crate as types;
    }

    const TYPE_NAMESPACE: &'static str = "my.custom.namespace.uri";

    #[derive(Debug, Clone, PartialEq)]
    #[ua_encodable]
    pub(crate) enum MyUnion {
        Null,
        Integer(i32),
        StringVariant(UAString),
    }

    impl ExpandedMessageInfo for MyUnion {
        fn full_type_id(&self) -> crate::ExpandedNodeId {
            crate::ExpandedNodeId::new_with_namespace(TYPE_NAMESPACE, 2)
        }

        fn full_json_type_id(&self) -> crate::ExpandedNodeId {
            crate::ExpandedNodeId::new_with_namespace(TYPE_NAMESPACE, 3)
        }

        fn full_xml_type_id(&self) -> crate::ExpandedNodeId {
            crate::ExpandedNodeId::new_with_namespace(TYPE_NAMESPACE, 4)
        }

        fn full_data_type_id(&self) -> crate::ExpandedNodeId {
            crate::ExpandedNodeId::new_with_namespace(TYPE_NAMESPACE, 1)
        }
    }

    static TYPES: LazyLock<TypeLoaderInstance> = LazyLock::new(|| {
        let mut inst = opcua::types::TypeLoaderInstance::new();
        inst.add_binary_type(1, 2, binary_decode_to_enc::<MyUnion>);
        inst.add_json_type(1, 3, json_decode_to_enc::<MyUnion>);
        inst.add_xml_type(1, 4, xml_decode_to_enc::<MyUnion>);
        inst
    });

    pub(crate) struct MyUnionTypeLoader;

    impl StaticTypeLoader for MyUnionTypeLoader {
        fn instance() -> &'static TypeLoaderInstance {
            &TYPES
        }

        fn namespace() -> &'static str {
            TYPE_NAMESPACE
        }
    }

    #[test]
    fn union_round_trip() {
        let ctx = get_custom_union();

        let mut write_buf = Vec::<u8>::new();
        let mut cursor = Cursor::new(&mut write_buf);

        let obj = ExtensionObject::from_message(MyUnion::Integer(123));

        // Encode the object, using the regular BinaryEncodable implementation
        BinaryEncodable::encode(&obj, &mut cursor, &ctx.context()).unwrap();
        cursor.seek(std::io::SeekFrom::Start(0)).unwrap();

        let obj2: ExtensionObject = BinaryDecodable::decode(&mut cursor, &ctx.context()).unwrap();

        // Decode it back, resulting in a dynamic structure.
        let value = obj2.inner_as::<DynamicStructure>().unwrap();
        assert_eq!(value.data.len(), 1);

        assert_eq!(value.data[0], Variant::from(123i32));
        assert_eq!(value.discriminant, 1);

        cursor.seek(std::io::SeekFrom::Start(0)).unwrap();
        BinaryEncodable::encode(&obj2, &mut cursor, &ctx.context()).unwrap();

        // Make a new context, this time with the regular decoder for MyUnion
        let mut ctx = ContextOwned::new_default(get_namespaces(), DecodingOptions::test());
        ctx.loaders_mut().add_type_loader(MyUnionTypeLoader);
        cursor.seek(std::io::SeekFrom::Start(0)).unwrap();
        let obj3: ExtensionObject = BinaryDecodable::decode(&mut cursor, &ctx.context()).unwrap();

        assert_eq!(obj, obj3);
    }

    #[test]
    fn union_null() {
        let ctx = get_custom_union();

        let mut write_buf = Vec::<u8>::new();
        let mut cursor = Cursor::new(&mut write_buf);

        let obj = ExtensionObject::from_message(MyUnion::Null);

        // Encode the object, using the regular BinaryEncodable implementation
        BinaryEncodable::encode(&obj, &mut cursor, &ctx.context()).unwrap();
        cursor.seek(std::io::SeekFrom::Start(0)).unwrap();

        let obj2: ExtensionObject = BinaryDecodable::decode(&mut cursor, &ctx.context()).unwrap();

        // Decode it back, resulting in a dynamic structure.
        let value = obj2.inner_as::<DynamicStructure>().unwrap();
        assert_eq!(value.data.len(), 0);
        assert_eq!(value.discriminant, 0);

        cursor.seek(std::io::SeekFrom::Start(0)).unwrap();
        BinaryEncodable::encode(&obj2, &mut cursor, &ctx.context()).unwrap();

        // Make a new context, this time with the regular decoder for MyUnion
        let mut ctx = ContextOwned::new_default(get_namespaces(), DecodingOptions::test());
        ctx.loaders_mut().add_type_loader(MyUnionTypeLoader);
        cursor.seek(std::io::SeekFrom::Start(0)).unwrap();
        let obj3: ExtensionObject = BinaryDecodable::decode(&mut cursor, &ctx.context()).unwrap();

        assert_eq!(obj, obj3);
    }
}
