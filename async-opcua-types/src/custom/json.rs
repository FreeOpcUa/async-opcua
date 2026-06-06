use std::{collections::HashMap, io::Write, sync::Arc};

use crate::{
    json::{JsonDecodable, JsonEncodable, JsonReader, JsonStreamWriter, JsonWriter},
    Array, ByteString, Context, DataValue, DateTime, DiagnosticInfo, DynEncodable, EncodingResult,
    Error, ExpandedNodeId, ExtensionObject, Guid, LocalizedText, NodeId, QualifiedName, StatusCode,
    StructureType, UAString, Variant, XmlElement,
};

use super::{
    custom_struct::{DynamicStructure, DynamicTypeLoader},
    type_tree::{ParsedStructureField, StructTypeInfo},
};

impl DynamicStructure {
    fn json_encode_array(
        &self,
        stream: &mut JsonStreamWriter<&mut dyn Write>,
        field: &ParsedStructureField,
        ctx: &Context<'_>,
        items: &[Variant],
        remaining_dims: &[u32],
        index: &mut usize,
    ) -> EncodingResult<()> {
        if remaining_dims.len() == 1 {
            stream.begin_array()?;
            for _ in 0..remaining_dims[0] {
                self.json_encode_field(
                    stream,
                    items.get(*index).unwrap_or(&Variant::Empty),
                    field,
                    ctx,
                )?;
                *index += 1;
            }
            stream.end_array()?;
        } else {
            stream.begin_array()?;
            for _ in 0..remaining_dims[0] {
                self.json_encode_array(stream, field, ctx, items, &remaining_dims[1..], index)?;
            }
            stream.end_array()?;
        }

        Ok(())
    }

    fn json_encode_field(
        &self,
        stream: &mut JsonStreamWriter<&mut dyn Write>,
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
                    body.encode_json(stream, ctx)
                }
            }
            Variant::Array(a) => {
                if field.value_rank > 1 {
                    let Some(dims) = &a.dimensions else {
                        return Err(Error::encoding(
                            "ArrayDimensions are required for fields with value rank > 1",
                        ));
                    };
                    if dims.len() as i32 != field.value_rank {
                        return Err(Error::encoding(
                            "ArrayDimensions must have length equal to field valuerank",
                        ));
                    }
                    let mut index = 0;
                    self.json_encode_array(stream, field, ctx, &a.values, dims, &mut index)?;
                } else {
                    stream.begin_array()?;
                    for value in a.values.iter() {
                        self.json_encode_field(stream, value, field, ctx)?;
                    }
                    stream.end_array()?;
                }

                Ok(())
            }
            r => r.serialize_variant_value(stream, ctx),
        }
    }
}

impl DynamicTypeLoader {
    fn json_decode_field_value(
        &self,
        field: &ParsedStructureField,
        stream: &mut crate::json::JsonStreamReader<&mut dyn std::io::Read>,
        ctx: &crate::Context<'_>,
    ) -> EncodingResult<Variant> {
        match field.scalar_type {
            crate::VariantScalarTypeId::Boolean => {
                Ok(Variant::from(<bool as JsonDecodable>::decode(stream, ctx)?))
            }
            crate::VariantScalarTypeId::SByte => {
                Ok(Variant::from(<i8 as JsonDecodable>::decode(stream, ctx)?))
            }
            crate::VariantScalarTypeId::Byte => {
                Ok(Variant::from(<u8 as JsonDecodable>::decode(stream, ctx)?))
            }
            crate::VariantScalarTypeId::Int16 => {
                Ok(Variant::from(<i16 as JsonDecodable>::decode(stream, ctx)?))
            }
            crate::VariantScalarTypeId::UInt16 => {
                Ok(Variant::from(<u16 as JsonDecodable>::decode(stream, ctx)?))
            }
            crate::VariantScalarTypeId::Int32 => {
                Ok(Variant::from(<i32 as JsonDecodable>::decode(stream, ctx)?))
            }
            crate::VariantScalarTypeId::UInt32 => {
                Ok(Variant::from(<u32 as JsonDecodable>::decode(stream, ctx)?))
            }
            crate::VariantScalarTypeId::Int64 => {
                Ok(Variant::from(<i64 as JsonDecodable>::decode(stream, ctx)?))
            }
            crate::VariantScalarTypeId::UInt64 => {
                Ok(Variant::from(<u64 as JsonDecodable>::decode(stream, ctx)?))
            }
            crate::VariantScalarTypeId::Float => {
                Ok(Variant::from(<f32 as JsonDecodable>::decode(stream, ctx)?))
            }
            crate::VariantScalarTypeId::Double => {
                Ok(Variant::from(<f64 as JsonDecodable>::decode(stream, ctx)?))
            }
            crate::VariantScalarTypeId::String => Ok(Variant::from(
                <UAString as JsonDecodable>::decode(stream, ctx)?,
            )),
            crate::VariantScalarTypeId::DateTime => Ok(Variant::from(
                <DateTime as JsonDecodable>::decode(stream, ctx)?,
            )),
            crate::VariantScalarTypeId::Guid => {
                Ok(Variant::from(<Guid as JsonDecodable>::decode(stream, ctx)?))
            }
            crate::VariantScalarTypeId::ByteString => Ok(Variant::from(
                <ByteString as JsonDecodable>::decode(stream, ctx)?,
            )),
            crate::VariantScalarTypeId::XmlElement => Ok(Variant::from(
                <XmlElement as JsonDecodable>::decode(stream, ctx)?,
            )),
            crate::VariantScalarTypeId::NodeId => Ok(Variant::from(
                <NodeId as JsonDecodable>::decode(stream, ctx)?,
            )),
            crate::VariantScalarTypeId::ExpandedNodeId => Ok(Variant::from(
                <ExpandedNodeId as JsonDecodable>::decode(stream, ctx)?,
            )),
            crate::VariantScalarTypeId::StatusCode => Ok(Variant::from(
                <StatusCode as JsonDecodable>::decode(stream, ctx)?,
            )),
            crate::VariantScalarTypeId::QualifiedName => Ok(Variant::from(
                <QualifiedName as JsonDecodable>::decode(stream, ctx)?,
            )),
            crate::VariantScalarTypeId::LocalizedText => Ok(Variant::from(
                <LocalizedText as JsonDecodable>::decode(stream, ctx)?,
            )),
            crate::VariantScalarTypeId::ExtensionObject => {
                let Some(field_ty) = self.type_tree.get_struct_type(&field.type_id) else {
                    return Err(Error::decoding(format!(
                        "Dynamic type field missing from type tree: {}",
                        field.type_id
                    )));
                };

                if field_ty.is_abstract {
                    Ok(Variant::from(<ExtensionObject as JsonDecodable>::decode(
                        stream, ctx,
                    )?))
                } else {
                    Ok(Variant::from(
                        ctx.load_from_json(&field_ty.node_id, stream)?,
                    ))
                }
            }
            crate::VariantScalarTypeId::DataValue => Ok(Variant::from(
                <DataValue as JsonDecodable>::decode(stream, ctx)?,
            )),
            crate::VariantScalarTypeId::Variant => Ok(Variant::Variant(Box::new(
                <Variant as JsonDecodable>::decode(stream, ctx)?,
            ))),
            crate::VariantScalarTypeId::DiagnosticInfo => Ok(Variant::from(
                <DiagnosticInfo as JsonDecodable>::decode(stream, ctx)?,
            )),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn json_decode_array(
        &self,
        field: &ParsedStructureField,
        stream: &mut crate::json::JsonStreamReader<&mut dyn std::io::Read>,
        ctx: &Context<'_>,
        value_rank: i32,
        depth: i32,
        values: &mut Vec<Variant>,
        dims: &mut Vec<u32>,
    ) -> EncodingResult<()> {
        let mut size = 0;
        stream.begin_array()?;
        if value_rank > depth {
            while stream.has_next()? {
                size += 1;
                self.json_decode_array(field, stream, ctx, value_rank, depth + 1, values, dims)?;
            }
        } else {
            while stream.has_next()? {
                size += 1;
                values.push(self.json_decode_field_value(field, stream, ctx)?);
            }
        }
        let old_dim = dims[depth as usize - 1];
        if old_dim > 0 && size != old_dim {
            return Err(Error::decoding(format!(
                "JSON matrix in field {} does not have even dimensions",
                field.name
            )));
        } else if old_dim == 0 {
            dims[depth as usize - 1] = size;
        }
        stream.end_array()?;

        Ok(())
    }

    fn json_decode_field(
        &self,
        field: &ParsedStructureField,
        stream: &mut crate::json::JsonStreamReader<&mut dyn std::io::Read>,
        ctx: &Context<'_>,
    ) -> EncodingResult<Variant> {
        if field.value_rank > 0 {
            let mut values = Vec::new();
            let mut dims = vec![0u32; field.value_rank as usize];
            self.json_decode_array(
                field,
                stream,
                ctx,
                field.value_rank,
                1,
                &mut values,
                &mut dims,
            )?;

            if dims.len() > 1 {
                Ok(Variant::Array(Box::new(
                    Array::new_multi(field.scalar_type, values, dims).map_err(Error::decoding)?,
                )))
            } else {
                Ok(Variant::Array(Box::new(
                    Array::new(field.scalar_type, values).map_err(Error::decoding)?,
                )))
            }
        } else {
            self.json_decode_field_value(field, stream, ctx)
        }
    }

    pub(super) fn json_decode_type_inner(
        &self,
        stream: &mut crate::json::JsonStreamReader<&mut dyn std::io::Read>,
        ctx: &Context<'_>,
        t: &Arc<StructTypeInfo>,
    ) -> EncodingResult<Box<dyn DynEncodable>> {
        match t.structure_type {
            crate::StructureType::Structure | crate::StructureType::StructureWithOptionalFields => {
                let mut by_name = HashMap::new();
                stream.begin_object()?;
                while stream.has_next()? {
                    let name = stream.next_name()?;
                    let Some(field) = t.get_field_by_name(name) else {
                        stream.skip_value()?;
                        continue;
                    };
                    by_name.insert(
                        field.name.as_str(),
                        self.json_decode_field(field, stream, ctx)?,
                    );
                }
                let mut data = Vec::with_capacity(by_name.len());
                for field in &t.fields {
                    let Some(f) = by_name.remove(field.name.as_str()) else {
                        // Just ignore decoding mask here, there really is no reason
                        // to care about it when it comes to JSON decoding.
                        if field.is_optional {
                            data.push(Variant::Empty);
                            continue;
                        }
                        return Err(Error::decoding(format!(
                            "Missing required field {}",
                            field.name
                        )));
                    };
                    data.push(f);
                }
                stream.end_object()?;

                Ok(Box::new(DynamicStructure {
                    type_def: t.clone(),
                    discriminant: 0,
                    type_tree: self.type_tree.clone(),
                    data,
                }))
            }
            crate::StructureType::Union => {
                let mut value: Option<Variant> = None;
                let mut discriminant: Option<u32> = None;

                stream.begin_object()?;
                while stream.has_next()? {
                    let name = stream.next_name()?;
                    match name {
                        "SwitchField" => {
                            discriminant = Some(stream.next_number()??);
                        }
                        r => {
                            let Some((idx, value_field)) =
                                t.fields.iter().enumerate().find(|(_, f)| f.name == r)
                            else {
                                stream.skip_value()?;
                                continue;
                            };
                            // If we've read the discriminant, double check that it matches the field name.
                            // OPC-UA unions are really only allowed to have two fields, but we can try to handle
                            // weird payloads anyway.
                            // Technically doesn't handle cases where there are multiple options _and_ the discriminant
                            // is late, but that violates the standard so it's probably fine.
                            if discriminant.is_some_and(|d| d != (idx + 1) as u32) {
                                stream.skip_value()?;
                            } else {
                                value = Some(self.json_decode_field(value_field, stream, ctx)?);
                                discriminant = Some((idx + 1) as u32);
                            }
                        }
                    }
                }

                let (Some(value), Some(discriminant)) = (value, discriminant) else {
                    return Ok(Box::new(DynamicStructure::new_null_union(
                        t.clone(),
                        self.type_tree.clone(),
                    )));
                };

                if discriminant == 0 {
                    return Ok(Box::new(DynamicStructure::new_null_union(
                        t.clone(),
                        self.type_tree.clone(),
                    )));
                }

                Ok(Box::new(DynamicStructure {
                    type_def: t.clone(),
                    discriminant,
                    type_tree: self.type_tree.clone(),
                    data: vec![value],
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

impl JsonEncodable for DynamicStructure {
    fn encode(
        &self,
        stream: &mut crate::json::JsonStreamWriter<&mut dyn std::io::Write>,
        ctx: &crate::Context<'_>,
    ) -> crate::EncodingResult<()> {
        let s = &self.type_def;
        stream.begin_object()?;
        match s.structure_type {
            crate::StructureType::Structure => {
                for (value, field) in self.data.iter().zip(s.fields.iter()) {
                    stream.name(&field.name)?;
                    self.json_encode_field(stream, value, field, ctx)?;
                }
            }
            crate::StructureType::StructureWithOptionalFields => {
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
                stream.name("EncodingMask")?;
                stream.number_value(encoding_mask)?;

                for (value, field) in self.data.iter().zip(s.fields.iter()) {
                    if !field.is_optional || !matches!(value, Variant::Empty) {
                        stream.name(&field.name)?;
                        self.json_encode_field(stream, value, field, ctx)?;
                    }
                }
            }
            crate::StructureType::Union => {
                if self.discriminant != 0 {
                    stream.name("SwitchField")?;
                    stream.number_value(self.discriminant)?;

                    let (Some(value), Some(field)) = (
                        self.data.first(),
                        s.fields.get((self.discriminant - 1) as usize),
                    ) else {
                        return Err(Error::encoding(
                            "Discriminant was out of range of known fields",
                        ));
                    };
                    stream.name(&field.name)?;
                    self.json_encode_field(stream, value, field, ctx)?;
                }
            }

            StructureType::StructureWithSubtypedValues => {
                todo!("StructureWithSubtypedValues is unsupported")
            }
            StructureType::UnionWithSubtypedValues => {
                todo!("UnionWithSubtypedValues is unsupported")
            }
        }
        stream.end_object()?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Cursor, Read, Seek, Write},
        sync::Arc,
    };

    use crate::{
        custom::custom_struct::tests::{
            get_custom_union, get_namespaces, MyUnion, MyUnionTypeLoader,
        },
        json::{JsonDecodable, JsonEncodable, JsonStreamReader, JsonStreamWriter, JsonWriter},
        Array, ContextOwned, DataTypeDefinition, DataTypeId, DecodingOptions, EUInformation,
        ExtensionObject, LocalizedText, NamespaceMap, NodeId, StructureDefinition, StructureField,
        TypeLoaderCollection, Variant, VariantScalarTypeId,
    };

    use crate::custom::{
        custom_struct::tests::{add_eu_information, make_type_tree},
        type_tree::TypeInfo,
        DynamicStructure, DynamicTypeLoader, EncodingIds,
    };

    #[test]
    fn json_dynamic_struct_round_trip() {
        let mut type_tree = make_type_tree();
        add_eu_information(&mut type_tree);

        let loader = DynamicTypeLoader::new(Arc::new(type_tree));
        let mut loaders = TypeLoaderCollection::new_empty();
        loaders.add_type_loader(loader);
        let ctx = ContextOwned::new(NamespaceMap::new(), loaders, DecodingOptions::test());

        let mut write_buf = Vec::<u8>::new();
        let mut cursor = Cursor::new(&mut write_buf);
        let mut writer = JsonStreamWriter::new(&mut cursor as &mut dyn Write);

        let obj = ExtensionObject::from_message(EUInformation {
            namespace_uri: "my.namespace.uri".into(),
            unit_id: 5,
            display_name: "Degrees Celsius".into(),
            description: "Description".into(),
        });

        JsonEncodable::encode(&obj, &mut writer, &ctx.context()).unwrap();
        writer.finish_document().unwrap();
        cursor.seek(std::io::SeekFrom::Start(0)).unwrap();

        let mut reader = JsonStreamReader::new(&mut cursor as &mut dyn Read);

        let obj2: ExtensionObject = JsonDecodable::decode(&mut reader, &ctx.context()).unwrap();

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
        let mut writer = JsonStreamWriter::new(&mut cursor as &mut dyn Write);
        JsonEncodable::encode(&obj2, &mut writer, &ctx.context()).unwrap();
        writer.finish_document().unwrap();

        // Make a new context, this time with the regular decoder for EUInformation
        let ctx = ContextOwned::new_default(NamespaceMap::new(), DecodingOptions::test());
        cursor.seek(std::io::SeekFrom::Start(0)).unwrap();
        let mut reader = JsonStreamReader::new(&mut cursor as &mut dyn Read);
        let obj3: ExtensionObject = JsonDecodable::decode(&mut reader, &ctx.context()).unwrap();

        assert_eq!(obj, obj3);
    }

    #[test]
    fn json_dynamic_nested_struct_round_trip() {
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
                "EUInformation".to_owned(),
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
        let mut writer = JsonStreamWriter::new(&mut cursor as &mut dyn Write);

        JsonEncodable::encode(&obj, &mut writer, &ctx.context()).unwrap();
        writer.finish_document().unwrap();

        cursor.seek(std::io::SeekFrom::Start(0)).unwrap();

        let mut reader = JsonStreamReader::new(&mut cursor as &mut dyn Read);
        let obj2: ExtensionObject = JsonDecodable::decode(&mut reader, &ctx.context()).unwrap();

        assert_eq!(obj, obj2);
    }

    #[test]
    fn union_round_trip() {
        let ctx = get_custom_union();

        let mut write_buf = Vec::<u8>::new();
        let mut cursor = Cursor::new(&mut write_buf);

        let obj = ExtensionObject::from_message(MyUnion::Integer(123));

        let mut writer = JsonStreamWriter::new(&mut cursor as &mut dyn Write);

        // Encode the object, using the regular JsonEncodable implementation
        JsonEncodable::encode(&obj, &mut writer, &ctx.context()).unwrap();
        writer.finish_document().unwrap();
        cursor.seek(std::io::SeekFrom::Start(0)).unwrap();

        let mut reader = JsonStreamReader::new(&mut cursor as &mut dyn Read);

        let obj2: ExtensionObject = JsonDecodable::decode(&mut reader, &ctx.context()).unwrap();

        // Decode it back, resulting in a dynamic structure.
        let value = obj2.inner_as::<DynamicStructure>().unwrap();
        assert_eq!(value.data.len(), 1);

        assert_eq!(value.data[0], Variant::from(123i32));
        assert_eq!(value.discriminant, 1);

        cursor.seek(std::io::SeekFrom::Start(0)).unwrap();
        let mut writer = JsonStreamWriter::new(&mut cursor as &mut dyn Write);
        JsonEncodable::encode(&obj2, &mut writer, &ctx.context()).unwrap();
        writer.finish_document().unwrap();

        // Make a new context, this time with the regular decoder for MyUnion
        let mut ctx = ContextOwned::new_default(get_namespaces(), DecodingOptions::test());
        ctx.loaders_mut().add_type_loader(MyUnionTypeLoader);
        cursor.seek(std::io::SeekFrom::Start(0)).unwrap();
        let mut reader = JsonStreamReader::new(&mut cursor as &mut dyn Read);
        let obj3: ExtensionObject = JsonDecodable::decode(&mut reader, &ctx.context()).unwrap();

        assert_eq!(obj, obj3);
    }
}
