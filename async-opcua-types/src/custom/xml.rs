use std::{collections::HashMap, io::Write, sync::Arc};

use crate::{
    xml::*, Array, ByteString, DataValue, DateTime, DiagnosticInfo, DynEncodable, ExpandedNodeId,
    ExtensionObject, Guid, LocalizedText, NodeId, QualifiedName, StatusCode, StructureType,
    UAString, Variant, VariantScalarTypeId, XmlElement,
};

use super::{DynamicStructure, DynamicTypeLoader, ParsedStructureField, StructTypeInfo};

impl XmlType for DynamicStructure {
    // Should never be used, kept as a fallback.
    const TAG: &'static str = "Unknown";
    fn tag(&self) -> &str {
        &self.type_def.name
    }
}

impl DynamicStructure {
    fn xml_encode_field(
        &self,
        stream: &mut XmlStreamWriter<&mut dyn Write>,
        f: &Variant,
        field: &ParsedStructureField,
        ctx: &Context<'_>,
    ) -> EncodingResult<()> {
        stream.write_start(&field.name)?;
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
                    body.encode_xml(stream, ctx)
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
                    // For some incredibly annoying reason, OPC-UA insists that dimensions be
                    // encoded as _signed_ integers. For other encoders it's irrelevant,
                    // but it matters for XML.
                    let dims: Vec<_> = dims.iter().map(|d| *d as i32).collect();
                    stream.encode_child("Dimensions", &dims, ctx)?;

                    stream.write_start("Elements")?;
                    for item in &a.values {
                        self.xml_encode_field(stream, item, field, ctx)?;
                    }
                    stream.write_end("Elements")?;
                } else {
                    for item in &a.values {
                        self.xml_encode_field(stream, item, field, ctx)?;
                    }
                }
                Ok(())
            }
            Variant::Empty => Ok(()),
            Variant::Boolean(v) => v.encode(stream, ctx),
            Variant::SByte(v) => v.encode(stream, ctx),
            Variant::Byte(v) => v.encode(stream, ctx),
            Variant::Int16(v) => v.encode(stream, ctx),
            Variant::UInt16(v) => v.encode(stream, ctx),
            Variant::Int32(v) => v.encode(stream, ctx),
            Variant::UInt32(v) => v.encode(stream, ctx),
            Variant::Int64(v) => v.encode(stream, ctx),
            Variant::UInt64(v) => v.encode(stream, ctx),
            Variant::Float(v) => v.encode(stream, ctx),
            Variant::Double(v) => v.encode(stream, ctx),
            Variant::String(v) => v.encode(stream, ctx),
            Variant::DateTime(v) => v.encode(stream, ctx),
            Variant::Guid(v) => v.encode(stream, ctx),
            Variant::StatusCode(v) => v.encode(stream, ctx),
            Variant::ByteString(v) => v.encode(stream, ctx),
            Variant::XmlElement(v) => v.encode(stream, ctx),
            Variant::QualifiedName(v) => v.encode(stream, ctx),
            Variant::LocalizedText(v) => v.encode(stream, ctx),
            Variant::NodeId(v) => v.encode(stream, ctx),
            Variant::ExpandedNodeId(v) => v.encode(stream, ctx),
            Variant::Variant(v) => v.encode(stream, ctx),
            Variant::DataValue(v) => v.encode(stream, ctx),
            Variant::DiagnosticInfo(v) => v.encode(stream, ctx),
        }?;
        stream.write_end(&field.name)?;
        Ok(())
    }
}

impl DynamicTypeLoader {
    fn xml_decode_field_value(
        &self,
        field: &ParsedStructureField,
        stream: &mut crate::xml::XmlStreamReader<&mut dyn std::io::Read>,
        ctx: &Context<'_>,
    ) -> EncodingResult<Variant> {
        match field.scalar_type {
            VariantScalarTypeId::Boolean => {
                Ok(Variant::from(<bool as XmlDecodable>::decode(stream, ctx)?))
            }
            VariantScalarTypeId::SByte => {
                Ok(Variant::from(<i8 as XmlDecodable>::decode(stream, ctx)?))
            }
            VariantScalarTypeId::Byte => {
                Ok(Variant::from(<u8 as XmlDecodable>::decode(stream, ctx)?))
            }
            VariantScalarTypeId::Int16 => {
                Ok(Variant::from(<i16 as XmlDecodable>::decode(stream, ctx)?))
            }
            VariantScalarTypeId::UInt16 => {
                Ok(Variant::from(<u16 as XmlDecodable>::decode(stream, ctx)?))
            }
            VariantScalarTypeId::Int32 => {
                Ok(Variant::from(<i32 as XmlDecodable>::decode(stream, ctx)?))
            }
            VariantScalarTypeId::UInt32 => {
                Ok(Variant::from(<u32 as XmlDecodable>::decode(stream, ctx)?))
            }
            VariantScalarTypeId::Int64 => {
                Ok(Variant::from(<i64 as XmlDecodable>::decode(stream, ctx)?))
            }
            VariantScalarTypeId::UInt64 => {
                Ok(Variant::from(<u64 as XmlDecodable>::decode(stream, ctx)?))
            }
            VariantScalarTypeId::Float => {
                Ok(Variant::from(<f32 as XmlDecodable>::decode(stream, ctx)?))
            }
            VariantScalarTypeId::Double => {
                Ok(Variant::from(<f64 as XmlDecodable>::decode(stream, ctx)?))
            }
            VariantScalarTypeId::String => Ok(Variant::from(<UAString as XmlDecodable>::decode(
                stream, ctx,
            )?)),
            VariantScalarTypeId::DateTime => Ok(Variant::from(<DateTime as XmlDecodable>::decode(
                stream, ctx,
            )?)),
            VariantScalarTypeId::Guid => {
                Ok(Variant::from(<Guid as XmlDecodable>::decode(stream, ctx)?))
            }
            VariantScalarTypeId::ByteString => Ok(Variant::from(
                <ByteString as XmlDecodable>::decode(stream, ctx)?,
            )),
            VariantScalarTypeId::XmlElement => Ok(Variant::from(
                <XmlElement as XmlDecodable>::decode(stream, ctx)?,
            )),
            VariantScalarTypeId::NodeId => Ok(Variant::from(<NodeId as XmlDecodable>::decode(
                stream, ctx,
            )?)),
            VariantScalarTypeId::ExpandedNodeId => Ok(Variant::from(
                <ExpandedNodeId as XmlDecodable>::decode(stream, ctx)?,
            )),
            VariantScalarTypeId::StatusCode => Ok(Variant::from(
                <StatusCode as XmlDecodable>::decode(stream, ctx)?,
            )),
            VariantScalarTypeId::QualifiedName => Ok(Variant::from(
                <QualifiedName as XmlDecodable>::decode(stream, ctx)?,
            )),
            VariantScalarTypeId::LocalizedText => Ok(Variant::from(
                <LocalizedText as XmlDecodable>::decode(stream, ctx)?,
            )),
            VariantScalarTypeId::ExtensionObject => {
                let Some(field_ty) = self.type_tree.get_struct_type(&field.type_id) else {
                    return Err(Error::decoding(format!(
                        "Dynamic type field missing from type tree: {}",
                        field.type_id
                    )));
                };

                if field_ty.is_abstract {
                    Ok(Variant::from(<ExtensionObject as XmlDecodable>::decode(
                        stream, ctx,
                    )?))
                } else {
                    Ok(Variant::from(ctx.load_from_xml(&field_ty.node_id, stream)?))
                }
            }
            VariantScalarTypeId::DataValue => Ok(Variant::from(
                <DataValue as XmlDecodable>::decode(stream, ctx)?,
            )),
            VariantScalarTypeId::Variant => Ok(Variant::Variant(Box::new(
                <Variant as XmlDecodable>::decode(stream, ctx)?,
            ))),
            VariantScalarTypeId::DiagnosticInfo => Ok(Variant::from(
                <DiagnosticInfo as XmlDecodable>::decode(stream, ctx)?,
            )),
        }
    }

    fn xml_decode_field(
        &self,
        field: &ParsedStructureField,
        stream: &mut crate::xml::XmlStreamReader<&mut dyn std::io::Read>,
        ctx: &Context<'_>,
    ) -> EncodingResult<Variant> {
        if field.value_rank > 1 {
            let mut values = Vec::new();
            let mut dims = Vec::new();
            stream.iter_children(
                |key, stream, ctx| {
                    match key.as_str() {
                        "Dimensions" => {
                            dims = Vec::<i32>::decode(stream, ctx)?;
                        }
                        "Elements" => stream.iter_children_include_empty(
                            |_, stream, ctx| {
                                let Some(stream) = stream else {
                                    values.push(Variant::get_variant_default(field.scalar_type));
                                    return Ok(());
                                };
                                let r = self.xml_decode_field_value(field, stream, ctx)?;
                                values.push(r);
                                Ok(())
                            },
                            ctx,
                        )?,
                        r => {
                            return Err(Error::decoding(format!(
                                "Invalid field in Matrix content: {r}"
                            )))
                        }
                    }
                    Ok(())
                },
                ctx,
            )?;
            Ok(Variant::Array(Box::new(
                Array::new_multi(
                    field.scalar_type,
                    values,
                    dims.into_iter()
                        .map(|d| d.try_into())
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(|_| {
                            Error::decoding("Invalid array dimensions, must all be non-negative")
                        })?,
                )
                .map_err(Error::decoding)?,
            )))
        } else if field.value_rank > 0 {
            let mut values = Vec::new();
            stream.iter_children_include_empty(
                |_, stream, ctx| {
                    let Some(stream) = stream else {
                        values.push(Variant::get_variant_default(field.scalar_type));
                        return Ok(());
                    };
                    let r = self.xml_decode_field_value(field, stream, ctx)?;
                    values.push(r);
                    Ok(())
                },
                ctx,
            )?;
            Ok(Variant::Array(Box::new(
                Array::new(field.scalar_type, values).map_err(Error::decoding)?,
            )))
        } else {
            self.xml_decode_field_value(field, stream, ctx)
        }
    }

    pub(super) fn xml_decode_type_inner(
        &self,
        stream: &mut crate::xml::XmlStreamReader<&mut dyn std::io::Read>,
        ctx: &Context<'_>,
        t: &Arc<StructTypeInfo>,
    ) -> EncodingResult<Box<dyn DynEncodable>> {
        match t.structure_type {
            StructureType::Structure | StructureType::StructureWithOptionalFields => {
                let mut by_name = HashMap::new();
                stream.iter_children(
                    |key, stream, ctx| {
                        let Some(field) = t.get_field_by_name(&key) else {
                            stream.skip_value()?;
                            return Ok(());
                        };
                        by_name.insert(
                            field.name.as_str(),
                            self.xml_decode_field(field, stream, ctx)?,
                        );
                        Ok(())
                    },
                    ctx,
                )?;

                let mut data = Vec::with_capacity(by_name.len());
                for field in &t.fields {
                    let Some(f) = by_name.remove(field.name.as_str()) else {
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

                Ok(Box::new(DynamicStructure {
                    type_def: t.clone(),
                    discriminant: 0,
                    type_tree: self.type_tree.clone(),
                    data,
                }))
            }
            StructureType::Union => {
                let mut value: Option<Variant> = None;
                let mut discriminant: Option<u32> = None;

                stream.iter_children(
                    |key, stream, ctx| {
                        match key.as_str() {
                            "SwitchField" => {
                                discriminant = Some(u32::decode(stream, ctx)?);
                            }
                            r => {
                                let Some((idx, value_field)) =
                                    t.fields.iter().enumerate().find(|(_, f)| f.name == r)
                                else {
                                    stream.skip_value()?;
                                    return Ok(());
                                };

                                // If we've read the discriminant, double check that it matches the field name.
                                // OPC-UA unions are really only allowed to have two fields, but we can try to handle
                                // weird payloads anyway.
                                // Technically doesn't handle cases where there are multiple options _and_ the discriminant
                                // is late, but that violates the standard so it's probably fine.
                                if discriminant.is_some_and(|d| d != (idx + 1) as u32) {
                                    stream.skip_value()?;
                                } else {
                                    value =
                                        Some(self.xml_decode_field(value_field, stream, ctx)?);
                                    discriminant = Some((idx + 1) as u32);
                                }
                            }
                        }
                        Ok(())
                    },
                    ctx,
                )?;

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

impl XmlEncodable for DynamicStructure {
    fn encode(
        &self,
        stream: &mut XmlStreamWriter<&mut dyn std::io::Write>,
        ctx: &Context<'_>,
    ) -> EncodingResult<()> {
        let s = &self.type_def;
        match s.structure_type {
            StructureType::Structure => {
                for (value, field) in self.data.iter().zip(s.fields.iter()) {
                    self.xml_encode_field(stream, value, field, ctx)?;
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
                stream.encode_child("EncodingMask", &encoding_mask, ctx)?;
                for (value, field) in self.data.iter().zip(s.fields.iter()) {
                    if !field.is_optional || !matches!(value, Variant::Empty) {
                        self.xml_encode_field(stream, value, field, ctx)?;
                    }
                }
            }
            StructureType::Union => {
                stream.encode_child("SwitchField", &self.discriminant, ctx)?;
                let (Some(value), Some(field)) = (
                    self.data.first(),
                    s.fields.get(self.discriminant as usize - 1),
                ) else {
                    return Err(Error::encoding(
                        "Discriminant was out of range of known fields",
                    ));
                };
                self.xml_encode_field(stream, value, field, ctx)?;
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
        xml::*,
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
    fn xml_dynamic_struct_round_trip() {
        let mut type_tree = make_type_tree();
        add_eu_information(&mut type_tree);

        let loader = DynamicTypeLoader::new(Arc::new(type_tree));
        let mut loaders = TypeLoaderCollection::new_empty();
        loaders.add_type_loader(loader);
        let ctx = ContextOwned::new(NamespaceMap::new(), loaders, DecodingOptions::test());

        let mut write_buf = Vec::<u8>::new();
        let mut cursor = Cursor::new(&mut write_buf);
        let mut writer = XmlStreamWriter::new(&mut cursor as &mut dyn Write);

        let obj = ExtensionObject::from_message(EUInformation {
            namespace_uri: "my.namespace.uri".into(),
            unit_id: 5,
            display_name: "Degrees Celsius".into(),
            description: "Description".into(),
        });

        XmlEncodable::encode(&obj, &mut writer, &ctx.context()).unwrap();
        cursor.seek(std::io::SeekFrom::Start(0)).unwrap();

        let mut reader = XmlStreamReader::new(&mut cursor as &mut dyn Read);

        let obj2: ExtensionObject = XmlDecodable::decode(&mut reader, &ctx.context()).unwrap();

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
        let mut writer = XmlStreamWriter::new(&mut cursor as &mut dyn Write);
        XmlEncodable::encode(&obj2, &mut writer, &ctx.context()).unwrap();

        // Make a new context, this time with the regular decoder for EUInformation
        let ctx = ContextOwned::new_default(NamespaceMap::new(), DecodingOptions::test());
        cursor.seek(std::io::SeekFrom::Start(0)).unwrap();
        let mut reader = XmlStreamReader::new(&mut cursor as &mut dyn Read);
        let obj3: ExtensionObject = XmlDecodable::decode(&mut reader, &ctx.context()).unwrap();

        assert_eq!(obj, obj3);
    }

    #[test]
    fn xml_dynamic_nested_struct_round_trip() {
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
        let mut writer = XmlStreamWriter::new(&mut cursor as &mut dyn Write);

        XmlEncodable::encode(&obj, &mut writer, &ctx.context()).unwrap();

        cursor.seek(std::io::SeekFrom::Start(0)).unwrap();

        println!("{}", std::str::from_utf8(&cursor.get_ref()).unwrap());

        let mut reader = XmlStreamReader::new(&mut cursor as &mut dyn Read);
        let obj2: ExtensionObject = XmlDecodable::decode(&mut reader, &ctx.context()).unwrap();

        assert_eq!(obj, obj2);
    }

    #[test]
    fn union_round_trip() {
        let ctx = get_custom_union();

        let mut write_buf = Vec::<u8>::new();
        let mut cursor = Cursor::new(&mut write_buf);

        let obj = ExtensionObject::from_message(MyUnion::Integer(123));

        let mut writer = XmlStreamWriter::new(&mut cursor as &mut dyn Write);

        // Encode the object, using the regular XmlEncodable implementation
        XmlEncodable::encode(&obj, &mut writer, &ctx.context()).unwrap();
        cursor.seek(std::io::SeekFrom::Start(0)).unwrap();

        let mut reader = XmlStreamReader::new(&mut cursor as &mut dyn Read);

        let obj2: ExtensionObject = XmlDecodable::decode(&mut reader, &ctx.context()).unwrap();

        // Decode it back, resulting in a dynamic structure.
        let value = obj2.inner_as::<DynamicStructure>().unwrap();
        assert_eq!(value.data.len(), 1);

        assert_eq!(value.data[0], Variant::from(123i32));
        assert_eq!(value.discriminant, 1);

        cursor.seek(std::io::SeekFrom::Start(0)).unwrap();
        let mut writer = XmlStreamWriter::new(&mut cursor as &mut dyn Write);
        XmlEncodable::encode(&obj2, &mut writer, &ctx.context()).unwrap();

        // Make a new context, this time with the regular decoder for MyUnion
        let mut ctx = ContextOwned::new_default(get_namespaces(), DecodingOptions::test());
        ctx.loaders_mut().add_type_loader(MyUnionTypeLoader);
        cursor.seek(std::io::SeekFrom::Start(0)).unwrap();
        let mut reader = XmlStreamReader::new(&mut cursor as &mut dyn Read);
        let obj3: ExtensionObject = XmlDecodable::decode(&mut reader, &ctx.context()).unwrap();

        assert_eq!(obj, obj3);
    }
}
