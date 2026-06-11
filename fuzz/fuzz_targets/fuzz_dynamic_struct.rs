#![cfg_attr(feature = "nightly", no_main)]

#[cfg(not(feature = "nightly"))]
fn main() {
    panic!("Fuzzing requires the nightly feature to be enabled.");
}

#[cfg(feature = "nightly")]
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    use opcua::types::{
        custom::{DataTypeTree, DynamicTypeLoader, EncodingIds, GenericTypeInfo, ParentIds, TypeInfo},
        BinaryDecodable, ContextOwned, DataTypeDefinition, DataTypeId, DecodingOptions, Error,
        ExtensionObject, NamespaceMap, NodeId, ObjectId, StructureDefinition, StructureField,
        TypeLoaderCollection,
    };
    use std::io::Cursor;
    use std::sync::Arc;

    fn make_context() -> ContextOwned {
        let mut type_tree = DataTypeTree::new(ParentIds::new());
        type_tree.add_type(DataTypeId::Int32.into(), GenericTypeInfo::new(false));
        type_tree.add_type(DataTypeId::String.into(), GenericTypeInfo::new(false));
        type_tree.add_type(
            DataTypeId::LocalizedText.into(),
            GenericTypeInfo::new(false),
        );
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
                    structure_type: opcua::types::StructureType::Structure,
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

        let loader = DynamicTypeLoader::new(Arc::new(type_tree));
        let mut loaders = TypeLoaderCollection::new_empty();
        loaders.add_type_loader(loader);
        ContextOwned::new(NamespaceMap::new(), loaders, DecodingOptions::default())
    }

    fn deserialize(data: &[u8], ctx: &ContextOwned) -> Result<ExtensionObject, Error> {
        // Decoding arbitrary bytes through the dynamic type loader must
        // return a value or an error, never panic.
        let mut stream = Cursor::new(data);
        ExtensionObject::decode(&mut stream, &ctx.context())
    }

    let ctx = make_context();
    let _ = deserialize(data, &ctx);
});
