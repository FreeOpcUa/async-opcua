use std::sync::Arc;

use opcua_client::custom_types::DataTypeTreeBuilder;
use opcua_nodes::{AccessLevel, DataTypeBuilder, VariableBuilder};
use opcua_types::{
    custom::{DynamicStructure, DynamicTypeLoader},
    DataTypeDefinition, DataTypeId, EUInformation, IntoVariant, LocalizedText, NodeId, ObjectId,
    ReadValueId, ReferenceTypeId, StructureDefinition, StructureField, StructureType,
    TimestampsToReturn, TypeLoader, VariableTypeId, Variant,
};

use crate::utils::setup;

use super::utils::{TestNodeManager, Tester};

fn struct_type_def() -> DataTypeDefinition {
    DataTypeDefinition::Structure(StructureDefinition {
        default_encoding_id: NodeId::null(),
        base_data_type: DataTypeId::Structure.into(),
        structure_type: StructureType::Structure,
        fields: Some(vec![
            StructureField {
                name: "Info".into(),
                data_type: DataTypeId::EUInformation.into(),
                value_rank: -1,
                ..Default::default()
            },
            StructureField {
                name: "AbstractField".into(),
                data_type: DataTypeId::BaseDataType.into(),
                value_rank: -1,
                ..Default::default()
            },
        ]),
    })
}

fn add_custom_data_type(
    nm: &TestNodeManager,
    tester: &Tester,
    type_def: DataTypeDefinition,
) -> NodeId {
    let id = nm.inner().next_node_id();

    nm.inner().add_node(
        nm.address_space(),
        tester.handle.type_tree(),
        DataTypeBuilder::new(&id, "CustomStruct", "CustomStruct")
            .data_type_definition(type_def)
            .build()
            .into(),
        &DataTypeId::Structure.into(),
        &ReferenceTypeId::HasSubtype.into(),
        None,
        Vec::new(),
    );
    id
}

#[tokio::test]
async fn test_data_type_tree_builder() {
    let (tester, nm, session) = setup().await;
    let type_def = struct_type_def();
    let type_id = add_custom_data_type(&nm, &tester, type_def.clone());

    let type_tree = DataTypeTreeBuilder::new(|f| f.namespace <= type_id.namespace)
        .build(&session)
        .await
        .unwrap();

    let typ = type_tree.get_struct_type(&type_id).unwrap().clone();
    let type_tree = Arc::new(type_tree);

    let loader = Arc::new(DynamicTypeLoader::new(type_tree.clone())) as Arc<dyn TypeLoader>;

    session.add_type_loader(loader.clone());
    tester.handle.info().add_type_loader(loader.clone());

    // Create a new variable with the dynamic type as value.
    let id = nm.inner().next_node_id();
    nm.inner().add_node(
        nm.address_space(),
        tester.handle.type_tree(),
        VariableBuilder::new(&id, "TestVar1", "TestVar1")
            .value(
                DynamicStructure::new_struct(
                    typ,
                    type_tree.clone(),
                    vec![
                        EUInformation {
                            namespace_uri: "some.namespace.uri".into(),
                            unit_id: 1,
                            display_name: "Some unit".into(),
                            description: "This is a unit".into(),
                        }
                        .into_variant(),
                        Variant::Variant(Box::new(
                            LocalizedText::new("en", "Hello there").into_variant(),
                        )),
                    ],
                )
                .unwrap()
                .into_variant(),
            )
            .description("Description")
            .data_type(type_id)
            .access_level(AccessLevel::CURRENT_READ)
            .user_access_level(AccessLevel::CURRENT_READ)
            .build()
            .into(),
        &ObjectId::ObjectsFolder.into(),
        &ReferenceTypeId::Organizes.into(),
        Some(&VariableTypeId::BaseDataVariableType.into()),
        Vec::new(),
    );

    let r = session
        .read(
            &[ReadValueId::new_value(id.clone())],
            TimestampsToReturn::Both,
            0.0,
        )
        .await
        .unwrap()
        .into_iter()
        .next()
        .unwrap();

    let Some(Variant::ExtensionObject(v)) = r.value else {
        panic!("Unexpected variant type");
    };

    assert_eq!(
        v.type_name().unwrap(),
        "opcua_types::custom::custom_struct::DynamicStructure"
    );
    let v: DynamicStructure = *v.into_inner_as().unwrap();

    assert_eq!(
        &EUInformation {
            namespace_uri: "some.namespace.uri".into(),
            unit_id: 1,
            display_name: "Some unit".into(),
            description: "This is a unit".into(),
        }
        .into_variant(),
        v.get_field(0).unwrap()
    );
    assert_eq!(
        &Variant::Variant(Box::new(
            LocalizedText::new("en", "Hello there").into_variant(),
        )),
        v.get_field(1).unwrap()
    );
    assert!(v.get_field(2).is_none());
}
