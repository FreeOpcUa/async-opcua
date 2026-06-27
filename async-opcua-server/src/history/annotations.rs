use crate::address_space::{AddressSpace, VariableBuilder};
use opcua_types::{
    DataTypeId, Identifier, NodeId, QualifiedName, ReferenceTypeId, VariableTypeId, Variant,
};

const ANNOTATIONS_PROPERTY_NAME: &str = "Annotations";

/// Attaches the Part 11 `Annotations` Property to a historized Variable.
///
/// The created Property is a Variable with BrowseName `Annotations`, DataType
/// `Annotation` (`i=891`), TypeDefinition `PropertyType`, and a forward
/// `HasProperty` reference from `source_variable`.
#[must_use]
pub fn attach_annotations_property(
    address_space: &mut AddressSpace,
    source_variable: &NodeId,
) -> NodeId {
    let annotations_id = annotations_property_node_id(source_variable);

    if !address_space.node_exists(&annotations_id) {
        VariableBuilder::new(
            &annotations_id,
            QualifiedName::new(0, ANNOTATIONS_PROPERTY_NAME),
            ANNOTATIONS_PROPERTY_NAME,
        )
        .data_type(DataTypeId::Annotation)
        .has_type_definition(VariableTypeId::PropertyType)
        .value(Variant::Empty)
        .property_of(source_variable.clone())
        .insert(address_space);
    } else if !address_space.has_reference(
        source_variable,
        &annotations_id,
        ReferenceTypeId::HasProperty,
    ) {
        address_space.insert_reference(
            source_variable,
            &annotations_id,
            ReferenceTypeId::HasProperty,
        );
    }

    annotations_id
}

fn annotations_property_node_id(source_variable: &NodeId) -> NodeId {
    let base = match &source_variable.identifier {
        Identifier::String(value) => value
            .value()
            .as_deref()
            .map(str::to_owned)
            .unwrap_or_else(|| source_variable.to_string()),
        _ => source_variable.to_string(),
    };

    NodeId::new(
        source_variable.namespace,
        format!("{base}_{ANNOTATIONS_PROPERTY_NAME}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address_space::NodeType;
    use opcua_types::{DataEncoding, NumericRange, TimestampsToReturn};

    fn address_space_with_source(source: &NodeId) -> AddressSpace {
        let mut address_space = AddressSpace::new();
        address_space.add_namespace("http://opcfoundation.org/UA/", 0);
        address_space.add_namespace("urn:test", source.namespace);

        VariableBuilder::new(source, "Temperature", "Temperature")
            .data_type(DataTypeId::Double)
            .value(1.0)
            .insert(&mut address_space);

        address_space
    }

    #[test]
    fn attach_annotations_property_creates_property_variable_and_reference() {
        let source = NodeId::new(2, "DeviceA.Temperature");
        let mut address_space = address_space_with_source(&source);

        let annotations_id = attach_annotations_property(&mut address_space, &source);

        assert_eq!(annotations_id.namespace, source.namespace);
        assert!(address_space.has_reference(
            &source,
            &annotations_id,
            ReferenceTypeId::HasProperty
        ));
        assert!(address_space.has_reference(
            &annotations_id,
            &NodeId::from(VariableTypeId::PropertyType),
            ReferenceTypeId::HasTypeDefinition
        ));

        let node = address_space
            .find(&annotations_id)
            .expect("Annotations property should exist");
        assert_eq!(
            node.as_node().browse_name(),
            &QualifiedName::new(0, "Annotations")
        );
        assert_eq!(node.as_node().display_name().to_string(), "Annotations");

        let NodeType::Variable(variable) = &*node else {
            panic!("Annotations property should be a variable");
        };
        assert_eq!(variable.data_type(), NodeId::from(DataTypeId::Annotation));
        assert_eq!(
            variable
                .value(
                    TimestampsToReturn::Neither,
                    &NumericRange::None,
                    &DataEncoding::Binary,
                    0.0,
                )
                .value,
            Some(Variant::Empty)
        );
    }
}
