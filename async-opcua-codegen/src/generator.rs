//! Topological sorting for code generator targets and types.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::types::loaders::{FieldType, StructureFieldType};
use crate::types::LoadedType;
use crate::{CodeGenError, CodeGenTarget};

/// Sort LoadedType slice topologically based on dependencies in the target namespace.
pub fn sort_types_topologically(
    types: Vec<LoadedType>,
    target_namespace: &str,
) -> Result<Vec<LoadedType>, CodeGenError> {
    let mut type_map = BTreeMap::new();
    for typ in types {
        let name = typ.name().to_owned();
        if type_map.insert(name.clone(), typ).is_some() {
            return Err(CodeGenError::other(format!(
                "duplicate type definition for {name}"
            )));
        }
    }

    let mut adj: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut in_degree: BTreeMap<String, usize> = BTreeMap::new();

    for name in type_map.keys() {
        adj.insert(name.clone(), BTreeSet::new());
        in_degree.insert(name.clone(), 0);
    }

    for (name, item) in &type_map {
        let deps = type_dependencies(item, target_namespace, &type_map);
        for dep in deps {
            if let Some(neighbors) = adj.get_mut(&dep) {
                neighbors.insert(name.clone());
            }
        }
    }

    for edges in adj.values() {
        for target in edges {
            if let Some(degree) = in_degree.get_mut(target) {
                *degree += 1;
            }
        }
    }

    let mut queue: BTreeSet<String> = in_degree
        .iter()
        .filter(|(_, degree)| **degree == 0)
        .map(|(name, _)| name.clone())
        .collect();

    let mut ordered_names = Vec::with_capacity(type_map.len());
    while let Some(name) = queue.pop_first() {
        ordered_names.push(name.clone());

        if let Some(neighbors) = adj.get(&name) {
            for neighbor in neighbors {
                if let Some(degree) = in_degree.get_mut(neighbor) {
                    *degree = degree.saturating_sub(1);
                    if *degree == 0 {
                        queue.insert(neighbor.clone());
                    }
                }
            }
        }
    }

    if ordered_names.len() != type_map.len() {
        let remaining = in_degree
            .iter()
            .filter_map(|(name, degree)| (*degree > 0).then_some(name.as_str()))
            .collect::<Vec<_>>()
            .join(", ");
        return Err(CodeGenError::other(format!(
            "circular type dependency detected among: {remaining}"
        )));
    }

    let mut result = Vec::with_capacity(type_map.len());
    for name in ordered_names {
        if let Some(t) = type_map.remove(&name) {
            result.push(t);
        }
    }
    Ok(result)
}

fn type_dependencies(
    item: &LoadedType,
    target_namespace: &str,
    type_map: &BTreeMap<String, LoadedType>,
) -> BTreeSet<String> {
    let mut deps = BTreeSet::new();
    let LoadedType::Struct(item) = item else {
        return deps;
    };

    if let Some(base_type) = &item.base_type {
        add_local_type_dependency(&mut deps, base_type, target_namespace, type_map);
    }

    for field in &item.fields {
        let field_type = match &field.typ {
            StructureFieldType::Field(field_type) | StructureFieldType::Array(field_type) => {
                field_type
            }
        };
        add_local_type_dependency(&mut deps, field_type, target_namespace, type_map);
    }

    deps
}

fn add_local_type_dependency(
    deps: &mut BTreeSet<String>,
    field_type: &FieldType,
    target_namespace: &str,
    type_map: &BTreeMap<String, LoadedType>,
) {
    let Some(name) = local_dependency_name(field_type, target_namespace) else {
        return;
    };

    if type_map.contains_key(name) {
        deps.insert(name.to_owned());
    }
}

fn local_dependency_name<'a>(field_type: &'a FieldType, target_namespace: &str) -> Option<&'a str> {
    let FieldType::Normal { name, namespace } = field_type else {
        return None;
    };

    match namespace.as_deref() {
        Some(namespace) if namespace != target_namespace => None,
        _ => Some(name),
    }
}

/// Sort CodeGenTarget slice topologically based on dependent nodesets.
pub fn sort_targets_topologically(
    targets: Vec<CodeGenTarget>,
) -> Result<Vec<CodeGenTarget>, CodeGenError> {
    let mut filename_to_indices: HashMap<String, Vec<usize>> = HashMap::new();
    for (idx, target) in targets.iter().enumerate() {
        if let Some(file) = target_file(target) {
            filename_to_indices
                .entry(file.to_owned())
                .or_default()
                .push(idx);
        }
    }

    let mut adj = vec![BTreeSet::new(); targets.len()];
    let mut in_degree = vec![0_usize; targets.len()];

    for (idx, target) in targets.iter().enumerate() {
        for dep in target_dependency_files(target) {
            if let Some(dep_indices) = filename_to_indices.get(dep) {
                for &dep_idx in dep_indices {
                    if dep_idx != idx && adj[dep_idx].insert(idx) {
                        in_degree[idx] += 1;
                    }
                }
            }
        }
    }

    let mut queue = in_degree
        .iter()
        .enumerate()
        .filter_map(|(idx, degree)| (*degree == 0).then_some(idx))
        .collect::<BTreeSet<_>>();

    let mut ordered_indices = Vec::with_capacity(targets.len());
    while let Some(idx) = queue.pop_first() {
        ordered_indices.push(idx);

        for &neighbor in &adj[idx] {
            in_degree[neighbor] = in_degree[neighbor].saturating_sub(1);
            if in_degree[neighbor] == 0 {
                queue.insert(neighbor);
            }
        }
    }

    if ordered_indices.len() != targets.len() {
        let remaining = in_degree
            .iter()
            .enumerate()
            .filter(|(_, degree)| **degree > 0)
            .map(|(idx, _)| target_label(&targets[idx]))
            .collect::<Vec<_>>()
            .join(", ");
        return Err(CodeGenError::other(format!(
            "circular code generation target dependency detected among: {remaining}"
        )));
    }

    let mut result = Vec::with_capacity(targets.len());
    let mut targets_opt: Vec<Option<CodeGenTarget>> = targets.into_iter().map(Some).collect();
    for idx in ordered_indices {
        if let Some(target) = targets_opt[idx].take() {
            result.push(target);
        }
    }
    Ok(result)
}

fn target_file(target: &CodeGenTarget) -> Option<&str> {
    match target {
        CodeGenTarget::Types(target) => Some(&target.file),
        CodeGenTarget::Nodes(target) => Some(&target.file),
        CodeGenTarget::Ids(_) => None,
        CodeGenTarget::Events(target) => Some(&target.file),
    }
}

fn target_dependency_files(target: &CodeGenTarget) -> Vec<&str> {
    match target {
        CodeGenTarget::Types(target) => target
            .dependent_nodesets
            .iter()
            .map(|dependency| dependency.file.as_str())
            .collect(),
        CodeGenTarget::Nodes(target) => target
            .types
            .iter()
            .map(|dependency| dependency.file.as_str())
            .collect(),
        CodeGenTarget::Ids(_) => Vec::new(),
        CodeGenTarget::Events(target) => target
            .dependent_nodesets
            .iter()
            .map(|dependency| dependency.file.as_str())
            .collect(),
    }
}

fn target_label(target: &CodeGenTarget) -> String {
    match target {
        CodeGenTarget::Types(target) => format!("types {}", target.file),
        CodeGenTarget::Nodes(target) => format!("nodes {}", target.file),
        CodeGenTarget::Ids(target) => format!("ids {}", target.output_file.display()),
        CodeGenTarget::Events(target) => format!("events {}", target.file),
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::{
        generator::{sort_targets_topologically, sort_types_topologically},
        types::loaders::{
            types::{EnumValue, StructureField},
            EnumReprType, EnumType, FieldType, StructureFieldType, StructuredType,
        },
        CodeGenTarget, DependentNodeset, TypeCodeGenTarget, BASE_NAMESPACE,
    };

    use super::LoadedType;

    const LOCAL_NAMESPACE: &str = "urn:local";

    fn struct_type(name: &str, fields: Vec<StructureField>) -> LoadedType {
        LoadedType::Struct(StructuredType {
            name: name.to_owned(),
            id: None,
            fields,
            hidden_fields: Vec::new(),
            documentation: None,
            base_type: None,
            is_union: false,
        })
    }

    fn union_type(name: &str, fields: Vec<StructureField>) -> LoadedType {
        LoadedType::Struct(StructuredType {
            name: name.to_owned(),
            id: None,
            fields,
            hidden_fields: Vec::new(),
            documentation: None,
            base_type: None,
            is_union: true,
        })
    }

    fn enum_type(name: &str) -> LoadedType {
        LoadedType::Enum(EnumType {
            name: name.to_owned(),
            values: vec![EnumValue {
                name: "Value".to_owned(),
                value: 0,
                documentation: None,
            }],
            documentation: None,
            typ: EnumReprType::i32,
            size: 4,
            option: false,
            default_value: None,
        })
    }

    fn field(name: &str, typ: &str, namespace: Option<&str>) -> StructureField {
        StructureField {
            name: name.to_owned(),
            original_name: name.to_owned(),
            typ: StructureFieldType::Field(FieldType::Normal {
                name: typ.to_owned(),
                namespace: namespace.map(str::to_owned),
            }),
            documentation: None,
        }
    }

    fn array_field(name: &str, typ: &str, namespace: Option<&str>) -> StructureField {
        StructureField {
            name: name.to_owned(),
            original_name: name.to_owned(),
            typ: StructureFieldType::Array(FieldType::Normal {
                name: typ.to_owned(),
                namespace: namespace.map(str::to_owned),
            }),
            documentation: None,
        }
    }

    fn names(types: &[LoadedType]) -> Vec<&str> {
        types.iter().map(LoadedType::name).collect()
    }

    #[test]
    fn sorts_struct_field_dependencies_before_dependents() -> Result<(), crate::CodeGenError> {
        let sorted = sort_types_topologically(
            vec![
                struct_type("Dependent", vec![field("inner", "Dependency", None)]),
                struct_type("Dependency", Vec::new()),
            ],
            LOCAL_NAMESPACE,
        )?;

        assert_eq!(names(&sorted), vec!["Dependency", "Dependent"]);
        Ok(())
    }

    #[test]
    fn sorts_array_enum_and_union_field_dependencies() -> Result<(), crate::CodeGenError> {
        let sorted = sort_types_topologically(
            vec![
                union_type(
                    "Choice",
                    vec![field("value", "Child", Some(LOCAL_NAMESPACE))],
                ),
                struct_type(
                    "Container",
                    vec![
                        array_field("children", "Child", Some(LOCAL_NAMESPACE)),
                        field("mode", "Mode", Some(LOCAL_NAMESPACE)),
                    ],
                ),
                enum_type("Mode"),
                struct_type("Child", Vec::new()),
            ],
            LOCAL_NAMESPACE,
        )?;

        assert_eq!(names(&sorted), vec!["Child", "Choice", "Mode", "Container"]);
        Ok(())
    }

    #[test]
    fn ignores_cross_namespace_references_with_matching_local_names(
    ) -> Result<(), crate::CodeGenError> {
        let sorted = sort_types_topologically(
            vec![
                struct_type(
                    "Companion",
                    vec![field("base", "SharedName", Some(BASE_NAMESPACE))],
                ),
                struct_type("SharedName", Vec::new()),
            ],
            LOCAL_NAMESPACE,
        )?;

        assert_eq!(names(&sorted), vec!["Companion", "SharedName"]);
        Ok(())
    }

    #[test]
    fn reports_circular_type_dependencies() {
        let err = sort_types_topologically(
            vec![
                struct_type("A", vec![field("b", "B", None)]),
                struct_type("B", vec![array_field("a", "A", None)]),
            ],
            LOCAL_NAMESPACE,
        )
        .unwrap_err();

        let err = err.to_string();
        assert!(err.contains("circular type dependency"));
        assert!(err.contains("A"));
        assert!(err.contains("B"));
    }

    fn type_target(file: &str, deps: &[&str]) -> CodeGenTarget {
        CodeGenTarget::Types(TypeCodeGenTarget {
            file: file.to_owned(),
            output_dir: PathBuf::new(),
            dependent_nodesets: deps
                .iter()
                .map(|file| DependentNodeset {
                    file: (*file).to_owned(),
                    import_path: String::new(),
                })
                .collect(),
            ..Default::default()
        })
    }

    #[test]
    fn reports_circular_target_dependencies() {
        let err = sort_targets_topologically(vec![
            type_target("base.xml", &["companion.xml"]),
            type_target("companion.xml", &["base.xml"]),
        ])
        .unwrap_err();

        let err = err.to_string();
        assert!(err.contains("circular code generation target dependency"));
        assert!(err.contains("base.xml"));
        assert!(err.contains("companion.xml"));
    }
}
