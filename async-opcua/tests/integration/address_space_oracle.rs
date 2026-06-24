//! Address-space conformance oracle (Part 5).
//!
//! Ground truth: the OPC Foundation canonical NodeId registry (`Schema/NodeIds.csv` from UA-Nodeset,
//! vendored MIT under `vectors/opcfoundation/`), filtered to the type-system node classes
//! (DataType / ObjectType / ReferenceType / VariableType). For every such standard type node the
//! server exposes, we assert the NodeClass and BrowseName are spec-correct, plus a coverage floor and
//! an explicit mandatory-core set must be present.
//!
//! What is intentionally NOT a hard failure: standard type nodes that are *absent*. The reference CSV
//! tracks a newer namespace version (1.05.07) than our bundled nodeset (1.05.04), and exposing every
//! abstract/service-structure DataType as an address-space node is not mandatory for a typical server
//! profile. Absent nodes are reported for visibility; correctness of what IS exposed is enforced.

use opcua::types::{AttributeId, NodeId, TimestampsToReturn, Variant};

use super::utils::{read_value_id, setup};

const NODE_IDS_CSV: &str = include_str!("vectors/opcfoundation/NodeIds.csv");

/// Conservative floor on how many of the 922 standard type nodes the server must expose. We measure
/// 677 today; this only catches a catastrophic collapse of the standard type system, while staying
/// robust to namespace-version drift (newer nodesets only add nodes).
const MIN_TYPE_NODES_PRESENT: usize = 600;

/// Unambiguously mandatory core type nodes — the primitive DataTypes plus the base type/reference
/// hierarchy. Any conformant server must expose every one of these (they have existed since 1.0).
const MANDATORY_CORE: &[(u32, &str)] = &[
    (1, "Boolean"),
    (11, "Double"),
    (12, "String"),
    (13, "DateTime"),
    (24, "BaseDataType"),
    (22, "Structure"),
    (58, "BaseObjectType"),
    (61, "FolderType"),
    (62, "BaseVariableType"),
    (63, "BaseDataVariableType"),
    (68, "PropertyType"),
    (31, "References"),
    (33, "HierarchicalReferences"),
    (40, "HasTypeDefinition"),
    (45, "HasSubtype"),
    (46, "HasProperty"),
    (47, "HasComponent"),
    (35, "Organizes"),
];

fn expected_node_class(csv_class: &str) -> Option<i32> {
    match csv_class {
        "DataType" => Some(64),
        "ObjectType" => Some(8),
        "ReferenceType" => Some(32),
        "VariableType" => Some(16),
        _ => None,
    }
}

/// The CSV `SymbolName` cannot begin with a digit, so OPC UA spells the leading "3D" as "ThreeD"
/// (e.g. `ThreeDVectorType` ↔ BrowseName `3DVectorType`). Normalize for comparison.
fn normalize_symbol_name(name: &str) -> String {
    name.strip_prefix("ThreeD")
        .map(|rest| format!("3D{rest}"))
        .unwrap_or_else(|| name.to_string())
}

#[tokio::test]
async fn standard_type_system_is_conformant() {
    let (_tester, _nm, session) = setup().await;

    // (numeric id, expected browse name, expected NodeClass) for every standard type-system node.
    let types: Vec<(u32, String, i32)> = NODE_IDS_CSV
        .lines()
        .filter_map(|line| {
            let mut it = line.split(',');
            let name = normalize_symbol_name(it.next()?.trim());
            let id = it.next()?.trim().parse::<u32>().ok()?;
            let class = expected_node_class(it.next()?.trim())?;
            Some((id, name, class))
        })
        .collect();
    assert!(
        types.len() > 900,
        "expected ~922 standard type nodes in the CSV, got {}",
        types.len()
    );

    let mut to_read = Vec::with_capacity(types.len() * 2);
    for (id, _, _) in &types {
        to_read.push(read_value_id(AttributeId::NodeClass, NodeId::new(0, *id)));
        to_read.push(read_value_id(AttributeId::BrowseName, NodeId::new(0, *id)));
    }
    let res = session
        .read(&to_read, TimestampsToReturn::Neither, 0.0)
        .await
        .unwrap();

    let mut present = 0usize;
    let mut missing = Vec::new();
    let mut wrong_class = Vec::new();
    let mut wrong_bn = Vec::new();
    for (i, (id, name, ec)) in types.iter().enumerate() {
        match &res[i * 2].value {
            Some(Variant::Int32(v)) if v == ec => {
                present += 1;
                match &res[i * 2 + 1].value {
                    Some(Variant::QualifiedName(q)) if q.name.as_ref() == name.as_str() => {}
                    other => wrong_bn.push((*id, name.clone(), format!("{other:?}"))),
                }
            }
            Some(Variant::Int32(v)) => wrong_class.push((*id, name.clone(), *v, *ec)),
            _ => missing.push((*id, name.clone())),
        }
    }

    println!(
        "[address-space oracle] type nodes={} present={} missing={} (informational) wrong_class={} wrong_bn={}",
        types.len(), present, missing.len(), wrong_class.len(), wrong_bn.len()
    );

    // Correctness of what IS exposed (hard failures).
    assert!(
        wrong_class.is_empty(),
        "standard type nodes with the wrong NodeClass: {:?}",
        &wrong_class[..wrong_class.len().min(20)]
    );
    assert!(
        wrong_bn.is_empty(),
        "standard type nodes with the wrong BrowseName: {:?}",
        &wrong_bn[..wrong_bn.len().min(20)]
    );

    // Coverage floor + mandatory core.
    assert!(
        present >= MIN_TYPE_NODES_PRESENT,
        "only {present} standard type nodes exposed, expected >= {MIN_TYPE_NODES_PRESENT}"
    );
    let present_ids: std::collections::HashSet<u32> = types
        .iter()
        .enumerate()
        .filter(|(i, _)| matches!(&res[i * 2].value, Some(Variant::Int32(_))))
        .map(|(_, (id, _, _))| *id)
        .collect();
    let missing_core: Vec<_> = MANDATORY_CORE
        .iter()
        .filter(|(id, _)| !present_ids.contains(id))
        .collect();
    assert!(
        missing_core.is_empty(),
        "mandatory core type nodes are missing from the address space: {missing_core:?}"
    );
}
