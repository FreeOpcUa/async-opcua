//! Diagnostics for parsed OPC UA NodeSet collections.

use crate::schema::ua_node_set::{NodeId, ReferenceChange};
use crate::NodeSetCollection;

/// Diagnostics collected from a parsed [`NodeSetCollection`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DiagnosticReport {
    /// References whose target NodeId could not be resolved in the collection.
    pub unresolved_references: Vec<UnresolvedReference>,
}

/// A reference target that could not be resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnresolvedReference {
    /// Index of the NodeSet containing the unresolved reference.
    pub source_node_set_index: usize,
    /// NodeId of the node containing the reference.
    pub source_node_id: String,
    /// Target NodeId from the unresolved reference body.
    pub target_node_id: String,
    /// Reference type NodeId from the reference attribute.
    pub reference_type: String,
    /// Whether the unresolved reference is a forward reference.
    pub is_forward: bool,
}

/// Generate diagnostics for unresolved reference targets in a NodeSet collection.
pub fn generate_diagnostics(collection: &NodeSetCollection) -> DiagnosticReport {
    let mut report = DiagnosticReport::default();

    for (source_node_set_index, node_set) in collection.node_sets().iter().enumerate() {
        if let Some(ua_node_set) = node_set.node_set.as_ref() {
            for node in &ua_node_set.nodes {
                let base = node.base();
                let Some(references) = base.references.as_ref() else {
                    continue;
                };

                for reference in &references.references {
                    if collection
                        .resolve_reference(source_node_set_index, &reference.node_id)
                        .is_none()
                    {
                        report.unresolved_references.push(UnresolvedReference {
                            source_node_set_index,
                            source_node_id: base.node_id.0.clone(),
                            target_node_id: reference.node_id.0.clone(),
                            reference_type: reference.reference_type.0.clone(),
                            is_forward: reference.is_forward,
                        });
                    }
                }
            }
        }

        if let Some(changes) = node_set.node_set_changes.as_ref() {
            if let Some(references_to_add) = changes.references_to_add.as_ref() {
                for reference in &references_to_add.references {
                    push_reference_change_diagnostic(
                        collection,
                        &mut report,
                        source_node_set_index,
                        reference,
                    );
                }
            }
        }
    }

    report
}

fn push_reference_change_diagnostic(
    collection: &NodeSetCollection,
    report: &mut DiagnosticReport,
    source_node_set_index: usize,
    reference: &ReferenceChange,
) {
    if collection
        .resolve_reference(source_node_set_index, &reference.node_id)
        .is_some()
    {
        return;
    }

    push_unresolved_reference(
        report,
        source_node_set_index,
        &reference.source,
        &reference.node_id,
        &reference.reference_type,
        reference.is_forward,
    );
}

fn push_unresolved_reference(
    report: &mut DiagnosticReport,
    source_node_set_index: usize,
    source_node_id: &NodeId,
    target_node_id: &NodeId,
    reference_type: &NodeId,
    is_forward: bool,
) {
    report.unresolved_references.push(UnresolvedReference {
        source_node_set_index,
        source_node_id: source_node_id.0.clone(),
        target_node_id: target_node_id.0.clone(),
        reference_type: reference_type.0.clone(),
        is_forward,
    });
}
