//! Topological sorting for OPC UA NodeSet model dependencies.

use std::collections::{HashMap, HashSet, VecDeque};

use crate::schema::ua_node_set::{ModelTableEntry, NodeSet2};
use crate::{XmlError, XmlErrorInner};

/// Sort NodeSets so required models appear before dependent models.
pub fn sort_nodesets(node_sets: Vec<NodeSet2>) -> Result<Vec<NodeSet2>, XmlError> {
    let model_uris = node_sets
        .iter()
        .map(model_uris_for_nodeset)
        .collect::<Vec<_>>();
    let mut provided_by = HashMap::new();

    for (index, uris) in model_uris.iter().enumerate() {
        for uri in uris {
            provided_by.entry(uri.as_str()).or_insert(index);
        }
    }

    let mut dependencies = vec![HashSet::new(); node_sets.len()];
    let mut dependents = vec![Vec::new(); node_sets.len()];

    for (index, node_set) in node_sets.iter().enumerate() {
        for required_uri in required_model_uris_for_nodeset(node_set) {
            let Some(&dependency_index) = provided_by.get(required_uri.as_str()) else {
                continue;
            };
            if dependency_index == index || !dependencies[index].insert(dependency_index) {
                continue;
            }
            dependents[dependency_index].push(index);
        }
    }

    let mut in_degree = dependencies.iter().map(HashSet::len).collect::<Vec<_>>();
    let mut ready = in_degree
        .iter()
        .enumerate()
        .filter_map(|(index, degree)| (*degree == 0).then_some(index))
        .collect::<VecDeque<_>>();
    let mut sorted_indices = Vec::with_capacity(node_sets.len());

    while let Some(index) = ready.pop_front() {
        sorted_indices.push(index);
        for &dependent_index in &dependents[index] {
            in_degree[dependent_index] = in_degree[dependent_index].saturating_sub(1);
            if in_degree[dependent_index] == 0 {
                ready.push_back(dependent_index);
            }
        }
    }

    if sorted_indices.len() != node_sets.len() {
        return Err(other_error("cyclic NodeSet model dependency"));
    }

    let mut slots = node_sets.into_iter().map(Some).collect::<Vec<_>>();
    sorted_indices
        .into_iter()
        .map(|index| {
            slots
                .get_mut(index)
                .and_then(Option::take)
                .ok_or_else(|| other_error("internal NodeSet sort state mismatch"))
        })
        .collect()
}

fn model_uris_for_nodeset(node_set: &NodeSet2) -> HashSet<String> {
    node_set
        .node_set
        .as_ref()
        .and_then(|node_set| node_set.models.as_ref())
        .map(|models| {
            models
                .models
                .iter()
                .map(|model| model.model_uri.clone())
                .collect()
        })
        .unwrap_or_default()
}

fn required_model_uris_for_nodeset(node_set: &NodeSet2) -> HashSet<String> {
    let mut required = HashSet::new();
    if let Some(models) = node_set
        .node_set
        .as_ref()
        .and_then(|node_set| node_set.models.as_ref())
    {
        for model in &models.models {
            collect_required_model_uris(model, &mut required);
        }
    }
    required
}

fn collect_required_model_uris(model: &ModelTableEntry, required: &mut HashSet<String>) {
    for required_model in &model.required_model {
        required.insert(required_model.model_uri.clone());
        collect_required_model_uris(required_model, required);
    }
}

fn other_error(message: &str) -> XmlError {
    XmlError {
        span: 0..0,
        error: XmlErrorInner::Other(message.to_owned()),
    }
}
