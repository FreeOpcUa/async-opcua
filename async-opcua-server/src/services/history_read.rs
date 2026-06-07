//! HistoryRead service preparation helpers.

use std::sync::Arc;

use opcua_core::{sync::RwLock, trace_write_lock};
use opcua_types::{HistoryReadValueId, NodeId, ObjectId, StatusCode};

use crate::{
    node_manager::{DynNodeManager, HistoryNode, NodeManagers, RequestContext},
    session::instance::Session,
};

/// Converts raw HistoryRead items into node-manager work items and releases removed continuation points.
pub async fn prepare_history_nodes(
    session_lock: &Arc<RwLock<Session>>,
    node_managers: &NodeManagers,
    context: &RequestContext,
    items: Vec<HistoryReadValueId>,
    is_events: bool,
    release: bool,
) -> Vec<HistoryNode> {
    let mut nodes: Vec<_> = {
        let mut session = trace_write_lock!(session_lock);
        items
            .into_iter()
            .map(|node| prepare_history_node(&mut session, node, is_events, release))
            .collect()
    };

    if release {
        release_continuation_points(&mut nodes, node_managers, context, is_events).await;
    }

    nodes
}

fn prepare_history_node(
    session: &mut Session,
    node: HistoryReadValueId,
    is_events: bool,
    release: bool,
) -> HistoryNode {
    if node.continuation_point.is_null_or_empty() {
        let mut node = HistoryNode::new(node, is_events, None);
        if release {
            node.set_status(StatusCode::Good);
        }
        return node;
    }

    let cp = session.remove_history_continuation_point(&node.continuation_point);
    let cp_missing = cp.is_none();
    let mut node = HistoryNode::new(node, is_events, cp);
    if cp_missing {
        node.set_status(StatusCode::BadContinuationPointInvalid);
    } else if release {
        node.set_status(StatusCode::Good);
    }
    node
}

async fn release_continuation_points(
    nodes: &mut [HistoryNode],
    node_managers: &NodeManagers,
    context: &RequestContext,
    is_events: bool,
) {
    for node in nodes {
        let result = {
            let Some(continuation_point) = node.continuation_point() else {
                continue;
            };

            let Some((node_manager_index, node_manager)) =
                owning_node_manager(node_managers, node.node_id(), is_events)
            else {
                continue;
            };

            let mut context = context.clone();
            context.current_node_manager_index = node_manager_index;
            node_manager
                .history_release_continuation_point(&context, node.node_id(), continuation_point)
                .await
        };

        if let Err(status) = result {
            node.set_status(status);
        }
    }
}

fn owning_node_manager(
    node_managers: &NodeManagers,
    node_id: &NodeId,
    is_events: bool,
) -> Option<(usize, Arc<DynNodeManager>)> {
    node_managers
        .iter()
        .enumerate()
        .find(|(_, node_manager)| {
            if node_id == &ObjectId::Server && is_events {
                node_manager.owns_server_events()
            } else {
                node_manager.owns_node(node_id)
            }
        })
        .map(|(index, node_manager)| (index, Arc::clone(node_manager)))
}
