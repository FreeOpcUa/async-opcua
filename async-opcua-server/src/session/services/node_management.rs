use crate::{
    node_manager::{
        consume_results, AddNodeItem, AddReferenceItem, DeleteNodeItem, DeleteReferenceItem,
        NodeManagers,
    },
    session::{controller::Response, message_handler::Request},
};
use opcua_types::{
    AddNodesRequest, AddNodesResponse, AddReferencesRequest, AddReferencesResponse,
    DeleteNodesRequest, DeleteNodesResponse, DeleteReferencesRequest, DeleteReferencesResponse,
    NodeId, ResponseHeader, StatusCode,
};
use tracing::debug_span;
use tracing_futures::Instrument;

pub async fn add_nodes(node_managers: NodeManagers, request: Request<AddNodesRequest>) -> Response {
    let mut context = request.context();

    let nodes_to_add = take_service_items!(
        request,
        request.request.nodes_to_add,
        request
            .info
            .operational_limits
            .max_nodes_per_node_management
    );

    let mut to_add: Vec<_> = nodes_to_add
        .into_iter()
        .map(|it| AddNodeItem::new(it, request.request.request_header.return_diagnostics))
        .collect();

    for (idx, node_manager) in node_managers.iter().enumerate() {
        context.current_node_manager_index = idx;
        let mut owned: Vec<_> = to_add
            .iter_mut()
            .filter(|c| {
                if c.status() != StatusCode::BadNotSupported {
                    return false;
                }
                if c.requested_new_node_id().is_null() {
                    node_manager.handle_new_node(c.parent_node_id())
                } else {
                    node_manager.owns_node(c.requested_new_node_id())
                }
            })
            .collect();

        if owned.is_empty() {
            continue;
        }

        if let Err(e) = node_manager
            .add_nodes(&context, &mut owned)
            .instrument(debug_span!("AddNodes", node_manager = %node_manager.name()))
            .await
        {
            for node in owned {
                node.set_result(NodeId::null(), e);
            }
        }
    }

    let (results, diagnostic_infos) =
        consume_results(to_add, request.request.request_header.return_diagnostics);

    Response {
        message: AddNodesResponse {
            response_header: ResponseHeader::new_good(request.request_handle),
            results,
            diagnostic_infos,
        }
        .into(),
        request_id: request.request_id,
    }
}

pub async fn add_references(
    node_managers: NodeManagers,
    request: Request<AddReferencesRequest>,
) -> Response {
    let mut context = request.context();

    let references_to_add = take_service_items!(
        request,
        request.request.references_to_add,
        request
            .info
            .operational_limits
            .max_references_per_references_management
    );

    let mut to_add: Vec<_> = references_to_add
        .into_iter()
        .map(|it| AddReferenceItem::new(it, request.request.request_header.return_diagnostics))
        .collect();

    for (idx, node_manager) in node_managers.iter().enumerate() {
        context.current_node_manager_index = idx;
        let mut owned: Vec<_> = to_add
            .iter_mut()
            .filter(|v| {
                if v.source_status() != StatusCode::BadNotSupported
                    && v.target_status() != StatusCode::BadNotSupported
                {
                    return false;
                }
                node_manager.owns_node(v.source_node_id())
                    || node_manager.owns_node(&v.target_node_id().node_id)
            })
            .collect();

        if owned.is_empty() {
            continue;
        }

        if let Err(e) = node_manager
            .add_references(&context, &mut owned)
            .instrument(debug_span!("AddReferences", node_manager = %node_manager.name()))
            .await
        {
            for node in owned {
                if node_manager.owns_node(node.source_node_id()) {
                    node.set_source_result(e);
                }
                if node_manager.owns_node(&node.target_node_id().node_id) {
                    node.set_target_result(e);
                }
            }
        }
    }

    let (results, diagnostic_infos) =
        consume_results(to_add, request.request.request_header.return_diagnostics);

    Response {
        message: AddReferencesResponse {
            response_header: ResponseHeader::new_good(request.request_handle),
            results,
            diagnostic_infos,
        }
        .into(),
        request_id: request.request_id,
    }
}

pub async fn delete_nodes(
    node_managers: NodeManagers,
    request: Request<DeleteNodesRequest>,
) -> Response {
    let mut context = request.context();

    let nodes_to_delete = take_service_items!(
        request,
        request.request.nodes_to_delete,
        request
            .info
            .operational_limits
            .max_nodes_per_node_management
    );

    let mut to_delete: Vec<_> = nodes_to_delete
        .into_iter()
        .map(|v| DeleteNodeItem::new(v, request.request.request_header.return_diagnostics))
        .collect();

    for (idx, node_manager) in node_managers.iter().enumerate() {
        context.current_node_manager_index = idx;
        let mut owned: Vec<_> = to_delete
            .iter_mut()
            .filter(|it| {
                it.status() == StatusCode::BadNodeIdUnknown && node_manager.owns_node(it.node_id())
            })
            .collect();

        if owned.is_empty() {
            continue;
        }

        if let Err(e) = node_manager
            .delete_nodes(&context, &mut owned)
            .instrument(debug_span!("DeleteNodes", node_manager = %node_manager.name()))
            .await
        {
            for node in owned {
                node.set_result(e);
            }
        }
    }

    // Then delete references where necessary.
    for (idx, node_manager) in node_managers.iter().enumerate() {
        context.current_node_manager_index = idx;
        let targets: Vec<_> = to_delete
            .iter()
            .filter(|it| it.status().is_good() && !node_manager.owns_node(it.node_id()))
            .collect();

        node_manager
            .delete_node_references(&context, &targets)
            .instrument(debug_span!("delete node references", node_manager = %node_manager.name()))
            .await;
    }

    let (results, diagnostic_infos) =
        consume_results(to_delete, request.request.request_header.return_diagnostics);

    Response {
        message: DeleteNodesResponse {
            response_header: ResponseHeader::new_good(request.request_handle),
            results,
            diagnostic_infos,
        }
        .into(),
        request_id: request.request_id,
    }
}

pub async fn delete_references(
    node_managers: NodeManagers,
    request: Request<DeleteReferencesRequest>,
) -> Response {
    let mut context = request.context();

    let references_to_delete = take_service_items!(
        request,
        request.request.references_to_delete,
        request
            .info
            .operational_limits
            .max_references_per_references_management
    );

    let mut to_delete: Vec<_> = references_to_delete
        .into_iter()
        .map(|it| DeleteReferenceItem::new(it, request.request.request_header.return_diagnostics))
        .collect();

    for (idx, node_manager) in node_managers.iter().enumerate() {
        context.current_node_manager_index = idx;
        let mut owned: Vec<_> = to_delete
            .iter_mut()
            .filter(|v| {
                if v.source_status() != StatusCode::BadNotSupported
                    && v.target_status() != StatusCode::BadNotSupported
                {
                    return false;
                }
                node_manager.owns_node(v.source_node_id())
                    || node_manager.owns_node(&v.target_node_id().node_id)
            })
            .collect();

        if owned.is_empty() {
            continue;
        }

        if let Err(e) = node_manager
            .delete_references(&context, &mut owned)
            .instrument(debug_span!("DeleteReferences", node_manager = %node_manager.name()))
            .await
        {
            for node in owned {
                if node_manager.owns_node(node.source_node_id()) {
                    node.set_source_result(e);
                }
                if node_manager.owns_node(&node.target_node_id().node_id) {
                    node.set_target_result(e);
                }
            }
        }
    }

    let (results, diagnostic_infos) =
        consume_results(to_delete, request.request.request_header.return_diagnostics);

    Response {
        message: DeleteReferencesResponse {
            response_header: ResponseHeader::new_good(request.request_handle),
            results,
            diagnostic_infos,
        }
        .into(),
        request_id: request.request_id,
    }
}
