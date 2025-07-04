use std::sync::Arc;

use crate::{
    node_manager::{
        consume_results, AddNodeItem, AddReferenceItem, DeleteNodeItem, DeleteReferenceItem,
        DynNodeManager, NodeManagers, RequestContext,
    },
    session::{
        controller::Response,
        message_handler::Request,
        services::{invoke_service_concurrently_mut, ServiceCb},
    },
};
use opcua_types::{
    AddNodesRequest, AddNodesResponse, AddReferencesRequest, AddReferencesResponse,
    DeleteNodesRequest, DeleteNodesResponse, DeleteReferencesRequest, DeleteReferencesResponse,
    NodeId, ResponseHeader, StatusCode,
};
use tracing::debug_span;
use tracing_futures::Instrument;

pub(crate) async fn add_nodes(
    node_managers: NodeManagers,
    request: Request<AddNodesRequest>,
) -> Response {
    let context = request.context();

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

    struct AddNodesServiceCb;

    impl ServiceCb<AddNodeItem> for AddNodesServiceCb {
        async fn call(
            &self,
            items: &mut [&mut AddNodeItem],
            node_manager: &Arc<DynNodeManager>,
            context: RequestContext,
        ) {
            if let Err(e) = node_manager
                .add_nodes(&context, items)
                .instrument(debug_span!("AddNodes", node_manager = %node_manager.name()))
                .await
            {
                for item in items {
                    item.set_result(NodeId::null(), e);
                }
            }
        }
    }

    invoke_service_concurrently_mut(
        context,
        &mut to_add,
        &node_managers,
        AddNodesServiceCb,
        |item, node_manager| {
            if item.status() != StatusCode::BadNotSupported {
                return false;
            }
            if item.requested_new_node_id().is_null() {
                node_manager.handle_new_node(item.parent_node_id())
            } else {
                node_manager.owns_node(item.requested_new_node_id())
            }
        },
    )
    .await;

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

pub(crate) async fn add_references(
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

    // We can't really do this concurrently, since
    // we don't know which node manager will actually create the reference
    // if it goes cross-node-manager.
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

pub(crate) async fn delete_nodes(
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

    struct DeleteNodesServiceCb;

    impl ServiceCb<DeleteNodeItem> for DeleteNodesServiceCb {
        async fn call(
            &self,
            items: &mut [&mut DeleteNodeItem],
            node_manager: &Arc<DynNodeManager>,
            context: RequestContext,
        ) {
            if let Err(e) = node_manager
                .delete_nodes(&context, items)
                .instrument(debug_span!("DeleteNodes", node_manager = %node_manager.name()))
                .await
            {
                for item in items {
                    item.set_result(e);
                }
            }
        }
    }

    invoke_service_concurrently_mut(
        context.clone(),
        &mut to_delete,
        &node_managers,
        DeleteNodesServiceCb,
        |item, node_manager| {
            item.status() == StatusCode::BadNodeIdUnknown && node_manager.owns_node(item.node_id())
        },
    )
    .await;

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

    // Then delete references where necessary. This is not done in parallel at the moment,
    // because our parallel implementation relies on each item bing owned by a single node manager,
    // and here each deleted node is attempted deleted from every other node manager.
    // If necessary we can improve on this later, it would require copying the references.
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

pub(crate) async fn delete_references(
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
