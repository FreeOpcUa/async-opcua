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

    for item in &mut to_add {
        if item.status() == StatusCode::BadNotSupported && !item.requested_new_node_id().is_null() {
            item.set_result(NodeId::null(), StatusCode::BadNodeIdRejected);
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

    // Then delete cross-manager references where necessary. This is not done in parallel at the
    // moment because our parallel implementation relies on each item being owned by a single node
    // manager, and here each deleted node is attempted deleted from every other node manager. The
    // node manager hook mirrors local DeleteNodes behavior and respects deleteTargetReferences.
    for (idx, node_manager) in node_managers.iter().enumerate() {
        context.current_node_manager_index = idx;
        let deleted_nodes: Vec<_> = to_delete
            .iter()
            .filter(|it| it.status().is_good() && !node_manager.owns_node(it.node_id()))
            .collect();
        if deleted_nodes.is_empty() {
            continue;
        }

        node_manager
            .delete_node_references(&context, &deleted_nodes)
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use async_trait::async_trait;
    use opcua_core::{sync::RwLock, ResponseMessage};
    use opcua_nodes::Object;
    use opcua_types::{
        AnonymousIdentityToken, ApplicationDescription, ByteString, DeleteNodesItem,
        MessageSecurityMode, NodeClass, NodeId, QualifiedName, ReferenceTypeId, RequestHeader,
        UAString,
    };

    use super::*;
    use crate::{
        address_space::{AddressSpace, EventNotifier},
        authenticator::UserToken,
        diagnostics::NamespaceMetadata,
        identity_token::IdentityToken,
        node_manager::{
            memory::{InMemoryNodeManager, InMemoryNodeManagerImpl},
            ServerContext,
        },
        session::instance::Session,
        ServerBuilder,
    };

    struct TestNodeManagerImpl {
        name: &'static str,
        namespace_index: u16,
        namespace_uri: &'static str,
    }

    #[async_trait]
    impl InMemoryNodeManagerImpl for TestNodeManagerImpl {
        async fn init(&self, _address_space: &mut AddressSpace, _context: ServerContext) {}

        fn name(&self) -> &str {
            self.name
        }

        fn namespaces(&self) -> Vec<NamespaceMetadata> {
            vec![NamespaceMetadata {
                namespace_uri: self.namespace_uri.to_string(),
                namespace_index: self.namespace_index,
                ..Default::default()
            }]
        }
    }

    fn object(node_id: NodeId, browse_name: &str) -> Object {
        Object::new(
            &node_id,
            QualifiedName::new(1, browse_name),
            browse_name,
            EventNotifier::empty(),
        )
    }

    fn manager(
        name: &'static str,
        namespace_index: u16,
        namespace_uri: &'static str,
        nodes: Vec<Object>,
    ) -> Arc<InMemoryNodeManager<TestNodeManagerImpl>> {
        let mut address_space = AddressSpace::new();
        address_space.add_namespace(namespace_uri, namespace_index);
        for node in nodes {
            address_space.insert::<_, NodeId>(node, None);
        }

        Arc::new(InMemoryNodeManager::new(
            TestNodeManagerImpl {
                name,
                namespace_index,
                namespace_uri,
            },
            address_space,
        ))
    }

    fn delete_nodes_request(
        info: Arc<crate::ServerInfo>,
        subscriptions: Arc<crate::SubscriptionCache>,
        node_id: NodeId,
    ) -> Request<DeleteNodesRequest> {
        let session = Session::create(
            &info,
            NodeId::new(0, 1),
            1,
            60_000,
            0,
            0,
            UAString::from("opc.tcp://localhost"),
            opcua_crypto::SecurityPolicy::None.to_str().to_string(),
            IdentityToken::Anonymous(AnonymousIdentityToken {
                policy_id: UAString::from("anonymous"),
            }),
            None,
            ByteString::null(),
            UAString::from("cross-manager-delete-nodes-test"),
            ApplicationDescription::default(),
            MessageSecurityMode::None,
        );

        Request {
            request: Box::new(DeleteNodesRequest {
                request_header: RequestHeader::default(),
                nodes_to_delete: Some(vec![DeleteNodesItem {
                    node_id,
                    delete_target_references: true,
                }]),
            }),
            request_id: 1,
            request_handle: 1,
            info: info.clone(),
            session: Arc::new(RwLock::new(session)),
            token: UserToken("anonymous".to_string()),
            subscriptions,
            session_id: 1,
        }
    }

    #[tokio::test]
    async fn cross_manager_delete_nodes_delete_target_references_removes_source_manager_reference()
    {
        let mut builder =
            ServerBuilder::new_anonymous("cross manager delete nodes test").without_node_managers();
        builder.config_mut().limits.clients_can_modify_address_space = true;
        let (_server, handle) = builder.build().expect("test server should build");
        let info = handle.info().clone();
        {
            let mut type_tree = info.type_tree.write();
            type_tree.add_type_node(
                &NodeId::from(ReferenceTypeId::HasComponent),
                &NodeId::from(ReferenceTypeId::References),
                NodeClass::ReferenceType,
            );
        }

        let source_id = NodeId::new(2, "source-owned-by-manager-a");
        let target_id = NodeId::new(3, "target-owned-by-manager-b");
        let source_manager = manager(
            "manager-a",
            2,
            "urn:cross-manager-delete-nodes:a",
            vec![object(source_id.clone(), "Source")],
        );
        let target_manager = manager(
            "manager-b",
            3,
            "urn:cross-manager-delete-nodes:b",
            vec![object(target_id.clone(), "Target")],
        );

        source_manager.address_space().write().insert_reference(
            &source_id,
            &target_id,
            NodeId::from(ReferenceTypeId::HasComponent),
        );

        let node_managers = NodeManagers::new(vec![source_manager.clone(), target_manager]);
        let response = delete_nodes(
            node_managers,
            delete_nodes_request(info, handle.subscriptions().clone(), target_id.clone()),
        )
        .await;

        let ResponseMessage::DeleteNodes(response) = response.message else {
            panic!("expected DeleteNodes response");
        };
        assert_eq!(response.results.as_deref(), Some(&[StatusCode::Good][..]));
        assert!(
            !source_manager.address_space().read().has_reference(
                &source_id,
                &target_id,
                &NodeId::from(ReferenceTypeId::HasComponent)
            ),
            "OPC-10000-4 5.8.4.2 deleteTargetReferences=TRUE requires deleting references to \
             the deleted target node even when the referencing source node is owned by another \
             node manager"
        );
    }
}
