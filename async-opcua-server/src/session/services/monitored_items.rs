use std::{collections::HashMap, sync::Arc};

use crate::{
    node_manager::{
        DynNodeManager, MonitoredItemRef, MonitoredItemUpdateRef, NodeManagers, RequestContext,
    },
    session::{
        controller::Response,
        message_handler::Request,
        services::{
            invoke_service_concurrently, invoke_service_concurrently_mut, ServiceCb, ServiceCbRef,
        },
    },
    subscriptions::CreateMonitoredItem,
};
use opcua_core::ResponseMessage;
use opcua_types::{
    AttributeId, BrowsePath, CreateMonitoredItemsRequest, CreateMonitoredItemsResponse,
    DataChangeFilter, DeadbandType, DeleteMonitoredItemsRequest, DeleteMonitoredItemsResponse,
    ModifyMonitoredItemsRequest, ModifyMonitoredItemsResponse, MonitoringMode, NodeId, Range,
    ReadRequest, ReferenceTypeId, RelativePath, RelativePathElement, RequestHeader, ResponseHeader,
    SetMonitoringModeRequest, SetMonitoringModeResponse, StatusCode, TimestampsToReturn,
    TranslateBrowsePathsToNodeIdsRequest, Variant,
};
use tracing::debug_span;
use tracing_futures::Instrument;

use super::{read, translate_browse_paths};

// OPC-UA is sometimes very painful. In order to actually implement percent-deadband, we need to
// fetch the EURange property from the node hierarchy. This method does that by calling TranslateBrowsePaths
// and then Read.
async fn get_eu_range(
    items: &[&NodeId],
    context: &RequestContext,
    node_managers: &NodeManagers,
) -> HashMap<NodeId, (f64, f64)> {
    let mut res = HashMap::with_capacity(items.len());
    if items.is_empty() {
        return res;
    }

    // First we call TranslateBrowsePathsToNodeIds to get the node ID of each EURange item.
    let req = Request {
        request: Box::new(TranslateBrowsePathsToNodeIdsRequest {
            request_header: RequestHeader::dummy(),
            browse_paths: Some(
                items
                    .iter()
                    .map(|i| BrowsePath {
                        starting_node: (**i).clone(),
                        relative_path: RelativePath {
                            elements: Some(vec![RelativePathElement {
                                reference_type_id: ReferenceTypeId::HasProperty.into(),
                                is_inverse: false,
                                include_subtypes: true,
                                target_name: "EURange".into(),
                            }]),
                        },
                    })
                    .collect(),
            ),
        }),
        request_id: 0,
        request_handle: 0,
        info: context.info.clone(),
        session: context.session.clone(),
        token: context.token.clone(),
        subscriptions: context.subscriptions.clone(),
        session_id: context.session_id,
    };
    let response = translate_browse_paths(node_managers.clone(), req).await;
    let ResponseMessage::TranslateBrowsePathsToNodeIds(translated) = response.message else {
        return res;
    };
    if !translated.response_header.service_result.is_good() {
        return res;
    }
    let mut to_read = Vec::new();
    for (id, r) in items
        .iter()
        .zip(translated.results.into_iter().flat_map(|i| i.into_iter()))
    {
        // If this somehow results in multiple targets we just use the first.
        if let Some(p) = r.targets.and_then(|p| p.into_iter().next()) {
            if !p.target_id.namespace_uri.is_empty() || p.target_id.server_index != 0 {
                continue;
            }
            to_read.push((*id, p.target_id.node_id));
        }
    }
    if to_read.is_empty() {
        return res;
    }

    // Next we call Read on each discovered EURange node.
    let read_req = Request {
        request: Box::new(ReadRequest {
            request_header: RequestHeader::dummy(),
            max_age: 0.0,
            timestamps_to_return: TimestampsToReturn::Neither,
            nodes_to_read: Some(
                to_read
                    .iter()
                    .map(|r| opcua_types::ReadValueId {
                        node_id: r.1.clone(),
                        attribute_id: AttributeId::Value as u32,
                        ..Default::default()
                    })
                    .collect(),
            ),
        }),
        request_id: 0,
        request_handle: 0,
        info: context.info.clone(),
        session: context.session.clone(),
        token: context.token.clone(),
        subscriptions: context.subscriptions.clone(),
        session_id: context.session_id,
    };
    let read_res = read(node_managers.clone(), read_req).await;
    let ResponseMessage::Read(read) = read_res.message else {
        return res;
    };
    if !read.response_header.service_result.is_good() {
        return res;
    }

    for (id, dv) in to_read
        .into_iter()
        .map(|r| r.0)
        .zip(read.results.into_iter().flat_map(|r| r.into_iter()))
    {
        if dv.status.is_some_and(|s| !s.is_good()) {
            continue;
        }
        let Some(Variant::ExtensionObject(o)) = dv.value else {
            continue;
        };
        let Some(range) = o.inner_as::<Range>() else {
            continue;
        };
        res.insert(id.clone(), (range.low, range.high));
    }

    res
}

pub(crate) async fn create_monitored_items(
    node_managers: NodeManagers,
    request: Request<CreateMonitoredItemsRequest>,
) -> Response {
    let context = request.context();
    let items_to_create = take_service_items!(
        request,
        request.request.items_to_create,
        request.info.operational_limits.max_monitored_items_per_call
    );
    let Some(len) = request
        .subscriptions
        .get_monitored_item_count(request.session_id, request.request.subscription_id)
    else {
        return service_fault!(request, StatusCode::BadSubscriptionIdInvalid);
    };

    let max_per_sub = request
        .info
        .config
        .limits
        .subscriptions
        .max_monitored_items_per_sub;
    if max_per_sub > 0 && max_per_sub < len + items_to_create.len() {
        return service_fault!(request, StatusCode::BadTooManyMonitoredItems);
    }

    // Try to get EURange for each item with a percent deadband filter.
    let mut items_needing_deadband = Vec::new();
    for item in &items_to_create {
        let Some(filter) = item
            .requested_parameters
            .filter
            .inner_as::<DataChangeFilter>()
        else {
            continue;
        };

        if filter.deadband_type == DeadbandType::Percent as u32 {
            items_needing_deadband.push(&item.item_to_monitor.node_id);
        }
    }
    let ranges = get_eu_range(&items_needing_deadband, &context, &node_managers).await;

    let mut items: Vec<_> = {
        let type_tree = context.get_type_tree_for_user();
        items_to_create
            .into_iter()
            .map(|r| {
                let range = ranges.get(&r.item_to_monitor.node_id).copied();
                CreateMonitoredItem::new(
                    r,
                    request.info.monitored_item_id_handle.next(),
                    request.request.subscription_id,
                    &request.info,
                    request.request.timestamps_to_return,
                    type_tree.get(),
                    range,
                )
            })
            .collect()
    };

    struct CreateMonitoredItemsServiceCb;

    impl ServiceCb<CreateMonitoredItem> for CreateMonitoredItemsServiceCb {
        async fn call(
            &self,
            items: &mut [&mut CreateMonitoredItem],
            node_manager: &Arc<DynNodeManager>,
            context: RequestContext,
        ) {
            if let Err(e) = node_manager
                .create_monitored_items(&context, items)
                .instrument(
                    debug_span!("CreateMonitoredItems", node_manager = %node_manager.name()),
                )
                .await
            {
                for item in items {
                    item.set_status(e);
                }
            }
        }
    }

    invoke_service_concurrently_mut(
        context.clone(),
        &mut items,
        &node_managers,
        CreateMonitoredItemsServiceCb,
        |node, node_manager| {
            node.status_code() == StatusCode::BadNodeIdUnknown
                && node_manager.owns_node(&node.item_to_monitor().node_id)
        },
    )
    .await;

    let res = match request.subscriptions.create_monitored_items(
        request.session_id,
        request.request.subscription_id,
        &items,
    ) {
        Ok(r) => r,
        // Shouldn't happen, would be due to a race condition. If it does happen we're fine with failing.
        Err(e) => {
            let handles: Vec<_> = items
                .iter()
                .map(|i| {
                    MonitoredItemRef::new(
                        i.handle(),
                        i.item_to_monitor().node_id.clone(),
                        i.item_to_monitor().attribute_id,
                    )
                })
                .collect();
            struct CleanupCb;
            impl ServiceCbRef<MonitoredItemRef> for CleanupCb {
                async fn call(
                    &self,
                    items: &[&MonitoredItemRef],
                    node_manager: &Arc<DynNodeManager>,
                    context: RequestContext,
                ) {
                    node_manager
                        .delete_monitored_items(&context, items)
                        .instrument(
                            debug_span!("DeleteMonitoredItems", node_manager = %node_manager.name()),
                        )
                        .await;
                }
            }
            invoke_service_concurrently(
                context,
                &handles,
                &node_managers,
                CleanupCb,
                |node, node_manager| node_manager.owns_node(node.node_id()),
            )
            .await;

            return service_fault!(request, e);
        }
    };

    Response {
        message: CreateMonitoredItemsResponse {
            response_header: ResponseHeader::new_good(request.request_handle),
            results: Some(res),
            diagnostic_infos: None,
        }
        .into(),
        request_id: request.request_id,
    }
}

pub(crate) async fn modify_monitored_items(
    node_managers: NodeManagers,
    request: Request<ModifyMonitoredItemsRequest>,
) -> Response {
    let context = request.context();
    let items_to_modify = take_service_items!(
        request,
        request.request.items_to_modify,
        request.info.operational_limits.max_monitored_items_per_call
    );

    // Call modify first, then only pass successful modify's to the node managers.
    let results = {
        let type_tree = context.get_type_tree_for_user();

        match request.subscriptions.modify_monitored_items(
            request.session_id,
            request.request.subscription_id,
            &request.info,
            request.request.timestamps_to_return,
            items_to_modify,
            type_tree.get(),
        ) {
            Ok(r) => r,
            Err(e) => return service_fault!(request, e),
        }
    };

    struct ModifyMonitoredItemsServiceCb;

    impl ServiceCbRef<MonitoredItemUpdateRef> for ModifyMonitoredItemsServiceCb {
        async fn call(
            &self,
            items: &[&MonitoredItemUpdateRef],
            node_manager: &Arc<DynNodeManager>,
            context: RequestContext,
        ) {
            node_manager
                .modify_monitored_items(&context, items)
                .instrument(
                    debug_span!("ModifyMonitoredItems", node_manager = %node_manager.name()),
                )
                .await;
        }
    }

    invoke_service_concurrently(
        context,
        &results,
        &node_managers,
        ModifyMonitoredItemsServiceCb,
        |node, node_manager| node.status_code().is_good() && node_manager.owns_node(node.node_id()),
    )
    .await;

    Response {
        message: ModifyMonitoredItemsResponse {
            response_header: ResponseHeader::new_good(request.request_handle),
            results: Some(results.into_iter().map(|r| r.into_result()).collect()),
            diagnostic_infos: None,
        }
        .into(),
        request_id: request.request_id,
    }
}

pub(crate) async fn set_monitoring_mode(
    node_managers: NodeManagers,
    request: Request<SetMonitoringModeRequest>,
) -> Response {
    let context = request.context();
    let items = take_service_items!(
        request,
        request.request.monitored_item_ids,
        request.info.operational_limits.max_monitored_items_per_call
    );

    let results = match request.subscriptions.set_monitoring_mode(
        request.session_id,
        request.request.subscription_id,
        request.request.monitoring_mode,
        items,
    ) {
        Ok(r) => r,
        Err(e) => return service_fault!(request, e),
    };

    struct SetMonitoringModeServiceCb {
        mode: MonitoringMode,
    }

    impl ServiceCbRef<(StatusCode, MonitoredItemRef)> for SetMonitoringModeServiceCb {
        async fn call(
            &self,
            items: &[&(StatusCode, MonitoredItemRef)],
            node_manager: &Arc<DynNodeManager>,
            context: RequestContext,
        ) {
            node_manager
                .set_monitoring_mode(
                    &context,
                    self.mode,
                    &items.iter().map(|n| &n.1).collect::<Vec<_>>(),
                )
                .instrument(debug_span!("SetMonitoringMode", node_manager = %node_manager.name()))
                .await;
        }
    }

    invoke_service_concurrently(
        context.clone(),
        &results,
        &node_managers,
        SetMonitoringModeServiceCb {
            mode: request.request.monitoring_mode,
        },
        |node, node_manager| node.0.is_good() && node_manager.owns_node(node.1.node_id()),
    )
    .await;

    Response {
        message: SetMonitoringModeResponse {
            response_header: ResponseHeader::new_good(request.request_handle),
            results: Some(results.into_iter().map(|r| r.0).collect()),
            diagnostic_infos: None,
        }
        .into(),
        request_id: request.request_id,
    }
}

pub(crate) async fn delete_monitored_items(
    node_managers: NodeManagers,
    request: Request<DeleteMonitoredItemsRequest>,
) -> Response {
    let context = request.context();
    let items = take_service_items!(
        request,
        request.request.monitored_item_ids,
        request.info.operational_limits.max_monitored_items_per_call
    );

    let results = match request.subscriptions.delete_monitored_items(
        request.session_id,
        request.request.subscription_id,
        &items,
    ) {
        Ok(r) => r,
        Err(e) => return service_fault!(request, e),
    };

    struct DeleteMonitoredItemsServiceCb;

    impl ServiceCbRef<(StatusCode, MonitoredItemRef)> for DeleteMonitoredItemsServiceCb {
        async fn call(
            &self,
            items: &[&(StatusCode, MonitoredItemRef)],
            node_manager: &Arc<DynNodeManager>,
            context: RequestContext,
        ) {
            node_manager
                .delete_monitored_items(&context, &items.iter().map(|n| &n.1).collect::<Vec<_>>())
                .instrument(
                    debug_span!("DeleteMonitoredItems", node_manager = %node_manager.name()),
                )
                .await;
        }
    }

    invoke_service_concurrently(
        context.clone(),
        &results,
        &node_managers,
        DeleteMonitoredItemsServiceCb,
        |node, node_manager| node.0.is_good() && node_manager.owns_node(node.1.node_id()),
    )
    .await;

    Response {
        message: DeleteMonitoredItemsResponse {
            response_header: ResponseHeader::new_good(request.request_handle),
            results: Some(results.into_iter().map(|r| r.0).collect()),
            diagnostic_infos: None,
        }
        .into(),
        request_id: request.request_id,
    }
}
