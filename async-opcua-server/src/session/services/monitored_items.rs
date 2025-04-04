use std::collections::HashMap;

use crate::{
    node_manager::{MonitoredItemRef, NodeManagers, RequestContext},
    session::{controller::Response, message_handler::Request},
    subscriptions::CreateMonitoredItem,
};
use opcua_core::ResponseMessage;
use opcua_types::{
    AttributeId, BrowsePath, CreateMonitoredItemsRequest, CreateMonitoredItemsResponse,
    DataChangeFilter, DeadbandType, DeleteMonitoredItemsRequest, DeleteMonitoredItemsResponse,
    ModifyMonitoredItemsRequest, ModifyMonitoredItemsResponse, NodeId, Range, ReadRequest,
    ReferenceTypeId, RelativePath, RelativePathElement, RequestHeader, ResponseHeader,
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
            if !p.target_id.namespace_uri.is_null() || p.target_id.server_index != 0 {
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

pub async fn create_monitored_items(
    node_managers: NodeManagers,
    request: Request<CreateMonitoredItemsRequest>,
) -> Response {
    let mut context = request.context();
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

    for (idx, mgr) in node_managers.iter().enumerate() {
        context.current_node_manager_index = idx;
        let mut owned: Vec<_> = items
            .iter_mut()
            .filter(|n| {
                n.status_code() == StatusCode::BadNodeIdUnknown
                    && mgr.owns_node(&n.item_to_monitor().node_id)
            })
            .collect();

        if owned.is_empty() {
            continue;
        }

        if let Err(e) = mgr
            .create_monitored_items(&context, &mut owned)
            .instrument(debug_span!("CreateMonitoredItems", node_manager = %mgr.name()))
            .await
        {
            for n in owned {
                n.set_status(e);
            }
        }
    }

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
    let handles_ref: Vec<_> = handles.iter().collect();

    let res = match request.subscriptions.create_monitored_items(
        request.session_id,
        request.request.subscription_id,
        &items,
    ) {
        Ok(r) => r,
        // Shouldn't happen, would be due to a race condition. If it does happen we're fine with failing.
        Err(e) => {
            // Should clean up any that failed to create though.
            for (idx, mgr) in node_managers.iter().enumerate() {
                context.current_node_manager_index = idx;
                mgr.delete_monitored_items(&context, &handles_ref)
                    .instrument(debug_span!("DeleteMonitoredItems", node_manager = %mgr.name()))
                    .await;
            }
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

pub async fn modify_monitored_items(
    node_managers: NodeManagers,
    request: Request<ModifyMonitoredItemsRequest>,
) -> Response {
    let mut context = request.context();
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

    for (idx, mgr) in node_managers.iter().enumerate() {
        context.current_node_manager_index = idx;
        let owned: Vec<_> = results
            .iter()
            .filter(|n| n.status_code().is_good() && mgr.owns_node(n.node_id()))
            .collect();

        if owned.is_empty() {
            continue;
        }

        mgr.modify_monitored_items(&context, &owned)
            .instrument(debug_span!("ModifyMonitoredItems", node_manager = %mgr.name()))
            .await;
    }

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

pub async fn set_monitoring_mode(
    node_managers: NodeManagers,
    request: Request<SetMonitoringModeRequest>,
) -> Response {
    let mut context = request.context();
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

    for (idx, mgr) in node_managers.iter().enumerate() {
        context.current_node_manager_index = idx;
        let owned: Vec<_> = results
            .iter()
            .filter(|n| n.0.is_good() && mgr.owns_node(n.1.node_id()))
            .map(|n| &n.1)
            .collect();

        if owned.is_empty() {
            continue;
        }

        mgr.set_monitoring_mode(&context, request.request.monitoring_mode, &owned)
            .instrument(debug_span!("SetMonitoringMode", node_manager = %mgr.name()))
            .await;
    }

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

pub async fn delete_monitored_items(
    node_managers: NodeManagers,
    request: Request<DeleteMonitoredItemsRequest>,
) -> Response {
    let mut context = request.context();
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

    for (idx, mgr) in node_managers.iter().enumerate() {
        context.current_node_manager_index = idx;
        let owned: Vec<_> = results
            .iter()
            .filter(|n| n.0.is_good() && mgr.owns_node(n.1.node_id()))
            .map(|n| &n.1)
            .collect();

        if owned.is_empty() {
            continue;
        }

        mgr.delete_monitored_items(&context, &owned)
            .instrument(debug_span!("DeleteMonitoredItems", node_manager = %mgr.name()))
            .await;
    }

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
