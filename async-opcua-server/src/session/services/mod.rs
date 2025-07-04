macro_rules! take_service_items {
    ($request:ident, $items:expr, $limit:expr) => {{
        let Some(it) = $items else {
            return service_fault!($request, StatusCode::BadNothingToDo);
        };
        if it.is_empty() {
            return service_fault!($request, StatusCode::BadNothingToDo);
        }
        if it.len() > $limit {
            return service_fault!($request, StatusCode::BadTooManyOperations);
        }
        it
    }};
}

mod attribute;
mod method;
mod monitored_items;
mod node_management;
mod query;
mod subscriptions;
mod view;

use std::{future::Future, sync::Arc};

pub(super) use attribute::*;
pub(super) use method::*;
pub(super) use monitored_items::*;
pub(super) use node_management::*;
pub(super) use query::*;
pub(super) use subscriptions::*;
pub(super) use view::*;

use crate::node_manager::{DynNodeManager, NodeManagers, RequestContext};

trait ServiceCb<T> {
    fn call(
        &self,
        items: &mut [&mut T],
        node_manager: &Arc<DynNodeManager>,
        context: RequestContext,
    ) -> impl Future<Output = ()> + Send;
}

/// Invokes a service concurrently across multiple node managers.
/// Note that this assumes that each item is owned by exactly one node manager.
/// If multiple return true for `filter`, the first one will be used.
/// You need to manually implement the `ServiceCb` trait. This is a workaround
/// for the lack of return type notation on async closures, otherwise we could use
/// AsyncFn instead.
async fn invoke_service_concurrently_mut<T, F>(
    context: RequestContext,
    items: &mut [T],
    node_managers: &NodeManagers,
    service: F,
    filter: impl Fn(&T, &Arc<DynNodeManager>) -> bool,
) where
    F: ServiceCb<T> + Send + Sync,
{
    // Reuse a slice of mutable references.
    // For each node manager, move the items that match the filter to the front of the slice.
    // Then split the refs slice into two parts: the matching items and the rest.
    // This way we don't need to allocate a new vector for each node manager.
    // We do still need to allocate a vector for the references, but
    // since we need to preserve the original order of the items, this is unavoidable.
    let mut refs = items.iter_mut().collect::<Vec<_>>();
    let mut refs_ch = refs.as_mut_slice();
    let mut futures = Vec::with_capacity(node_managers.len());
    for (i, node_manager) in node_managers.iter().enumerate() {
        let mut end_idx = 0;
        for i in 0..refs_ch.len() {
            if filter(refs_ch[i], node_manager) {
                refs_ch.swap(end_idx, i);
                end_idx += 1;
            }
        }

        let (group, next_ch) = refs_ch.split_at_mut(end_idx);
        refs_ch = next_ch;

        if !group.is_empty() {
            let mut ctx = context.clone();
            ctx.current_node_manager_index = i;
            futures.push(service.call(group, node_manager, ctx));
        }
    }
    futures::future::join_all(futures).await;
}

trait ServiceCbRef<T> {
    fn call(
        &self,
        items: &[&T],
        node_manager: &Arc<DynNodeManager>,
        context: RequestContext,
    ) -> impl Future<Output = ()> + Send;
}

async fn invoke_service_concurrently<T, F>(
    context: RequestContext,
    items: &[T],
    node_managers: &NodeManagers,
    service: F,
    filter: impl Fn(&T, &Arc<DynNodeManager>) -> bool,
) where
    F: ServiceCbRef<T> + Send + Sync,
{
    // Reuse a slice of references.
    // For each node manager, move the items that match the filter to the front of the slice.
    // Then split the refs slice into two parts: the matching items and the rest.
    // This way we don't need to allocate a new vector for each node manager.
    // We do still need to allocate a vector for the references, but
    // since we need to preserve the original order of the items, this is unavoidable.
    let mut refs = items.iter().collect::<Vec<_>>();
    let mut refs_ch = refs.as_mut_slice();
    let mut futures = Vec::with_capacity(node_managers.len());
    for (i, node_manager) in node_managers.iter().enumerate() {
        let mut end_idx = 0;
        for i in 0..refs_ch.len() {
            if filter(refs_ch[i], node_manager) {
                refs_ch.swap(end_idx, i);
                end_idx += 1;
            }
        }

        let (group, next_ch) = refs_ch.split_at_mut(end_idx);
        refs_ch = next_ch;

        if !group.is_empty() {
            let mut ctx = context.clone();
            ctx.current_node_manager_index = i;
            futures.push(service.call(group, node_manager, ctx));
        }
    }
    futures::future::join_all(futures).await;
}
