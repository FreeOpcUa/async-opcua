use std::sync::Arc;

use crate::{
    node_manager::{consume_results, DynNodeManager, MethodCall, NodeManagers, RequestContext},
    session::{
        controller::Response,
        message_handler::Request,
        services::{invoke_service_concurrently_mut, ServiceCb},
    },
};
use opcua_types::{CallRequest, CallResponse, ResponseHeader, StatusCode};
use tracing::debug_span;
use tracing_futures::Instrument;

pub(crate) async fn call(node_managers: NodeManagers, request: Request<CallRequest>) -> Response {
    let context = request.context();
    let method_calls = take_service_items!(
        request,
        request.request.methods_to_call,
        request.info.operational_limits.max_nodes_per_method_call
    );

    let mut calls: Vec<_> = method_calls
        .into_iter()
        .map(|c| MethodCall::new(c, request.request.request_header.return_diagnostics))
        .collect();

    struct MethodServiceCb;

    impl ServiceCb<MethodCall> for MethodServiceCb {
        async fn call(
            &self,
            items: &mut [&mut MethodCall],
            node_manager: &Arc<DynNodeManager>,
            context: RequestContext,
        ) {
            if let Err(e) = node_manager
                .call(&context, &mut *items)
                .instrument(debug_span!("Call", node_manager = %node_manager.name()))
                .await
            {
                for call in items {
                    call.set_status(e);
                }
            }
        }
    }

    invoke_service_concurrently_mut(
        context,
        &mut calls,
        &node_managers,
        MethodServiceCb,
        |call, node_manager| {
            node_manager.owns_node(call.method_id())
                && call.status() == StatusCode::BadMethodInvalid
        },
    )
    .await;

    let (results, diagnostic_infos) =
        consume_results(calls, request.request.request_header.return_diagnostics);

    Response {
        message: CallResponse {
            response_header: ResponseHeader::new_good(request.request_handle),
            results,
            diagnostic_infos,
        }
        .into(),
        request_id: request.request_id,
    }
}
