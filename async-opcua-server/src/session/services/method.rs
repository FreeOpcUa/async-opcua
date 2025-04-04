use crate::{
    node_manager::{consume_results, MethodCall, NodeManagers},
    session::{controller::Response, message_handler::Request},
};
use opcua_types::{CallRequest, CallResponse, ResponseHeader, StatusCode};
use tracing::debug_span;
use tracing_futures::Instrument;

pub async fn call(node_managers: NodeManagers, request: Request<CallRequest>) -> Response {
    let mut context = request.context();
    let method_calls = take_service_items!(
        request,
        request.request.methods_to_call,
        request.info.operational_limits.max_nodes_per_method_call
    );

    let mut calls: Vec<_> = method_calls
        .into_iter()
        .map(|c| MethodCall::new(c, request.request.request_header.return_diagnostics))
        .collect();

    for (idx, node_manager) in node_managers.into_iter().enumerate() {
        context.current_node_manager_index = idx;
        let mut owned: Vec<_> = calls
            .iter_mut()
            .filter(|c| {
                node_manager.owns_node(c.method_id()) && c.status() == StatusCode::BadMethodInvalid
            })
            .collect();

        if owned.is_empty() {
            continue;
        }

        if let Err(e) = node_manager
            .call(&context, &mut owned)
            .instrument(debug_span!("Call", node_manager = %node_manager.name()))
            .await
        {
            for call in owned {
                call.set_status(e);
            }
        }
    }

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
