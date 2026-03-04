use std::time::Duration;

use crate::{
    session::{
        process_unexpected_response,
        request_builder::{builder_base, builder_error, RequestHeaderBuilder},
        session_error,
    },
    AsyncSecureChannel, Session, UARequest,
};
use opcua_core::ResponseMessage;
use opcua_types::{
    CallMethodRequest, CallMethodResult, CallRequest, CallResponse, IntegerId, MethodId, NodeId,
    ObjectId, StatusCode, TryFromVariant, Variant,
};
use tracing::{debug_span, Instrument};

#[derive(Debug, Clone)]
/// Calls a list of methods on the server by sending a [`CallRequest`] to the server.
///
/// See OPC UA Part 4 - Services 5.11.2 for complete description of the service and error responses.
pub struct Call {
    methods: Vec<CallMethodRequest>,

    header: RequestHeaderBuilder,
}

builder_base!(Call);

impl Call {
    /// Create a new call to the `Call` service.
    pub fn new(session: &Session) -> Self {
        Self {
            methods: Vec::new(),
            header: RequestHeaderBuilder::new_from_session(session),
        }
    }

    /// Construct a new call to the `Call` service, setting header parameters manually.
    pub fn new_manual(
        session_id: u32,
        timeout: Duration,
        auth_token: NodeId,
        request_handle: IntegerId,
    ) -> Self {
        Self {
            methods: Vec::new(),
            header: RequestHeaderBuilder::new(session_id, timeout, auth_token, request_handle),
        }
    }

    /// Set the list of methods to call.
    pub fn methods_to_call(mut self, methods: Vec<CallMethodRequest>) -> Self {
        self.methods = methods;
        self
    }

    /// Add a method to call.
    pub fn method(mut self, method: impl Into<CallMethodRequest>) -> Self {
        self.methods.push(method.into());
        self
    }
}

impl UARequest for Call {
    type Out = CallResponse;

    async fn send<'a>(self, channel: &'a AsyncSecureChannel) -> Result<Self::Out, StatusCode>
    where
        Self: 'a,
    {
        let span = debug_span!(
            "Sending Call request",
            num_method_calls = self.methods.len()
        );
        let cnt = self.methods.len();
        let request = {
            let _h = span.enter();
            if self.methods.is_empty() {
                builder_error!(self, "call(), was not supplied with any methods to call");
                return Err(StatusCode::BadNothingToDo);
            }

            CallRequest {
                request_header: self.header.header,
                methods_to_call: Some(self.methods),
            }
        };

        let response = channel
            .send(request, self.header.timeout)
            .instrument(span.clone())
            .await?;
        let _h = span.enter();
        if let ResponseMessage::Call(response) = response {
            if let Some(results) = &response.results {
                if results.len() != cnt {
                    builder_error!(
                        self,
                        "call(), expecting {cnt} results from the call to the server, got {} results",
                        results.len()
                    );
                    Err(StatusCode::BadUnexpectedError)
                } else {
                    Ok(*response)
                }
            } else {
                builder_error!(
                    self,
                    "call(), expecting a result from the call to the server, got nothing"
                );
                Err(StatusCode::BadUnexpectedError)
            }
        } else {
            Err(process_unexpected_response(response))
        }
    }
}

impl Session {
    /// Calls a list of methods on the server by sending a [`CallRequest`] to the server.
    ///
    /// See OPC UA Part 4 - Services 5.11.2 for complete description of the service and error responses.
    ///
    /// # Arguments
    ///
    /// * `methods` - The method to call.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<CallMethodResult>)` - A [`CallMethodResult`] for the Method call.
    /// * `Err(StatusCode)` - Request failed, [Status code](StatusCode) is the reason for failure.
    ///
    pub async fn call(
        &self,
        methods: Vec<CallMethodRequest>,
    ) -> Result<Vec<CallMethodResult>, StatusCode> {
        Ok(Call::new(self)
            .methods_to_call(methods)
            .send(&self.channel)
            .await?
            .results
            .unwrap_or_default())
    }

    /// Calls a single method on an object on the server by sending a [`CallRequest`] to the server.
    ///
    /// See OPC UA Part 4 - Services 5.11.2 for complete description of the service and error responses.
    ///
    /// # Arguments
    ///
    /// * `method` - The method to call. Note this function takes anything that can be turned into
    ///   a [`CallMethodRequest`] which includes a ([`NodeId`], [`NodeId`], `Option<Vec<Variant>>`) tuple
    ///   which refers to the object id, method id, and input arguments respectively.
    ///
    /// # Returns
    ///
    /// * `Ok(CallMethodResult)` - A [`CallMethodResult`] for the Method call.
    /// * `Err(StatusCode)` - Request failed, [Status code](StatusCode) is the reason for failure.
    ///
    pub async fn call_one(
        &self,
        method: impl Into<CallMethodRequest>,
    ) -> Result<CallMethodResult, StatusCode> {
        Ok(self
            .call(vec![method.into()])
            .await?
            .into_iter()
            .next()
            .unwrap())
    }

    /// Calls GetMonitoredItems via call_method(), putting a sane interface on the input / output.
    ///
    /// # Arguments
    ///
    /// * `subscription_id` - Server allocated identifier for the subscription to return monitored items for.
    ///
    /// # Returns
    ///
    /// * `Ok((Vec<u32>, Vec<u32>))` - Result for call, consisting a list of (monitored_item_id, client_handle)
    /// * `Err(StatusCode)` - Request failed, [Status code](StatusCode) is the reason for failure.
    ///
    pub async fn call_get_monitored_items(
        &self,
        subscription_id: u32,
    ) -> Result<(Vec<u32>, Vec<u32>), StatusCode> {
        let args = Some(vec![Variant::from(subscription_id)]);
        let object_id: NodeId = ObjectId::Server.into();
        let method_id: NodeId = MethodId::Server_GetMonitoredItems.into();
        let request: CallMethodRequest = (object_id, method_id, args).into();
        let response = self.call_one(request).await?;
        if let Some(mut result) = response.output_arguments {
            if result.len() == 2 {
                let server_handles = <Vec<u32>>::try_from_variant(result.remove(0))
                    .map_err(|_| StatusCode::BadUnexpectedError)?;
                let client_handles = <Vec<u32>>::try_from_variant(result.remove(0))
                    .map_err(|_| StatusCode::BadUnexpectedError)?;
                Ok((server_handles, client_handles))
            } else {
                session_error!(
                    self,
                    "Expected a result with 2 args but got {}",
                    result.len()
                );
                Err(StatusCode::BadUnexpectedError)
            }
        } else {
            session_error!(self, "Expected output arguments but got null");
            Err(StatusCode::BadUnexpectedError)
        }
    }
}
