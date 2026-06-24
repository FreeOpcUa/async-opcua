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
    ByteString, CallMethodRequest, CallMethodResult, CallRequest, CallResponse, Error, IntegerId,
    LocalizedText, MethodId, NodeId, ObjectId, ObjectTypeId, StatusCode, TryFromVariant, Variant,
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

    async fn send<'a>(self, channel: &'a AsyncSecureChannel) -> Result<Self::Out, Error>
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
                return Err(Error::new(
                    StatusCode::BadNothingToDo,
                    "call was not supplied with any methods to call",
                ));
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
                    Err(Error::new(
                        StatusCode::BadUnexpectedError,
                        format!(
                            "call(), expecting {cnt} results from the call to the server, got {} results",
                            results.len()
                        ),
                    ))
                } else {
                    Ok(*response)
                }
            } else {
                builder_error!(
                    self,
                    "call(), expecting a result from the call to the server, got nothing"
                );
                Err(Error::new(
                    StatusCode::BadUnexpectedError,
                    "call(), expecting a result from the call to the server, got nothing",
                ))
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
    /// * `Err(Error)` - Request failed, [Status code](StatusCode) is the reason for failure.
    ///
    pub async fn call(
        &self,
        methods: Vec<CallMethodRequest>,
    ) -> Result<Vec<CallMethodResult>, Error> {
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
    /// * `Err(Error)` - Request failed, [Status code](StatusCode) is the reason for failure.
    ///
    pub async fn call_one(
        &self,
        method: impl Into<CallMethodRequest>,
    ) -> Result<CallMethodResult, Error> {
        Ok(self
            .call(vec![method.into()])
            .await?
            .into_iter()
            .next()
            .unwrap())
    }

    /// Calls the ConditionRefresh method for an event subscription.
    ///
    /// This asks the server to resend the current retained condition state for all event monitored
    /// items in the subscription.
    ///
    /// # Arguments
    ///
    /// * `subscription_id` - Server allocated identifier for the subscription to refresh.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] if the Call service fails or if the method operation status is not Good.
    pub async fn refresh_conditions(&self, subscription_id: u32) -> Result<(), Error> {
        let result = self
            .call_one((
                NodeId::from(ObjectTypeId::ConditionType),
                NodeId::from(MethodId::ConditionType_ConditionRefresh),
                Some(vec![Variant::from(subscription_id)]),
            ))
            .await?;

        method_status_to_result(
            result.status_code,
            "ConditionRefresh returned bad status code",
        )
    }

    /// Calls the ConditionRefresh2 method for one event monitored item.
    ///
    /// This asks the server to resend the current retained condition state for a single event
    /// monitored item in the subscription.
    ///
    /// # Arguments
    ///
    /// * `subscription_id` - Server allocated identifier for the subscription to refresh.
    /// * `monitored_item_id` - Server allocated identifier for the monitored item to refresh.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] if the Call service fails or if the method operation status is not Good.
    pub async fn refresh_conditions_for_item(
        &self,
        subscription_id: u32,
        monitored_item_id: u32,
    ) -> Result<(), Error> {
        let result = self
            .call_one((
                NodeId::from(ObjectTypeId::ConditionType),
                NodeId::from(MethodId::ConditionType_ConditionRefresh2),
                Some(vec![
                    Variant::from(subscription_id),
                    Variant::from(monitored_item_id),
                ]),
            ))
            .await?;

        method_status_to_result(
            result.status_code,
            "ConditionRefresh2 returned bad status code",
        )
    }

    /// Calls the Acknowledge method on an AcknowledgeableCondition instance.
    ///
    /// # Arguments
    ///
    /// * `condition_id` - NodeId of the condition instance to acknowledge.
    /// * `event_id` - EventId of the condition event being acknowledged.
    /// * `comment` - Human-readable acknowledgement comment.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] if the Call service fails or if the method operation status is not Good.
    pub async fn acknowledge_condition(
        &self,
        condition_id: &NodeId,
        event_id: ByteString,
        comment: impl Into<LocalizedText>,
    ) -> Result<(), Error> {
        let result = self
            .call_one((
                condition_id.clone(),
                NodeId::from(MethodId::AcknowledgeableConditionType_Acknowledge),
                Some(vec![Variant::from(event_id), Variant::from(comment.into())]),
            ))
            .await?;

        method_status_to_result(result.status_code, "Acknowledge returned bad status code")
    }

    /// Calls the Confirm method on an AcknowledgeableCondition instance.
    ///
    /// # Arguments
    ///
    /// * `condition_id` - NodeId of the condition instance to confirm.
    /// * `event_id` - EventId of the condition event being confirmed.
    /// * `comment` - Human-readable confirmation comment.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] if the Call service fails or if the method operation status is not Good.
    pub async fn confirm_condition(
        &self,
        condition_id: &NodeId,
        event_id: ByteString,
        comment: impl Into<LocalizedText>,
    ) -> Result<(), Error> {
        let result = self
            .call_one((
                condition_id.clone(),
                NodeId::from(MethodId::AcknowledgeableConditionType_Confirm),
                Some(vec![Variant::from(event_id), Variant::from(comment.into())]),
            ))
            .await?;

        method_status_to_result(result.status_code, "Confirm returned bad status code")
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
    /// * `Err(Error)` - Request failed, [Status code](StatusCode) is the reason for failure.
    ///
    pub async fn call_get_monitored_items(
        &self,
        subscription_id: u32,
    ) -> Result<(Vec<u32>, Vec<u32>), Error> {
        let args = Some(vec![Variant::from(subscription_id)]);
        let object_id: NodeId = ObjectId::Server.into();
        let method_id: NodeId = MethodId::Server_GetMonitoredItems.into();
        let request: CallMethodRequest = (object_id, method_id, args).into();
        let response = self.call_one(request).await?;
        if let Some(mut result) = response.output_arguments {
            if result.len() == 2 {
                let server_handles = <Vec<u32>>::try_from_variant(result.remove(0))?;
                let client_handles = <Vec<u32>>::try_from_variant(result.remove(0))?;
                Ok((server_handles, client_handles))
            } else {
                session_error!(
                    self,
                    "Expected a result with 2 args but got {}",
                    result.len()
                );
                Err(Error::new(
                    StatusCode::BadUnexpectedError,
                    format!("Expected a result with 2 args but got {}", result.len()),
                ))
            }
        } else {
            session_error!(self, "Expected 2 output arguments but got null");
            Err(Error::new(
                StatusCode::BadUnexpectedError,
                "Expected 2 output arguments but got null",
            ))
        }
    }
}

fn method_status_to_result(status_code: StatusCode, context: &'static str) -> Result<(), Error> {
    if status_code.is_good() {
        Ok(())
    } else {
        Err(Error::new(status_code, context))
    }
}
