#![allow(dead_code, unreachable_pub)]

use std::time::Duration;

use crate::{
    session::{
        process_service_result, process_unexpected_response,
        request_builder::{builder_base, builder_debug, builder_error, RequestHeaderBuilder},
    },
    Session, UARequest,
};
use opcua_core::ResponseMessage;
use opcua_types::{
    ContentFilter, ContinuationPoint, Error, IntegerId, NodeId, NodeTypeDescription,
    QueryFirstRequest, QueryFirstResponse, QueryNextRequest, QueryNextResponse, ViewDescription,
};
use tracing::{debug_span, Instrument};

#[derive(Debug, Clone)]
/// Query the address space by sending a [`QueryFirstRequest`] to the server.
///
/// See OPC UA Part 4 - Services 5.9 for complete description of the service and error responses.
pub struct QueryFirst {
    view: ViewDescription,
    node_types: Vec<NodeTypeDescription>,
    filter: ContentFilter,
    max_data_sets_to_return: u32,
    max_references_to_return: u32,

    header: RequestHeaderBuilder,
}

builder_base!(QueryFirst);

impl QueryFirst {
    /// Construct a new call to the `QueryFirst` service.
    pub fn new(session: &Session) -> Self {
        Self {
            view: ViewDescription::default(),
            node_types: Vec::new(),
            filter: ContentFilter::default(),
            max_data_sets_to_return: 0,
            max_references_to_return: 0,

            header: RequestHeaderBuilder::new_from_session(session),
        }
    }

    /// Construct a new call to the `QueryFirst` service, setting header parameters manually.
    pub fn new_manual(
        session_id: u32,
        timeout: Duration,
        auth_token: NodeId,
        request_handle: IntegerId,
    ) -> Self {
        Self {
            view: ViewDescription::default(),
            node_types: Vec::new(),
            filter: ContentFilter::default(),
            max_data_sets_to_return: 0,
            max_references_to_return: 0,

            header: RequestHeaderBuilder::new(session_id, timeout, auth_token, request_handle),
        }
    }

    /// Set the view to query.
    pub fn view(mut self, view: ViewDescription) -> Self {
        self.view = view;
        self
    }

    /// Set node types to query, overwriting any that were set previously.
    pub fn node_types(mut self, node_types: Vec<NodeTypeDescription>) -> Self {
        self.node_types = node_types;
        self
    }

    /// Add a node type to query.
    pub fn node_type(mut self, node_type: impl Into<NodeTypeDescription>) -> Self {
        self.node_types.push(node_type.into());
        self
    }

    /// Set the content filter to apply to the query.
    pub fn filter(mut self, filter: ContentFilter) -> Self {
        self.filter = filter;
        self
    }

    /// Set max data sets to return. The default is zero, meaning server-defined.
    pub fn max_data_sets_to_return(mut self, max_data_sets_to_return: u32) -> Self {
        self.max_data_sets_to_return = max_data_sets_to_return;
        self
    }

    /// Set max references to return. The default is zero, meaning server-defined.
    pub fn max_references_to_return(mut self, max_references_to_return: u32) -> Self {
        self.max_references_to_return = max_references_to_return;
        self
    }
}

impl UARequest for QueryFirst {
    type Out = QueryFirstResponse;

    async fn send<'a>(self, channel: &'a crate::AsyncSecureChannel) -> Result<Self::Out, Error>
    where
        Self: 'a,
    {
        let span = debug_span!(
            "Sending QueryFirst request",
            num_node_types = self.node_types.len(),
            max_data_sets_to_return = self.max_data_sets_to_return,
            max_references_to_return = self.max_references_to_return
        );
        let request = {
            let _h = span.enter();
            QueryFirstRequest {
                request_header: self.header.header,
                view: self.view,
                node_types: if self.node_types.is_empty() {
                    None
                } else {
                    Some(self.node_types)
                },
                filter: self.filter,
                max_data_sets_to_return: self.max_data_sets_to_return,
                max_references_to_return: self.max_references_to_return,
            }
        };
        let response = channel
            .send(request, self.header.timeout)
            .instrument(span.clone())
            .await?;
        let _h = span.enter();
        if let ResponseMessage::QueryFirst(response) = response {
            builder_debug!(self, "query_first, success");
            process_service_result(&response.response_header)?;
            Ok(*response)
        } else {
            builder_error!(self, "query_first failed");
            Err(process_unexpected_response(response))
        }
    }
}

#[derive(Debug, Clone)]
/// Continue a query by sending a [`QueryNextRequest`] to the server.
///
/// See OPC UA Part 4 - Services 5.9 for complete description of the service and error responses.
pub struct QueryNext {
    release_continuation_point: bool,
    continuation_point: ContinuationPoint,

    header: RequestHeaderBuilder,
}

builder_base!(QueryNext);

impl QueryNext {
    /// Construct a new call to the `QueryNext` service.
    pub fn new(session: &Session) -> Self {
        Self {
            release_continuation_point: false,
            continuation_point: ContinuationPoint::default(),

            header: RequestHeaderBuilder::new_from_session(session),
        }
    }

    /// Construct a new call to the `QueryNext` service, setting header parameters manually.
    pub fn new_manual(
        session_id: u32,
        timeout: Duration,
        auth_token: NodeId,
        request_handle: IntegerId,
    ) -> Self {
        Self {
            release_continuation_point: false,
            continuation_point: ContinuationPoint::default(),

            header: RequestHeaderBuilder::new(session_id, timeout, auth_token, request_handle),
        }
    }

    /// Set release continuation point. Default is false, if this is true,
    /// the continuation point will be released and no results will be returned.
    pub fn release_continuation_point(mut self, release_continuation_point: bool) -> Self {
        self.release_continuation_point = release_continuation_point;
        self
    }

    /// Set the continuation point returned from `query_first` or `query_next`.
    pub fn continuation_point(mut self, continuation_point: ContinuationPoint) -> Self {
        self.continuation_point = continuation_point;
        self
    }
}

impl UARequest for QueryNext {
    type Out = QueryNextResponse;

    async fn send<'a>(self, channel: &'a crate::AsyncSecureChannel) -> Result<Self::Out, Error>
    where
        Self: 'a,
    {
        let span = debug_span!(
            "Sending QueryNext request",
            release_continuation_point = self.release_continuation_point
        );
        let request = {
            let _h = span.enter();
            QueryNextRequest {
                request_header: self.header.header,
                release_continuation_point: self.release_continuation_point,
                continuation_point: self.continuation_point,
            }
        };
        let response = channel
            .send(request, self.header.timeout)
            .instrument(span.clone())
            .await?;
        let _h = span.enter();
        if let ResponseMessage::QueryNext(response) = response {
            builder_debug!(self, "query_next, success");
            process_service_result(&response.response_header)?;
            Ok(*response)
        } else {
            builder_error!(self, "query_next failed");
            Err(process_unexpected_response(response))
        }
    }
}

impl Session {
    /// Query the address space by sending a [`QueryFirstRequest`] to the server.
    ///
    /// See OPC UA Part 4 - Services 5.9 for complete description of the service and error responses.
    ///
    /// # Arguments
    ///
    /// * `view` - The view to query.
    /// * `node_types` - Node type descriptions defining the queried node classes and returned attributes.
    /// * `filter` - A content filter applied by the server to matching nodes.
    /// * `max_data_sets_to_return` - Requested maximum number of data sets to return.
    /// * `max_references_to_return` - Requested maximum number of references to return.
    ///
    /// # Returns
    ///
    /// * `Ok(QueryFirstResponse)` - The full response containing query data sets and continuation point.
    /// * `Err(Error)` - Request failed, [Status code](opcua_types::StatusCode) is the reason for failure.
    pub async fn query_first(
        &self,
        view: ViewDescription,
        node_types: Vec<NodeTypeDescription>,
        filter: ContentFilter,
        max_data_sets_to_return: u32,
        max_references_to_return: u32,
    ) -> Result<QueryFirstResponse, Error> {
        QueryFirst::new(self)
            .view(view)
            .node_types(node_types)
            .filter(filter)
            .max_data_sets_to_return(max_data_sets_to_return)
            .max_references_to_return(max_references_to_return)
            .send(&self.channel)
            .await
    }

    /// Continue a query by sending a [`QueryNextRequest`] to the server.
    ///
    /// See OPC UA Part 4 - Services 5.9 for complete description of the service and error responses.
    ///
    /// # Arguments
    ///
    /// * `release_continuation_point` - Flag indicating if the continuation point should be released by the server.
    /// * `continuation_point` - Continuation point from a previous [`QueryFirstResponse`] or [`QueryNextResponse`].
    ///
    /// # Returns
    ///
    /// * `Ok(QueryNextResponse)` - The full response containing query data sets and revised continuation point.
    /// * `Err(Error)` - Request failed, [Status code](opcua_types::StatusCode) is the reason for failure.
    pub async fn query_next(
        &self,
        release_continuation_point: bool,
        continuation_point: ContinuationPoint,
    ) -> Result<QueryNextResponse, Error> {
        QueryNext::new(self)
            .release_continuation_point(release_continuation_point)
            .continuation_point(continuation_point)
            .send(&self.channel)
            .await
    }
}
