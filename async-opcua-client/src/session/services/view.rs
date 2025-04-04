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
    BrowseDescription, BrowseNextRequest, BrowseNextResponse, BrowsePath, BrowsePathResult,
    BrowseRequest, BrowseResponse, BrowseResult, ByteString, IntegerId, NodeId,
    RegisterNodesRequest, RegisterNodesResponse, StatusCode, TranslateBrowsePathsToNodeIdsRequest,
    TranslateBrowsePathsToNodeIdsResponse, UnregisterNodesRequest, UnregisterNodesResponse,
    ViewDescription,
};

#[derive(Debug, Clone)]
/// Discover the references to the specified nodes by sending a [`BrowseRequest`] to the server.
///
/// See OPC UA Part 4 - Services 5.8.2 for complete description of the service and error responses.
pub struct Browse {
    nodes_to_browse: Vec<BrowseDescription>,
    view: ViewDescription,
    max_references_per_node: u32,

    header: RequestHeaderBuilder,
}

builder_base!(Browse);

impl Browse {
    /// Construct a new call to the `Browse` service.
    pub fn new(session: &Session) -> Self {
        Self {
            nodes_to_browse: Vec::new(),
            view: ViewDescription::default(),
            max_references_per_node: 0,

            header: RequestHeaderBuilder::new_from_session(session),
        }
    }

    /// Construct a new call to the `Browse` service, setting header parameters manually.
    pub fn new_manual(
        session_id: u32,
        timeout: Duration,
        auth_token: NodeId,
        request_handle: IntegerId,
    ) -> Self {
        Self {
            nodes_to_browse: Vec::new(),
            view: ViewDescription::default(),
            max_references_per_node: 0,

            header: RequestHeaderBuilder::new(session_id, timeout, auth_token, request_handle),
        }
    }

    /// Set the view to browse.
    pub fn view(mut self, view: ViewDescription) -> Self {
        self.view = view;
        self
    }

    /// Set max references per node. The default is zero, meaning server-defined.
    pub fn max_references_per_node(mut self, max_references_per_node: u32) -> Self {
        self.max_references_per_node = max_references_per_node;
        self
    }

    /// Set nodes to browse, overwriting any that were set previously.
    pub fn nodes_to_browse(mut self, nodes_to_browse: Vec<BrowseDescription>) -> Self {
        self.nodes_to_browse = nodes_to_browse;
        self
    }

    /// Add a node to browse.
    pub fn browse_node(mut self, node_to_browse: impl Into<BrowseDescription>) -> Self {
        self.nodes_to_browse.push(node_to_browse.into());
        self
    }
}

impl UARequest for Browse {
    type Out = BrowseResponse;

    async fn send<'a>(self, channel: &'a crate::AsyncSecureChannel) -> Result<Self::Out, StatusCode>
    where
        Self: 'a,
    {
        if self.nodes_to_browse.is_empty() {
            builder_error!(self, "browse was not supplied with any nodes to browse");
            return Err(StatusCode::BadNothingToDo);
        }
        let request = BrowseRequest {
            request_header: self.header.header,
            view: self.view,
            requested_max_references_per_node: self.max_references_per_node,
            nodes_to_browse: Some(self.nodes_to_browse),
        };
        let response = channel.send(request, self.header.timeout).await?;
        if let ResponseMessage::Browse(response) = response {
            builder_debug!(self, "browse, success");
            process_service_result(&response.response_header)?;
            Ok(*response)
        } else {
            builder_error!(self, "browse failed");
            Err(process_unexpected_response(response))
        }
    }
}

#[derive(Debug, Clone)]
/// Continue to discover references to nodes by sending continuation points in a [`BrowseNextRequest`]
/// to the server. This function may have to be called repeatedly to process the initial query.
///
/// See OPC UA Part 4 - Services 5.8.3 for complete description of the service and error responses.
pub struct BrowseNext {
    continuation_points: Vec<ByteString>,
    release_continuation_points: bool,

    header: RequestHeaderBuilder,
}

builder_base!(BrowseNext);

impl BrowseNext {
    /// Construct a new call to the `BrowseNext` service.
    pub fn new(session: &Session) -> Self {
        Self {
            continuation_points: Vec::new(),
            release_continuation_points: false,

            header: RequestHeaderBuilder::new_from_session(session),
        }
    }

    /// Construct a new call to the `BrowseNext` service, setting header parameters manually.
    pub fn new_manual(
        session_id: u32,
        timeout: Duration,
        auth_token: NodeId,
        request_handle: IntegerId,
    ) -> Self {
        Self {
            continuation_points: Vec::new(),
            release_continuation_points: false,

            header: RequestHeaderBuilder::new(session_id, timeout, auth_token, request_handle),
        }
    }

    /// Set release continuation points. Default is false, if this is true,
    /// continuation points will be released and no results will be returned.
    pub fn release_continuation_points(mut self, release_continuation_points: bool) -> Self {
        self.release_continuation_points = release_continuation_points;
        self
    }

    /// Set continuation points, overwriting any that were set previously.
    pub fn continuation_points(mut self, continuation_points: Vec<ByteString>) -> Self {
        self.continuation_points = continuation_points;
        self
    }

    /// Add a continuation point to the request.
    pub fn continuation_point(mut self, continuation_point: ByteString) -> Self {
        self.continuation_points.push(continuation_point);
        self
    }
}

impl UARequest for BrowseNext {
    type Out = BrowseNextResponse;

    async fn send<'a>(self, channel: &'a crate::AsyncSecureChannel) -> Result<Self::Out, StatusCode>
    where
        Self: 'a,
    {
        if self.continuation_points.is_empty() {
            builder_error!(
                self,
                "browse_next was not supplied with any continuation points"
            );
            return Err(StatusCode::BadNothingToDo);
        }
        let request = BrowseNextRequest {
            request_header: self.header.header,
            continuation_points: Some(self.continuation_points),
            release_continuation_points: self.release_continuation_points,
        };
        let response = channel.send(request, self.header.timeout).await?;
        if let ResponseMessage::BrowseNext(response) = response {
            builder_debug!(self, "browse_next, success");
            process_service_result(&response.response_header)?;
            Ok(*response)
        } else {
            builder_error!(self, "browse_next failed");
            Err(process_unexpected_response(response))
        }
    }
}

#[derive(Debug, Clone)]
/// Translate browse paths to NodeIds by sending a [`TranslateBrowsePathsToNodeIdsRequest`] request to the Server
/// Each [`BrowsePath`] is constructed of a starting node and a `RelativePath`. The specified starting node
/// identifies the node from which the RelativePath is based. The RelativePath contains a sequence of
/// ReferenceTypes and BrowseNames.
///
/// See OPC UA Part 4 - Services 5.8.4 for complete description of the service and error responses.
pub struct TranslateBrowsePaths {
    browse_paths: Vec<BrowsePath>,

    header: RequestHeaderBuilder,
}

builder_base!(TranslateBrowsePaths);

impl TranslateBrowsePaths {
    /// Construct a new call to the `TranslateBrowsePaths` service.
    pub fn new(session: &Session) -> Self {
        Self {
            browse_paths: Vec::new(),

            header: RequestHeaderBuilder::new_from_session(session),
        }
    }

    /// Construct a new call to the `TranslateBrowsePaths` service, setting header parameters manually.
    pub fn new_manual(
        session_id: u32,
        timeout: Duration,
        auth_token: NodeId,
        request_handle: IntegerId,
    ) -> Self {
        Self {
            browse_paths: Vec::new(),

            header: RequestHeaderBuilder::new(session_id, timeout, auth_token, request_handle),
        }
    }

    /// Set browse paths, overwriting any that were set previously.
    pub fn browse_paths(mut self, browse_paths: Vec<BrowsePath>) -> Self {
        self.browse_paths = browse_paths;
        self
    }

    /// Add a browse path to the request.
    pub fn browse_path(mut self, browse_path: BrowsePath) -> Self {
        self.browse_paths.push(browse_path);
        self
    }
}

impl UARequest for TranslateBrowsePaths {
    type Out = TranslateBrowsePathsToNodeIdsResponse;

    async fn send<'a>(self, channel: &'a crate::AsyncSecureChannel) -> Result<Self::Out, StatusCode>
    where
        Self: 'a,
    {
        if self.browse_paths.is_empty() {
            builder_error!(
                self,
                "translate_browse_paths_to_node_ids was not supplied with any browse paths"
            );
            return Err(StatusCode::BadNothingToDo);
        }
        let request = TranslateBrowsePathsToNodeIdsRequest {
            request_header: self.header.header,
            browse_paths: Some(self.browse_paths),
        };
        let response = channel.send(request, self.header.timeout).await?;
        if let ResponseMessage::TranslateBrowsePathsToNodeIds(response) = response {
            builder_debug!(self, "translate_browse_paths_to_node_ids, success");
            process_service_result(&response.response_header)?;
            Ok(*response)
        } else {
            builder_error!(self, "translate_browse_paths_to_node_ids failed");
            Err(process_unexpected_response(response))
        }
    }
}

#[derive(Debug, Clone)]
/// Register nodes on the server by sending a [`RegisterNodesRequest`]. The purpose of this
/// call is server-dependent but allows a client to ask a server to create nodes which are
/// otherwise expensive to set up or maintain, e.g. nodes attached to hardware.
///
/// See OPC UA Part 4 - Services 5.8.5 for complete description of the service and error responses.
pub struct RegisterNodes {
    nodes_to_register: Vec<NodeId>,

    header: RequestHeaderBuilder,
}

builder_base!(RegisterNodes);

impl RegisterNodes {
    /// Construct a new call to the `RegisterNodes` service.
    pub fn new(session: &Session) -> Self {
        Self {
            nodes_to_register: Vec::new(),

            header: RequestHeaderBuilder::new_from_session(session),
        }
    }

    /// Construct a new call to the `RegisterNodes` service, setting header parameters manually.
    pub fn new_manual(
        session_id: u32,
        timeout: Duration,
        auth_token: NodeId,
        request_handle: IntegerId,
    ) -> Self {
        Self {
            nodes_to_register: Vec::new(),

            header: RequestHeaderBuilder::new(session_id, timeout, auth_token, request_handle),
        }
    }

    /// Set nodes to register, overwriting any that were set previously.
    pub fn nodes_to_register(mut self, nodes_to_register: Vec<NodeId>) -> Self {
        self.nodes_to_register = nodes_to_register;
        self
    }

    /// Add a node to the request.
    pub fn node_to_register(mut self, node_to_register: impl Into<NodeId>) -> Self {
        self.nodes_to_register.push(node_to_register.into());
        self
    }
}

impl UARequest for RegisterNodes {
    type Out = RegisterNodesResponse;

    async fn send<'a>(self, channel: &'a crate::AsyncSecureChannel) -> Result<Self::Out, StatusCode>
    where
        Self: 'a,
    {
        if self.nodes_to_register.is_empty() {
            builder_error!(self, "register_nodes was not supplied with any node IDs");
            return Err(StatusCode::BadNothingToDo);
        }
        let request = RegisterNodesRequest {
            request_header: self.header.header,
            nodes_to_register: Some(self.nodes_to_register),
        };
        let response = channel.send(request, self.header.timeout).await?;
        if let ResponseMessage::RegisterNodes(response) = response {
            builder_debug!(self, "register_nodes, success");
            process_service_result(&response.response_header)?;
            Ok(*response)
        } else {
            builder_error!(self, "register_nodes failed");
            Err(process_unexpected_response(response))
        }
    }
}

#[derive(Debug, Clone)]
/// Unregister nodes on the server by sending a [`UnregisterNodesRequest`]. This indicates to
/// the server that the client relinquishes any need for these nodes. The server will ignore
/// unregistered nodes.
///
/// See OPC UA Part 4 - Services 5.8.5 for complete description of the service and error responses.
pub struct UnregisterNodes {
    nodes_to_unregister: Vec<NodeId>,

    header: RequestHeaderBuilder,
}

builder_base!(UnregisterNodes);

impl UnregisterNodes {
    /// Construct a new call to the `UnregisterNodes` service.
    pub fn new(session: &Session) -> Self {
        Self {
            nodes_to_unregister: Vec::new(),

            header: RequestHeaderBuilder::new_from_session(session),
        }
    }

    /// Construct a new call to the `UnregisterNodes` service, setting header parameters manually.
    pub fn new_manual(
        session_id: u32,
        timeout: Duration,
        auth_token: NodeId,
        request_handle: IntegerId,
    ) -> Self {
        Self {
            nodes_to_unregister: Vec::new(),

            header: RequestHeaderBuilder::new(session_id, timeout, auth_token, request_handle),
        }
    }

    /// Set nodes to register, overwriting any that were set previously.
    pub fn nodes_to_unregister(mut self, nodes_to_unregister: Vec<NodeId>) -> Self {
        self.nodes_to_unregister = nodes_to_unregister;
        self
    }

    /// Add a continuation point to the request.
    pub fn node_to_unregister(mut self, node_to_unregister: impl Into<NodeId>) -> Self {
        self.nodes_to_unregister.push(node_to_unregister.into());
        self
    }
}

impl UARequest for UnregisterNodes {
    type Out = UnregisterNodesResponse;

    async fn send<'a>(self, channel: &'a crate::AsyncSecureChannel) -> Result<Self::Out, StatusCode>
    where
        Self: 'a,
    {
        if self.nodes_to_unregister.is_empty() {
            builder_error!(self, "unregister_nodes was not supplied with any node IDs");
            return Err(StatusCode::BadNothingToDo);
        }
        let request = UnregisterNodesRequest {
            request_header: self.header.header,
            nodes_to_unregister: Some(self.nodes_to_unregister),
        };
        let response = channel.send(request, self.header.timeout).await?;
        if let ResponseMessage::UnregisterNodes(response) = response {
            builder_debug!(self, "unregister_nodes, success");
            process_service_result(&response.response_header)?;
            Ok(*response)
        } else {
            builder_error!(self, "unregister_nodes failed");
            Err(process_unexpected_response(response))
        }
    }
}

impl Session {
    /// Discover the references to the specified nodes by sending a [`BrowseRequest`] to the server.
    ///
    /// See OPC UA Part 4 - Services 5.8.2 for complete description of the service and error responses.
    ///
    /// # Arguments
    ///
    /// * `nodes_to_browse` - A list of [`BrowseDescription`] describing nodes to browse.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<BrowseResult>)` - A list [`BrowseResult`] corresponding to each node to browse. A browse result
    ///   may contain a continuation point, for use with `browse_next()`.
    /// * `Err(StatusCode)` - Request failed, [Status code](StatusCode) is the reason for failure.
    ///
    pub async fn browse(
        &self,
        nodes_to_browse: &[BrowseDescription],
        max_references_per_node: u32,
        view: Option<ViewDescription>,
    ) -> Result<Vec<BrowseResult>, StatusCode> {
        Ok(Browse::new(self)
            .nodes_to_browse(nodes_to_browse.to_vec())
            .view(view.unwrap_or_default())
            .max_references_per_node(max_references_per_node)
            .send(&self.channel)
            .await?
            .results
            .unwrap_or_default())
    }

    /// Continue to discover references to nodes by sending continuation points in a [`BrowseNextRequest`]
    /// to the server. This function may have to be called repeatedly to process the initial query.
    ///
    /// See OPC UA Part 4 - Services 5.8.3 for complete description of the service and error responses.
    ///
    /// # Arguments
    ///
    /// * `release_continuation_points` - Flag indicating if the continuation points should be released by the server
    /// * `continuation_points` - A list of [`BrowseDescription`] continuation points
    ///
    /// # Returns
    ///
    /// * `Ok(Option<Vec<BrowseResult>)` - A list [`BrowseResult`] corresponding to each node to browse. A browse result
    ///   may contain a continuation point, for use with `browse_next()`.
    /// * `Err(StatusCode)` - Request failed, [Status code](StatusCode) is the reason for failure.
    ///
    pub async fn browse_next(
        &self,
        release_continuation_points: bool,
        continuation_points: &[ByteString],
    ) -> Result<Vec<BrowseResult>, StatusCode> {
        Ok(BrowseNext::new(self)
            .continuation_points(continuation_points.to_vec())
            .release_continuation_points(release_continuation_points)
            .send(&self.channel)
            .await?
            .results
            .unwrap_or_default())
    }

    /// Translate browse paths to NodeIds by sending a [`TranslateBrowsePathsToNodeIdsRequest`] request to the Server
    /// Each [`BrowsePath`] is constructed of a starting node and a `RelativePath`. The specified starting node
    /// identifies the node from which the RelativePath is based. The RelativePath contains a sequence of
    /// ReferenceTypes and BrowseNames.
    ///
    /// See OPC UA Part 4 - Services 5.8.4 for complete description of the service and error responses.
    ///
    /// # Arguments
    ///
    /// * `browse_paths` - A list of [`BrowsePath`] node + relative path for the server to look up
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<BrowsePathResult>>)` - List of [`BrowsePathResult`] for the list of browse
    ///   paths. The size and order of the list matches the size and order of the `browse_paths`
    ///   parameter.
    /// * `Err(StatusCode)` - Request failed, [Status code](StatusCode) is the reason for failure.
    ///
    pub async fn translate_browse_paths_to_node_ids(
        &self,
        browse_paths: &[BrowsePath],
    ) -> Result<Vec<BrowsePathResult>, StatusCode> {
        Ok(TranslateBrowsePaths::new(self)
            .browse_paths(browse_paths.to_vec())
            .send(&self.channel)
            .await?
            .results
            .unwrap_or_default())
    }

    /// Register nodes on the server by sending a [`RegisterNodesRequest`]. The purpose of this
    /// call is server-dependent but allows a client to ask a server to create nodes which are
    /// otherwise expensive to set up or maintain, e.g. nodes attached to hardware.
    ///
    /// See OPC UA Part 4 - Services 5.8.5 for complete description of the service and error responses.
    ///
    /// # Arguments
    ///
    /// * `nodes_to_register` - A list of [`NodeId`] nodes for the server to register
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<NodeId>)` - A list of [`NodeId`] corresponding to size and order of the input. The
    ///   server may return an alias for the input `NodeId`
    /// * `Err(StatusCode)` - Request failed, [Status code](StatusCode) is the reason for failure.
    ///
    pub async fn register_nodes(
        &self,
        nodes_to_register: &[NodeId],
    ) -> Result<Vec<NodeId>, StatusCode> {
        Ok(RegisterNodes::new(self)
            .nodes_to_register(nodes_to_register.to_vec())
            .send(&self.channel)
            .await?
            .registered_node_ids
            .unwrap_or_default())
    }

    /// Unregister nodes on the server by sending a [`UnregisterNodesRequest`]. This indicates to
    /// the server that the client relinquishes any need for these nodes. The server will ignore
    /// unregistered nodes.
    ///
    /// See OPC UA Part 4 - Services 5.8.5 for complete description of the service and error responses.
    ///
    /// # Arguments
    ///
    /// * `nodes_to_unregister` - A list of [`NodeId`] nodes for the server to unregister
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Request succeeded, server ignores invalid nodes
    /// * `Err(StatusCode)` - Request failed, [Status code](StatusCode) is the reason for failure.
    ///
    pub async fn unregister_nodes(&self, nodes_to_unregister: &[NodeId]) -> Result<(), StatusCode> {
        UnregisterNodes::new(self)
            .nodes_to_unregister(nodes_to_unregister.to_vec())
            .send(&self.channel)
            .await?;
        Ok(())
    }
}
