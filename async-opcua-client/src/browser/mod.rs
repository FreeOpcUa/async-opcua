//! This module contains a utility for recursively browsing the node hierarchy
//! in a flexible, efficient, and reliable manner.
//!
//! # Notes on usage.
//!
//! The browser does not spawn any internal tasks or threads, instead
//! it is all driven by a `Stream`, that needs to be consumed for the
//! browser to make progress.
//!
//! The browser is generic over two parameters:
//!
//! The first is a [BrowserPolicy], which dictates the recursive behavior of
//! the browser. It accepts a result, and returns a set of nodes to browse.
//! For simple usage, it is implemented for [BrowseFilter], which just creates
//! a new [BrowseDescription] for each returned reference.
//!
//! Note that the browser will only ever browse a node in a given direction
//! (forward or inverse) once, so if you return the same [BrowseDescription] multiple
//! times, even with different filters, it will be ignored.
//!
//! The second parameter is a [RequestRetryPolicy], this dictates how
//! requests should be retried. It defaults to an instance of
//! [crate::DefaultRetryPolicy] with reasonable defaults.
//!
//! # Cancellation
//!
//! You _can_ just stop listening to the stream. The pending requests
//! will still complete, but the browser will not send any more without
//! anyone polling the stream. The problem with this is that browsing
//! in OPC-UA produces `ContinuationPoints` on the server that need to be
//! freed.
//!
//! If you instead set a `CancellationToken` when creating the browser,
//! cancel it, then wait for the stream to terminate, the browser will attempt
//! to clean up any pending continuation points after all requests finish.
//!
//! It will also attempt to do this on an error, but without retries.
//!
//! If you are closing the session anyway, continuation points are
//! probable freed by the server then, so you can ignore this and just
//! drop the stream.

use opcua_types::{
    BrowseDescription, BrowseDirection, BrowseResultMaskFlags, ByteString, NodeClassMask, NodeId,
    ReferenceDescription, ReferenceTypeId, StatusCode,
};
use tokio_util::sync::CancellationToken;

mod browse;
mod result;

pub use result::{BrowserResult, NodeDescription};

use crate::{RequestRetryPolicy, Session};

/// Configuration for the browser
#[derive(Debug, Clone)]
pub struct BrowserConfig {
    max_nodes_per_request: usize,
    max_references_per_node: u32,
    max_concurrent_requests: usize,
    max_continuation_point_retries: usize,
}

impl BrowserConfig {
    /// Create a new default browser config.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the maximum number of nodes per request sent to the server.
    ///
    /// Note that the browser makes no guarantee that all requests sent
    /// will be as large as possible.
    pub fn max_nodes_per_request(mut self, max_nodes_per_request: usize) -> Self {
        self.max_nodes_per_request = max_nodes_per_request;
        self
    }

    /// Set the maximum number of references requested per node.
    /// Can be 0 to let the server decide.
    pub fn max_references_per_node(mut self, max_references_per_node: u32) -> Self {
        self.max_references_per_node = max_references_per_node;
        self
    }

    /// Set the maximum number of concurrent requests. Defaults to 1.
    pub fn max_concurrent_requests(mut self, max_concurrent_requests: usize) -> Self {
        self.max_concurrent_requests = max_concurrent_requests;
        self
    }

    /// Set the maximum number of times a browse will be retried if the
    /// continuation point becomes invalid while the browser is running.
    ///
    /// This will start the browse process over from zero for the affected node,
    /// meaning that the same references will be returned multiple times.
    pub fn max_continuation_point_retries(mut self, max_continuation_point_retries: usize) -> Self {
        self.max_continuation_point_retries = max_continuation_point_retries;
        self
    }
}

impl Default for BrowserConfig {
    fn default() -> Self {
        Self {
            max_nodes_per_request: 100,
            max_references_per_node: 1000,
            max_concurrent_requests: 1,
            max_continuation_point_retries: 0,
        }
    }
}

#[derive(Debug, Default, Clone)]
struct RequestWithRetries {
    pub(self) request: BrowseDescription,
    pub(self) num_outer_retries: usize,
    pub(self) depth: usize,
}

#[derive(Debug, Default)]
/// Result of a browse iteration.
pub struct BrowseResultItem {
    pub(self) request: RequestWithRetries,
    pub(self) references: Vec<ReferenceDescription>,
    pub(self) status: StatusCode,
    pub(self) request_continuation_point: Option<ByteString>,
}

impl BrowseResultItem {
    /// Get the parent ID for this browse iteration.
    pub fn parent_id(&self) -> &NodeId {
        &self.request.request.node_id
    }

    /// Consume this turning it into a list of references
    /// and the parent ID.
    /// Potentially more efficient than cloning from `references`.
    pub fn into_results(self) -> (NodeId, Vec<ReferenceDescription>) {
        (self.request.request.node_id, self.references)
    }

    /// Get the list of references.
    ///
    /// Use `into_results` if you need owned copies of the results.
    pub fn references(&self) -> &[ReferenceDescription] {
        &self.references
    }

    /// Get the status code. This may be an error if the
    /// request failed. `BadContinuationPointInvalid` has special handling.
    pub fn status(&self) -> StatusCode {
        self.status
    }

    /// Get the browse request that produced this result item.
    pub fn request(&self) -> &BrowseDescription {
        &self.request.request
    }

    /// Get whether this was the result of a `BrowseNext` oepration.
    pub fn is_browse_next(&self) -> bool {
        self.request_continuation_point.is_some()
    }

    /// Depth of this reference in the recursive browse.
    /// Depth 1 was returned from the list of root nodes.
    pub fn depth(&self) -> usize {
        self.request.depth + 1
    }
}

/// Trait for deciding which nodes to browse next in a recursive browse.
pub trait BrowserPolicy {
    /// Given a parent node, and a list of references from that node,
    /// return a list of nodes to browse next.
    fn get_next(&self, results: &BrowseResultItem) -> Vec<BrowseDescription>;
}

impl<T> BrowserPolicy for T
where
    T: for<'a> Fn(&BrowseResultItem) -> Vec<BrowseDescription> + Send + Sync,
{
    fn get_next(&self, results: &BrowseResultItem) -> Vec<BrowseDescription> {
        self(results)
    }
}

/// Browse policy that browses nothing except the root nodes.
#[derive(Debug, Clone, Copy)]
pub struct NoneBrowserPolicy;

impl BrowserPolicy for NoneBrowserPolicy {
    fn get_next(&self, _results: &BrowseResultItem) -> Vec<BrowseDescription> {
        Vec::new()
    }
}

/// Simple filter for the [Browser]. All discovered nodes
/// will be recursively browsed using the stored configuration.
#[derive(Debug, Clone)]
pub struct BrowseFilter {
    direction: BrowseDirection,
    include_subtypes: bool,
    result_mask: BrowseResultMaskFlags,
    node_class_mask: NodeClassMask,
    reference_type_id: NodeId,
    max_depth: usize,
}

impl BrowserPolicy for BrowseFilter {
    fn get_next(&self, results: &BrowseResultItem) -> Vec<BrowseDescription> {
        if self.max_depth > 0 && results.depth() >= self.max_depth {
            return Vec::new();
        }

        results
            .references
            .iter()
            .filter(|r| r.node_id.server_index == 0)
            .map(|r| self.new_description_from_node(r.node_id.node_id.clone()))
            .collect()
    }
}

impl BrowseFilter {
    /// Create a new browse filter for browsing references of
    /// `reference_type_id` (optionally including subtypes) in the
    /// given `direction`.
    pub fn new(
        direction: BrowseDirection,
        reference_type_id: impl Into<NodeId>,
        include_subtypes: bool,
    ) -> Self {
        Self {
            direction,
            reference_type_id: reference_type_id.into(),
            include_subtypes,
            result_mask: BrowseResultMaskFlags::all(),
            node_class_mask: NodeClassMask::all(),
            max_depth: 0,
        }
    }

    /// Create a new browse description from this filter and a node ID to browse.
    pub fn new_description_from_node(&self, node_id: NodeId) -> BrowseDescription {
        BrowseDescription {
            node_id,
            browse_direction: self.direction,
            reference_type_id: self.reference_type_id.clone(),
            include_subtypes: self.include_subtypes,
            node_class_mask: self.node_class_mask.bits(),
            result_mask: self.result_mask.bits(),
        }
    }

    /// Create a new browse filter for browsing hierarchical references.
    pub fn new_hierarchical() -> Self {
        Self::new(
            BrowseDirection::Forward,
            ReferenceTypeId::HierarchicalReferences,
            true,
        )
    }

    /// Set the node class mask, the filter for allowed node classes
    /// in the returned references. Defaults to `all`.
    pub fn node_class_mask(mut self, mask: NodeClassMask) -> Self {
        self.node_class_mask = mask;
        self
    }

    /// Set the result mask, indicating which values should be returned
    /// for each reference. Defaults to `all`.
    pub fn result_mask(mut self, mask: BrowseResultMaskFlags) -> Self {
        self.result_mask = mask;
        self
    }

    /// Set the maximum browse depth. If this is 1 only the root nodes will be browsed,
    /// if it is 0, there is no upper limit.
    pub fn max_depth(mut self, depth: usize) -> Self {
        self.max_depth = depth;
        self
    }
}

/// A utility for recursively discovering nodes on an OPC-UA server.
pub struct Browser<'a, T, R> {
    pub(self) handler: T,
    pub(self) retry_policy: R,
    pub(self) config: BrowserConfig,
    pub(self) session: &'a Session,
    pub(self) token: CancellationToken,
}

impl<'a, T, R> Browser<'a, T, R> {
    /// Create a new browser with the given handler and retry policy.
    pub fn new(session: &'a Session, handler: T, retry_policy: R) -> Self {
        Self {
            session,
            handler,
            retry_policy,
            config: BrowserConfig::default(),
            token: CancellationToken::new(),
        }
    }

    /// Set a new browser policy. This is used to generate new browses after each
    /// visited node. Note that no matter what, a node will only be browsed _once_
    /// in each direction. (Or once in both at the same time).
    pub fn handler<T2: BrowserPolicy + 'a>(self, new_handler: T2) -> Browser<'a, T2, R> {
        Browser {
            handler: new_handler,
            retry_policy: self.retry_policy,
            config: self.config,
            session: self.session,
            token: self.token,
        }
    }

    /// Set a new request retry policy.
    pub fn retry_policy<R2: RequestRetryPolicy + Clone + 'a>(
        self,
        new_retry_policy: R2,
    ) -> Browser<'a, T, R2> {
        Browser {
            handler: self.handler,
            retry_policy: new_retry_policy,
            config: self.config,
            session: self.session,
            token: self.token,
        }
    }

    /// Set a new cancellation token. Once this is cancelled, the
    /// browser will try to shut down gracefully, which means waiting for
    /// any pending requests and then releasing continuation points.
    ///
    /// If you don't care about that (for example if you are shutting down
    /// the session soon), then you can just stop polling to the stream.
    pub fn token(mut self, token: CancellationToken) -> Self {
        self.token = token;
        self
    }

    /// Set the maximum number of nodes per request sent to the server.
    ///
    /// Note that the browser makes no guarantee that all requests sent
    /// will be as large as possible.
    pub fn max_nodes_per_request(mut self, max_nodes_per_request: usize) -> Self {
        self.config.max_nodes_per_request = max_nodes_per_request;
        self
    }

    /// Set the maximum number of references requested per node.
    /// Can be 0 to let the server decide.
    pub fn max_references_per_node(mut self, max_references_per_node: u32) -> Self {
        self.config.max_references_per_node = max_references_per_node;
        self
    }

    /// Set the maximum number of concurrent requests. Defaults to 1.
    pub fn max_concurrent_requests(mut self, max_concurrent_requests: usize) -> Self {
        self.config.max_concurrent_requests = max_concurrent_requests;
        self
    }

    /// Set the maximum number of times a browse will be retried if the
    /// continuation point becomes invalid while the browser is running.
    ///
    /// This will start the browse process over from zero for the affected node,
    /// meaning that the same references will be returned multiple times.
    pub fn max_continuation_point_retries(mut self, max_continuation_point_retries: usize) -> Self {
        self.config.max_continuation_point_retries = max_continuation_point_retries;
        self
    }

    /// Set the browse configuration.
    pub fn config(mut self, config: BrowserConfig) -> Self {
        self.config = config;
        self
    }
}
