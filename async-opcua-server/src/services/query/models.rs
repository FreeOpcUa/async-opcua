//! Query service request models.

use opcua_types::{
    ContentFilter, ContinuationPoint, Counter, NodeTypeDescription,
    QueryFirstRequest as OpcuaQueryFirstRequest, QueryNextRequest as OpcuaQueryNextRequest,
    ViewDescription,
};

/// Service-level payload for an OPC UA `QueryFirst` request.
///
/// This mirrors the OPC UA request body without the transport-level request header.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct QueryFirstRequest {
    /// View to query. Non-default views are rejected by the current server implementation.
    pub view: ViewDescription,
    /// Node type descriptions that define the target types and returned data.
    pub node_types: Option<Vec<NodeTypeDescription>>,
    /// Content filter used to match nodes in the address space.
    pub filter: ContentFilter,
    /// Maximum number of data sets to return, or `0` for the server default.
    pub max_data_sets_to_return: Counter,
    /// Maximum number of references to follow/return, or `0` for the server default.
    pub max_references_to_return: Counter,
}

impl QueryFirstRequest {
    /// Creates a `QueryFirst` service request payload.
    #[must_use]
    pub fn new(
        view: ViewDescription,
        node_types: Option<Vec<NodeTypeDescription>>,
        filter: ContentFilter,
        max_data_sets_to_return: Counter,
        max_references_to_return: Counter,
    ) -> Self {
        Self {
            view,
            node_types,
            filter,
            max_data_sets_to_return,
            max_references_to_return,
        }
    }
}

impl From<OpcuaQueryFirstRequest> for QueryFirstRequest {
    fn from(request: OpcuaQueryFirstRequest) -> Self {
        Self {
            view: request.view,
            node_types: request.node_types,
            filter: request.filter,
            max_data_sets_to_return: request.max_data_sets_to_return,
            max_references_to_return: request.max_references_to_return,
        }
    }
}

/// Service-level payload for an OPC UA `QueryNext` request.
///
/// This mirrors the OPC UA request body without the transport-level request header.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct QueryNextRequest {
    /// Whether the server should release the continuation point instead of returning more data.
    pub release_continuation_point: bool,
    /// Continuation point returned by `QueryFirst` or a previous `QueryNext`.
    pub continuation_point: ContinuationPoint,
}

impl QueryNextRequest {
    /// Creates a `QueryNext` service request payload.
    #[must_use]
    pub fn new(release_continuation_point: bool, continuation_point: ContinuationPoint) -> Self {
        Self {
            release_continuation_point,
            continuation_point,
        }
    }
}

impl From<OpcuaQueryNextRequest> for QueryNextRequest {
    fn from(request: OpcuaQueryNextRequest) -> Self {
        Self {
            release_continuation_point: request.release_continuation_point,
            continuation_point: request.continuation_point,
        }
    }
}

#[cfg(test)]
mod tests {
    use opcua_types::{
        ByteString, ContentFilter, NodeTypeDescription, QueryFirstRequest as OpcuaQueryFirstRequest,
    };

    use super::{QueryFirstRequest, QueryNextRequest};

    #[test]
    fn query_first_from_opcua_request_preserves_payload_fields() {
        let node_types = Some(vec![NodeTypeDescription::default()]);
        let request = OpcuaQueryFirstRequest {
            node_types: node_types.clone(),
            max_data_sets_to_return: 25,
            max_references_to_return: 50,
            ..Default::default()
        };

        let model = QueryFirstRequest::from(request);

        assert_eq!(model.node_types, node_types);
        assert_eq!(model.filter, ContentFilter::default());
        assert_eq!(model.max_data_sets_to_return, 25);
        assert_eq!(model.max_references_to_return, 50);
    }

    #[test]
    fn query_next_from_opcua_request_preserves_payload_fields() {
        let continuation_point = ByteString::from(vec![1, 2, 3]);
        let request = opcua_types::QueryNextRequest {
            release_continuation_point: true,
            continuation_point: continuation_point.clone(),
            ..Default::default()
        };

        let model = QueryNextRequest::from(request);

        assert!(model.release_continuation_point);
        assert_eq!(model.continuation_point, continuation_point);
    }
}
