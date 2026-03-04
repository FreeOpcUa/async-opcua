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
    AddNodesItem, AddNodesRequest, AddNodesResponse, AddNodesResult, AddReferencesItem,
    AddReferencesRequest, AddReferencesResponse, DeleteNodesItem, DeleteNodesRequest,
    DeleteNodesResponse, DeleteReferencesItem, DeleteReferencesRequest, DeleteReferencesResponse,
    IntegerId, NodeId, StatusCode,
};
use tracing::{debug_span, Instrument};

#[derive(Debug, Clone)]
/// Add nodes by sending a [`AddNodesRequest`] to the server.
///
/// See OPC UA Part 4 - Services 5.7.2 for complete description of the service and error responses.
pub struct AddNodes {
    nodes_to_add: Vec<AddNodesItem>,

    header: RequestHeaderBuilder,
}

builder_base!(AddNodes);

impl AddNodes {
    /// Construct a new call to the `AddNodes` service.
    pub fn new(session: &Session) -> Self {
        Self {
            nodes_to_add: Vec::new(),
            header: RequestHeaderBuilder::new_from_session(session),
        }
    }

    /// Construct a new call to the `AddNodes` service, setting header parameters manually.
    pub fn new_manual(
        session_id: u32,
        timeout: Duration,
        auth_token: NodeId,
        request_handle: IntegerId,
    ) -> Self {
        Self {
            nodes_to_add: Vec::new(),
            header: RequestHeaderBuilder::new(session_id, timeout, auth_token, request_handle),
        }
    }

    /// Set nodes to add, overwriting any that were set previously.
    pub fn nodes_to_add(mut self, nodes_to_add: Vec<AddNodesItem>) -> Self {
        self.nodes_to_add = nodes_to_add;
        self
    }

    /// Add a node to create.
    pub fn node(mut self, node: impl Into<AddNodesItem>) -> Self {
        self.nodes_to_add.push(node.into());
        self
    }
}

impl UARequest for AddNodes {
    type Out = AddNodesResponse;

    async fn send<'a>(self, channel: &'a crate::AsyncSecureChannel) -> Result<Self::Out, StatusCode>
    where
        Self: 'a,
    {
        let span = debug_span!(
            "Sending AddNodes request",
            num_nodes_to_add = self.nodes_to_add.len()
        );
        let request = {
            let _h = span.enter();
            if self.nodes_to_add.is_empty() {
                builder_error!(self, "add_nodes, called with no nodes to add");
                return Err(StatusCode::BadNothingToDo);
            }
            AddNodesRequest {
                request_header: self.header.header,
                nodes_to_add: Some(self.nodes_to_add),
            }
        };

        let response = channel
            .send(request, self.header.timeout)
            .instrument(span.clone())
            .await?;
        let _h = span.enter();
        if let ResponseMessage::AddNodes(response) = response {
            builder_debug!(self, "add_nodes, success");
            process_service_result(&response.response_header)?;
            Ok(*response)
        } else {
            builder_error!(self, "add_nodes failed");
            Err(process_unexpected_response(response))
        }
    }
}

#[derive(Debug, Clone)]
/// Add references by sending a [`AddReferencesRequest`] to the server.
///
/// See OPC UA Part 4 - Services 5.7.3 for complete description of the service and error responses.
pub struct AddReferences {
    references_to_add: Vec<AddReferencesItem>,

    header: RequestHeaderBuilder,
}

builder_base!(AddReferences);

impl AddReferences {
    /// Construct a new call to the `AddReferences` service.
    pub fn new(session: &Session) -> Self {
        Self {
            references_to_add: Vec::new(),
            header: RequestHeaderBuilder::new_from_session(session),
        }
    }

    /// Construct a new call to the `AddReferences` service, setting header parameters manually.
    pub fn new_manual(
        session_id: u32,
        timeout: Duration,
        auth_token: NodeId,
        request_handle: IntegerId,
    ) -> Self {
        Self {
            references_to_add: Vec::new(),
            header: RequestHeaderBuilder::new(session_id, timeout, auth_token, request_handle),
        }
    }

    /// Set references to add, overwriting any that were set previously.
    pub fn references_to_add(mut self, references_to_add: Vec<AddReferencesItem>) -> Self {
        self.references_to_add = references_to_add;
        self
    }

    /// Add a reference to create.
    pub fn reference(mut self, reference: impl Into<AddReferencesItem>) -> Self {
        self.references_to_add.push(reference.into());
        self
    }
}

impl UARequest for AddReferences {
    type Out = AddReferencesResponse;

    async fn send<'a>(self, channel: &'a crate::AsyncSecureChannel) -> Result<Self::Out, StatusCode>
    where
        Self: 'a,
    {
        let span = debug_span!(
            "Sending AddReferences request",
            num_references_to_add = self.references_to_add.len()
        );
        let request = {
            let _h = span.enter();
            if self.references_to_add.is_empty() {
                builder_error!(self, "add_references, called with no references to add");
                return Err(StatusCode::BadNothingToDo);
            }
            AddReferencesRequest {
                request_header: self.header.header,
                references_to_add: Some(self.references_to_add),
            }
        };
        let response = channel
            .send(request, self.header.timeout)
            .instrument(span.clone())
            .await?;
        let _h = span.enter();
        if let ResponseMessage::AddReferences(response) = response {
            builder_debug!(self, "add_references, success");
            process_service_result(&response.response_header)?;
            Ok(*response)
        } else {
            builder_error!(self, "add_references failed");
            Err(process_unexpected_response(response))
        }
    }
}

#[derive(Debug, Clone)]
/// Delete nodes by sending a [`DeleteNodesRequest`] to the server.
///
/// See OPC UA Part 4 - Services 5.7.4 for complete description of the service and error responses.
pub struct DeleteNodes {
    nodes_to_delete: Vec<DeleteNodesItem>,

    header: RequestHeaderBuilder,
}

builder_base!(DeleteNodes);

impl DeleteNodes {
    /// Construct a new call to the `DeleteNodes` service.
    pub fn new(session: &Session) -> Self {
        Self {
            nodes_to_delete: Vec::new(),
            header: RequestHeaderBuilder::new_from_session(session),
        }
    }

    /// Construct a new call to the `DeleteNodes` service, setting header parameters manually.
    pub fn new_manual(
        session_id: u32,
        timeout: Duration,
        auth_token: NodeId,
        request_handle: IntegerId,
    ) -> Self {
        Self {
            nodes_to_delete: Vec::new(),
            header: RequestHeaderBuilder::new(session_id, timeout, auth_token, request_handle),
        }
    }

    /// Set nodes to delete, overwriting any that were set previously.
    pub fn nodes_to_delete(mut self, nodes_to_delete: Vec<DeleteNodesItem>) -> Self {
        self.nodes_to_delete = nodes_to_delete;
        self
    }

    /// Add a node to delete.
    pub fn node(mut self, reference: impl Into<DeleteNodesItem>) -> Self {
        self.nodes_to_delete.push(reference.into());
        self
    }
}

impl UARequest for DeleteNodes {
    type Out = DeleteNodesResponse;

    async fn send<'a>(self, channel: &'a crate::AsyncSecureChannel) -> Result<Self::Out, StatusCode>
    where
        Self: 'a,
    {
        let span = debug_span!(
            "Sending DeleteNodes request",
            num_nodes_to_delete = self.nodes_to_delete.len()
        );
        let request = {
            let _h = span.enter();
            if self.nodes_to_delete.is_empty() {
                builder_error!(self, "delete_nodes, called with no nodes to delete");
                return Err(StatusCode::BadNothingToDo);
            }
            DeleteNodesRequest {
                request_header: self.header.header,
                nodes_to_delete: Some(self.nodes_to_delete),
            }
        };

        let response = channel
            .send(request, self.header.timeout)
            .instrument(span.clone())
            .await?;
        let _h = span.enter();
        if let ResponseMessage::DeleteNodes(response) = response {
            builder_debug!(self, "delete_nodes, success");
            process_service_result(&response.response_header)?;
            Ok(*response)
        } else {
            builder_error!(self, "delete_nodes failed");
            Err(process_unexpected_response(response))
        }
    }
}

#[derive(Debug, Clone)]
/// Delete references by sending a [`DeleteReferencesRequest`] to the server.
///
/// See OPC UA Part 4 - Services 5.7.5 for complete description of the service and error responses.
pub struct DeleteReferences {
    references_to_delete: Vec<DeleteReferencesItem>,

    header: RequestHeaderBuilder,
}

builder_base!(DeleteReferences);

impl DeleteReferences {
    /// Construct a new call to the `DeleteReferences` service.
    pub fn new(session: &Session) -> Self {
        Self {
            references_to_delete: Vec::new(),
            header: RequestHeaderBuilder::new_from_session(session),
        }
    }

    /// Construct a new call to the `DeleteReferences` service, setting header parameters manually.
    pub fn new_manual(
        session_id: u32,
        timeout: Duration,
        auth_token: NodeId,
        request_handle: IntegerId,
    ) -> Self {
        Self {
            references_to_delete: Vec::new(),
            header: RequestHeaderBuilder::new(session_id, timeout, auth_token, request_handle),
        }
    }

    /// Set nodes to delete, overwriting any that were set previously.
    pub fn references_to_delete(mut self, references_to_delete: Vec<DeleteReferencesItem>) -> Self {
        self.references_to_delete = references_to_delete;
        self
    }

    /// Add a reference to delete.
    pub fn reference(mut self, reference: impl Into<DeleteReferencesItem>) -> Self {
        self.references_to_delete.push(reference.into());
        self
    }
}

impl UARequest for DeleteReferences {
    type Out = DeleteReferencesResponse;

    async fn send<'a>(self, channel: &'a crate::AsyncSecureChannel) -> Result<Self::Out, StatusCode>
    where
        Self: 'a,
    {
        let span = debug_span!(
            "Sending DeleteReferences request",
            num_references_to_delete = self.references_to_delete.len()
        );
        let request = {
            let _h = span.enter();
            if self.references_to_delete.is_empty() {
                builder_error!(
                    self,
                    "delete_references, called with no references to delete"
                );
                return Err(StatusCode::BadNothingToDo);
            }
            DeleteReferencesRequest {
                request_header: self.header.header,
                references_to_delete: Some(self.references_to_delete),
            }
        };
        let response = channel
            .send(request, self.header.timeout)
            .instrument(span.clone())
            .await?;
        let _h = span.enter();
        if let ResponseMessage::DeleteReferences(response) = response {
            builder_debug!(self, "delete_references, success");
            process_service_result(&response.response_header)?;
            Ok(*response)
        } else {
            builder_error!(self, "delete_references failed");
            Err(process_unexpected_response(response))
        }
    }
}

impl Session {
    /// Add nodes by sending a [`AddNodesRequest`] to the server.
    ///
    /// See OPC UA Part 4 - Services 5.7.2 for complete description of the service and error responses.
    ///
    /// # Arguments
    ///
    /// * `nodes_to_add` - A list of [`AddNodesItem`] to be added to the server.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<AddNodesResult>)` - A list of [`AddNodesResult`] corresponding to each add node operation.
    /// * `Err(StatusCode)` - Request failed, [Status code](StatusCode) is the reason for failure.
    ///
    pub async fn add_nodes(
        &self,
        nodes_to_add: &[AddNodesItem],
    ) -> Result<Vec<AddNodesResult>, StatusCode> {
        Ok(AddNodes::new(self)
            .nodes_to_add(nodes_to_add.to_vec())
            .send(&self.channel)
            .await?
            .results
            .unwrap_or_default())
    }

    /// Add references by sending a [`AddReferencesRequest`] to the server.
    ///
    /// See OPC UA Part 4 - Services 5.7.3 for complete description of the service and error responses.
    ///
    /// # Arguments
    ///
    /// * `references_to_add` - A list of [`AddReferencesItem`] to be sent to the server.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<StatusCode>)` - A list of `StatusCode` corresponding to each add reference operation.
    /// * `Err(StatusCode)` - Request failed, [Status code](StatusCode) is the reason for failure.
    ///
    pub async fn add_references(
        &self,
        references_to_add: &[AddReferencesItem],
    ) -> Result<Vec<StatusCode>, StatusCode> {
        Ok(AddReferences::new(self)
            .references_to_add(references_to_add.to_vec())
            .send(&self.channel)
            .await?
            .results
            .unwrap_or_default())
    }

    /// Delete nodes by sending a [`DeleteNodesRequest`] to the server.
    ///
    /// See OPC UA Part 4 - Services 5.7.4 for complete description of the service and error responses.
    ///
    /// # Arguments
    ///
    /// * `nodes_to_delete` - A list of [`DeleteNodesItem`] to be sent to the server.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<StatusCode>)` - A list of `StatusCode` corresponding to each delete node operation.
    /// * `Err(StatusCode)` - Request failed, [Status code](StatusCode) is the reason for failure.
    ///
    pub async fn delete_nodes(
        &self,
        nodes_to_delete: &[DeleteNodesItem],
    ) -> Result<Vec<StatusCode>, StatusCode> {
        Ok(DeleteNodes::new(self)
            .nodes_to_delete(nodes_to_delete.to_vec())
            .send(&self.channel)
            .await?
            .results
            .unwrap_or_default())
    }

    /// Delete references by sending a [`DeleteReferencesRequest`] to the server.
    ///
    /// See OPC UA Part 4 - Services 5.7.5 for complete description of the service and error responses.
    ///
    /// # Arguments
    ///
    /// * `nodes_to_delete` - A list of [`DeleteReferencesItem`] to be sent to the server.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<StatusCode>)` - A list of `StatusCode` corresponding to each delete node operation.
    /// * `Err(StatusCode)` - Request failed, [Status code](StatusCode) is the reason for failure.
    ///
    pub async fn delete_references(
        &self,
        references_to_delete: &[DeleteReferencesItem],
    ) -> Result<Vec<StatusCode>, StatusCode> {
        Ok(DeleteReferences::new(self)
            .references_to_delete(references_to_delete.to_vec())
            .send(&self.channel)
            .await?
            .results
            .unwrap_or_default())
    }
}
