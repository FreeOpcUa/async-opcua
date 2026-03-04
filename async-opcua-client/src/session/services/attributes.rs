use std::time::Duration;

use crate::{
    session::{
        process_service_result, process_unexpected_response,
        request_builder::{
            builder_base, builder_debug, builder_error, builder_trace, RequestHeaderBuilder,
        },
        UARequest,
    },
    AsyncSecureChannel, Session,
};
use opcua_core::ResponseMessage;
use opcua_types::{
    DataValue, DeleteAtTimeDetails, DeleteEventDetails, DeleteRawModifiedDetails, ExtensionObject,
    HistoryReadRequest, HistoryReadResponse, HistoryReadResult, HistoryReadValueId,
    HistoryUpdateRequest, HistoryUpdateResponse, HistoryUpdateResult, IntegerId, NodeId,
    ReadAtTimeDetails, ReadEventDetails, ReadProcessedDetails, ReadRawModifiedDetails, ReadRequest,
    ReadResponse, ReadValueId, StatusCode, TimestampsToReturn, UpdateDataDetails,
    UpdateEventDetails, UpdateStructureDataDetails, WriteRequest, WriteResponse, WriteValue,
};
use tracing::{debug_span, Instrument};

/// Enumeration used with Session::history_read()
#[derive(Debug, Clone)]
pub enum HistoryReadAction {
    /// Read historical events.
    ReadEventDetails(ReadEventDetails),
    /// Read raw data values.
    ReadRawModifiedDetails(ReadRawModifiedDetails),
    /// Read data values with processing.
    ReadProcessedDetails(ReadProcessedDetails),
    /// Read data values at specific timestamps.
    ReadAtTimeDetails(ReadAtTimeDetails),
}

impl From<HistoryReadAction> for ExtensionObject {
    fn from(action: HistoryReadAction) -> Self {
        match action {
            HistoryReadAction::ReadEventDetails(v) => Self::from_message(v),
            HistoryReadAction::ReadRawModifiedDetails(v) => Self::from_message(v),
            HistoryReadAction::ReadProcessedDetails(v) => Self::from_message(v),
            HistoryReadAction::ReadAtTimeDetails(v) => Self::from_message(v),
        }
    }
}

/// Enumeration used with Session::history_update()
#[derive(Debug, Clone)]
pub enum HistoryUpdateAction {
    /// Update historical data values.
    UpdateDataDetails(UpdateDataDetails),
    /// Update historical structures.
    UpdateStructureDataDetails(UpdateStructureDataDetails),
    /// Update historical events.
    UpdateEventDetails(UpdateEventDetails),
    /// Delete raw data values.
    DeleteRawModifiedDetails(DeleteRawModifiedDetails),
    /// Delete data values at specific timestamps.
    DeleteAtTimeDetails(DeleteAtTimeDetails),
    /// Delete historical events.
    DeleteEventDetails(DeleteEventDetails),
}

impl From<UpdateDataDetails> for HistoryUpdateAction {
    fn from(value: UpdateDataDetails) -> Self {
        Self::UpdateDataDetails(value)
    }
}
impl From<UpdateStructureDataDetails> for HistoryUpdateAction {
    fn from(value: UpdateStructureDataDetails) -> Self {
        Self::UpdateStructureDataDetails(value)
    }
}
impl From<UpdateEventDetails> for HistoryUpdateAction {
    fn from(value: UpdateEventDetails) -> Self {
        Self::UpdateEventDetails(value)
    }
}
impl From<DeleteRawModifiedDetails> for HistoryUpdateAction {
    fn from(value: DeleteRawModifiedDetails) -> Self {
        Self::DeleteRawModifiedDetails(value)
    }
}
impl From<DeleteAtTimeDetails> for HistoryUpdateAction {
    fn from(value: DeleteAtTimeDetails) -> Self {
        Self::DeleteAtTimeDetails(value)
    }
}
impl From<DeleteEventDetails> for HistoryUpdateAction {
    fn from(value: DeleteEventDetails) -> Self {
        Self::DeleteEventDetails(value)
    }
}

impl From<HistoryUpdateAction> for ExtensionObject {
    fn from(action: HistoryUpdateAction) -> Self {
        match action {
            HistoryUpdateAction::UpdateDataDetails(v) => Self::from_message(v),
            HistoryUpdateAction::UpdateStructureDataDetails(v) => Self::from_message(v),
            HistoryUpdateAction::UpdateEventDetails(v) => Self::from_message(v),
            HistoryUpdateAction::DeleteRawModifiedDetails(v) => Self::from_message(v),
            HistoryUpdateAction::DeleteAtTimeDetails(v) => Self::from_message(v),
            HistoryUpdateAction::DeleteEventDetails(v) => Self::from_message(v),
        }
    }
}

/// Builder for a call to the `Read` service.
///
/// See OPC UA Part 4 - Services 5.10.2 for complete description of the service and error responses.
#[derive(Debug, Clone)]
pub struct Read {
    nodes_to_read: Vec<ReadValueId>,
    timestamps_to_return: TimestampsToReturn,
    max_age: f64,

    header: RequestHeaderBuilder,
}

impl Read {
    /// Construct a new call to the `Read` service.
    pub fn new(session: &Session) -> Self {
        Self {
            nodes_to_read: Vec::new(),
            timestamps_to_return: TimestampsToReturn::Neither,
            max_age: 0.0,
            header: RequestHeaderBuilder::new_from_session(session),
        }
    }

    /// Construct a new call to the `Read` service, setting header parameters manually.
    pub fn new_manual(
        session_id: u32,
        timeout: Duration,
        auth_token: NodeId,
        request_handle: IntegerId,
    ) -> Self {
        Self {
            nodes_to_read: Vec::new(),
            timestamps_to_return: TimestampsToReturn::Neither,
            max_age: 0.0,
            header: RequestHeaderBuilder::new(session_id, timeout, auth_token, request_handle),
        }
    }

    /// Set timestamps to return.
    pub fn timestamps_to_return(mut self, timestamps: TimestampsToReturn) -> Self {
        self.timestamps_to_return = timestamps;
        self
    }

    /// Set max age.
    pub fn max_age(mut self, max_age: f64) -> Self {
        self.max_age = max_age;
        self
    }

    /// Set nodes to read, overwriting any that were set previously.
    pub fn nodes_to_read(mut self, nodes_to_read: Vec<ReadValueId>) -> Self {
        self.nodes_to_read = nodes_to_read;
        self
    }

    /// Add a node to read.
    pub fn node(mut self, node: ReadValueId) -> Self {
        self.nodes_to_read.push(node);
        self
    }
}

builder_base!(Read);

impl UARequest for Read {
    type Out = ReadResponse;

    async fn send<'b>(self, channel: &'b AsyncSecureChannel) -> Result<Self::Out, StatusCode>
    where
        Self: 'b,
    {
        let span = debug_span!(
            "Sending Read request",
            nodes_to_read = self.nodes_to_read.len(),
            timestamps_to_return = ?self.timestamps_to_return,
            max_age = self.max_age
        );
        let request = {
            let _h = span.enter();
            if self.nodes_to_read.is_empty() {
                builder_error!(self, "read(), was not supplied with any nodes to read");
                return Err(StatusCode::BadNothingToDo);
            }
            ReadRequest {
                request_header: self.header.header,
                max_age: self.max_age,
                timestamps_to_return: self.timestamps_to_return,
                nodes_to_read: Some(self.nodes_to_read),
            }
        };

        let response = channel
            .send(request, self.header.timeout)
            .instrument(span.clone())
            .await?;

        let _h = span.enter();
        if let ResponseMessage::Read(response) = response {
            builder_debug!(self, "read(), success");
            process_service_result(&response.response_header)?;
            Ok(*response)
        } else {
            builder_error!(self, "read() value failed");
            Err(process_unexpected_response(response))
        }
    }
}

#[derive(Debug, Clone)]
/// Reads historical values or events of one or more nodes. The caller is expected to provide
/// a HistoryReadAction enum which must be one of the following:
///
/// * [`ReadEventDetails`]
/// * [`ReadRawModifiedDetails`]
/// * [`ReadProcessedDetails`]
/// * [`ReadAtTimeDetails`]
///
/// See OPC UA Part 4 - Services 5.10.3 for complete description of the service and error responses.
pub struct HistoryRead {
    details: HistoryReadAction,
    timestamps_to_return: TimestampsToReturn,
    release_continuation_points: bool,
    nodes_to_read: Vec<HistoryReadValueId>,

    header: RequestHeaderBuilder,
}

builder_base!(HistoryRead);

impl HistoryRead {
    /// Create a new `HistoryRead` request.
    pub fn new(details: HistoryReadAction, session: &Session) -> Self {
        Self {
            details,
            timestamps_to_return: TimestampsToReturn::Neither,
            release_continuation_points: false,
            nodes_to_read: Vec::new(),

            header: RequestHeaderBuilder::new_from_session(session),
        }
    }

    /// Construct a new call to the `HistoryRead` service, setting header parameters manually.
    pub fn new_manual(
        details: HistoryReadAction,
        session_id: u32,
        timeout: Duration,
        auth_token: NodeId,
        request_handle: IntegerId,
    ) -> Self {
        Self {
            details,
            timestamps_to_return: TimestampsToReturn::Neither,
            release_continuation_points: false,
            nodes_to_read: Vec::new(),
            header: RequestHeaderBuilder::new(session_id, timeout, auth_token, request_handle),
        }
    }

    /// Set timestamps to return.
    pub fn timestamps_to_return(mut self, timestamps: TimestampsToReturn) -> Self {
        self.timestamps_to_return = timestamps;
        self
    }

    /// Set release continuation points. Default is false, if this is true,
    /// continuation points will be freed and the request will return without reading
    /// any history.
    pub fn release_continuation_points(mut self, release_continuation_points: bool) -> Self {
        self.release_continuation_points = release_continuation_points;
        self
    }

    /// Set nodes to read, overwriting any that were set previously.
    pub fn nodes_to_read(mut self, nodes_to_read: Vec<HistoryReadValueId>) -> Self {
        self.nodes_to_read = nodes_to_read;
        self
    }

    /// Add a node to read.
    pub fn node(mut self, node: HistoryReadValueId) -> Self {
        self.nodes_to_read.push(node);
        self
    }
}

impl UARequest for HistoryRead {
    type Out = HistoryReadResponse;

    async fn send<'b>(self, channel: &'b AsyncSecureChannel) -> Result<Self::Out, StatusCode>
    where
        Self: 'b,
    {
        let span = debug_span!(
            "Sending HistoryRead request",
            details = ?self.details,
            timestamps_to_return = ?self.timestamps_to_return,
            release_continuation_points = self.release_continuation_points,
            num_nodes_to_read = self.nodes_to_read.len()
        );
        let request = {
            let _h = span.enter();
            let history_read_details = ExtensionObject::from(self.details);
            builder_trace!(
                self,
                "history_read() requested to read nodes {:?}",
                self.nodes_to_read
            );
            HistoryReadRequest {
                request_header: self.header.header,
                history_read_details,
                timestamps_to_return: self.timestamps_to_return,
                release_continuation_points: self.release_continuation_points,
                nodes_to_read: if self.nodes_to_read.is_empty() {
                    None
                } else {
                    Some(self.nodes_to_read)
                },
            }
        };

        let response = channel
            .send(request, self.header.timeout)
            .instrument(span.clone())
            .await?;
        let _h = span.enter();
        if let ResponseMessage::HistoryRead(response) = response {
            builder_debug!(self, "history_read(), success");
            process_service_result(&response.response_header)?;
            Ok(*response)
        } else {
            builder_error!(self, "history_read() value failed");
            Err(process_unexpected_response(response))
        }
    }
}

#[derive(Debug, Clone)]
/// Writes values to nodes by sending a [`WriteRequest`] to the server. Note that some servers may reject DataValues
/// containing source or server timestamps.
///
/// See OPC UA Part 4 - Services 5.10.4 for complete description of the service and error responses.
pub struct Write {
    nodes_to_write: Vec<WriteValue>,

    header: RequestHeaderBuilder,
}

builder_base!(Write);

impl Write {
    /// Construct a new call to the `Write` service.
    pub fn new(session: &Session) -> Self {
        Self {
            nodes_to_write: Vec::new(),
            header: RequestHeaderBuilder::new_from_session(session),
        }
    }

    /// Construct a new call to the `Write` service, setting header parameters manually.
    pub fn new_manual(
        session_id: u32,
        timeout: Duration,
        auth_token: NodeId,
        request_handle: IntegerId,
    ) -> Self {
        Self {
            nodes_to_write: Vec::new(),
            header: RequestHeaderBuilder::new(session_id, timeout, auth_token, request_handle),
        }
    }

    /// Set nodes to write, overwriting any that were set previously.
    pub fn nodes_to_write(mut self, nodes_to_write: Vec<WriteValue>) -> Self {
        self.nodes_to_write = nodes_to_write;
        self
    }

    /// Add a write value.
    pub fn node(mut self, node: impl Into<WriteValue>) -> Self {
        self.nodes_to_write.push(node.into());
        self
    }
}

impl UARequest for Write {
    type Out = WriteResponse;

    async fn send<'a>(self, channel: &'a AsyncSecureChannel) -> Result<Self::Out, StatusCode>
    where
        Self: 'a,
    {
        let span = debug_span!(
            "Sending Write request",
            num_nodes_to_write = self.nodes_to_write.len()
        );
        let request = {
            let _h = span.enter();
            if self.nodes_to_write.is_empty() {
                builder_error!(self, "write(), was not supplied with any nodes to write");
                return Err(StatusCode::BadNothingToDo);
            }
            WriteRequest {
                request_header: self.header.header,
                nodes_to_write: Some(self.nodes_to_write),
            }
        };
        let response = channel
            .send(request, self.header.timeout)
            .instrument(span.clone())
            .await?;
        let _h = span.enter();
        if let ResponseMessage::Write(response) = response {
            builder_debug!(self, "write(), success");
            process_service_result(&response.response_header)?;
            Ok(*response)
        } else {
            builder_error!(self, "write() failed {:?}", response);
            Err(process_unexpected_response(response))
        }
    }
}

#[derive(Debug, Clone)]
/// Updates historical values. The caller is expected to provide one or more history update operations
/// in a slice of HistoryUpdateAction enums which are one of the following:
///
/// * [`UpdateDataDetails`]
/// * [`UpdateStructureDataDetails`]
/// * [`UpdateEventDetails`]
/// * [`DeleteRawModifiedDetails`]
/// * [`DeleteAtTimeDetails`]
/// * [`DeleteEventDetails`]
///
/// See OPC UA Part 4 - Services 5.10.5 for complete description of the service and error responses.
pub struct HistoryUpdate {
    details: Vec<HistoryUpdateAction>,

    header: RequestHeaderBuilder,
}

builder_base!(HistoryUpdate);

impl HistoryUpdate {
    /// Construct a new call to the `HistoryUpdate` service.
    pub fn new(session: &Session) -> Self {
        Self {
            details: Vec::new(),

            header: RequestHeaderBuilder::new_from_session(session),
        }
    }

    /// Construct a new call to the `HistoryUpdate` service, setting header parameters manually.
    pub fn new_manual(
        session_id: u32,
        timeout: Duration,
        auth_token: NodeId,
        request_handle: IntegerId,
    ) -> Self {
        Self {
            details: Vec::new(),
            header: RequestHeaderBuilder::new(session_id, timeout, auth_token, request_handle),
        }
    }

    /// Set the history update actions to perform.
    pub fn details(mut self, details: Vec<HistoryUpdateAction>) -> Self {
        self.details = details;
        self
    }

    /// Add a history update action to the list.
    pub fn action(mut self, action: impl Into<HistoryUpdateAction>) -> Self {
        self.details.push(action.into());
        self
    }
}

impl UARequest for HistoryUpdate {
    type Out = HistoryUpdateResponse;

    async fn send<'a>(self, channel: &'a AsyncSecureChannel) -> Result<Self::Out, StatusCode>
    where
        Self: 'a,
    {
        let span = debug_span!(
            "Sending HistoryUpdate request",
            num_details = self.details.len()
        );
        let request = {
            let _h = span.enter();
            if self.details.is_empty() {
                builder_error!(
                    self,
                    "history_update(), was not supplied with any detail to update"
                );
                return Err(StatusCode::BadNothingToDo);
            }
            let details = self
                .details
                .into_iter()
                .map(ExtensionObject::from)
                .collect();
            HistoryUpdateRequest {
                request_header: self.header.header,
                history_update_details: Some(details),
            }
        };

        let response = channel
            .send(request, self.header.timeout)
            .instrument(span.clone())
            .await?;
        let _h = span.enter();
        if let ResponseMessage::HistoryUpdate(response) = response {
            builder_error!(self, "history_update(), success");
            process_service_result(&response.response_header)?;
            Ok(*response)
        } else {
            builder_error!(self, "history_update() failed {:?}", response);
            Err(process_unexpected_response(response))
        }
    }
}

impl Session {
    /// Reads the value of nodes by sending a [`ReadRequest`] to the server.
    ///
    /// See OPC UA Part 4 - Services 5.10.2 for complete description of the service and error responses.
    ///
    /// # Arguments
    ///
    /// * `nodes_to_read` - A list of [`ReadValueId`] to be read by the server.
    /// * `timestamps_to_return` - The [`TimestampsToReturn`] for each node, Both, Server, Source or None
    /// * `max_age` - The maximum age of value to read in milliseconds. Read the service description
    ///   for details. Basically it will attempt to read a value within the age range or
    ///   attempt to read a new value. If 0 the server will attempt to read a new value from the datasource.
    ///   If set to `i32::MAX` or greater, the server shall attempt to get a cached value.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<DataValue>)` - A list of [`DataValue`] corresponding to each read operation.
    /// * `Err(StatusCode)` - Request failed, [Status code](StatusCode) is the reason for failure.
    ///
    pub async fn read(
        &self,
        nodes_to_read: &[ReadValueId],
        timestamps_to_return: TimestampsToReturn,
        max_age: f64,
    ) -> Result<Vec<DataValue>, StatusCode> {
        Ok(Read::new(self)
            .nodes_to_read(nodes_to_read.to_vec())
            .timestamps_to_return(timestamps_to_return)
            .max_age(max_age)
            .send(&self.channel)
            .await?
            .results
            .unwrap_or_default())
    }

    /// Reads historical values or events of one or more nodes. The caller is expected to provide
    /// a HistoryReadAction enum which must be one of the following:
    ///
    /// * [`ReadEventDetails`]
    /// * [`ReadRawModifiedDetails`]
    /// * [`ReadProcessedDetails`]
    /// * [`ReadAtTimeDetails`]
    ///
    /// See OPC UA Part 4 - Services 5.10.3 for complete description of the service and error responses.
    ///
    /// # Arguments
    ///
    /// * `history_read_details` - A history read operation.
    /// * `timestamps_to_return` - Enumeration of which timestamps to return.
    /// * `release_continuation_points` - Flag indicating whether to release the continuation point for the operation.
    /// * `nodes_to_read` - The list of [`HistoryReadValueId`] of the nodes to apply the history read operation to.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<HistoryReadResult>)` - A list of [`HistoryReadResult`] results corresponding to history read operation.
    /// * `Err(StatusCode)` - Request failed, [Status code](StatusCode) is the reason for failure.
    ///
    pub async fn history_read(
        &self,
        history_read_details: HistoryReadAction,
        timestamps_to_return: TimestampsToReturn,
        release_continuation_points: bool,
        nodes_to_read: &[HistoryReadValueId],
    ) -> Result<Vec<HistoryReadResult>, StatusCode> {
        Ok(HistoryRead::new(history_read_details, self)
            .timestamps_to_return(timestamps_to_return)
            .release_continuation_points(release_continuation_points)
            .nodes_to_read(nodes_to_read.to_vec())
            .send(&self.channel)
            .await?
            .results
            .unwrap_or_default())
    }

    /// Writes values to nodes by sending a [`WriteRequest`] to the server. Note that some servers may reject DataValues
    /// containing source or server timestamps.
    ///
    /// See OPC UA Part 4 - Services 5.10.4 for complete description of the service and error responses.
    ///
    /// # Arguments
    ///
    /// * `nodes_to_write` - A list of [`WriteValue`] to be sent to the server.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<StatusCode>)` - A list of [`StatusCode`] results corresponding to each write operation.
    /// * `Err(StatusCode)` - Request failed, [Status code](StatusCode) is the reason for failure.
    ///
    pub async fn write(
        &self,
        nodes_to_write: &[WriteValue],
    ) -> Result<Vec<StatusCode>, StatusCode> {
        Ok(Write::new(self)
            .nodes_to_write(nodes_to_write.to_vec())
            .send(&self.channel)
            .await?
            .results
            .unwrap_or_default())
    }

    /// Updates historical values. The caller is expected to provide one or more history update operations
    /// in a slice of HistoryUpdateAction enums which are one of the following:
    ///
    /// * [`UpdateDataDetails`]
    /// * [`UpdateStructureDataDetails`]
    /// * [`UpdateEventDetails`]
    /// * [`DeleteRawModifiedDetails`]
    /// * [`DeleteAtTimeDetails`]
    /// * [`DeleteEventDetails`]
    ///
    /// See OPC UA Part 4 - Services 5.10.5 for complete description of the service and error responses.
    ///
    /// # Arguments
    ///
    /// * `history_update_details` - A list of history update operations.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<HistoryUpdateResult>)` - A list of [`HistoryUpdateResult`] results corresponding to history update operation.
    /// * `Err(StatusCode)` - Request failed, [Status code](StatusCode) is the reason for failure.
    ///
    pub async fn history_update(
        &self,
        history_update_details: &[HistoryUpdateAction],
    ) -> Result<Vec<HistoryUpdateResult>, StatusCode> {
        Ok(HistoryUpdate::new(self)
            .details(history_update_details.to_vec())
            .send(&self.channel)
            .await?
            .results
            .unwrap_or_default())
    }
}
