use crate::session::{continuation_points::ContinuationPoint, instance::Session};
use opcua_crypto::random;
use opcua_types::{
    match_extension_object_owned, ByteString, DeleteAtTimeDetails, DeleteEventDetails,
    DeleteRawModifiedDetails, DynEncodable, ExtensionObject, HistoryData, HistoryEvent,
    HistoryModifiedData, HistoryReadResult, HistoryReadValueId, HistoryUpdateResult, NodeId,
    NumericRange, QualifiedName, ReadAnnotationDataDetails, ReadAtTimeDetails, ReadEventDetails,
    ReadProcessedDetails, ReadRawModifiedDetails, StatusCode, UpdateDataDetails,
    UpdateEventDetails, UpdateStructureDataDetails,
};

/// Container for a single node in a history read request.
pub struct HistoryNode {
    node_id: NodeId,
    index_range: NumericRange,
    data_encoding: QualifiedName,
    input_continuation_point: Option<ContinuationPoint>,
    next_continuation_point: Option<ContinuationPoint>,
    result: Option<ExtensionObject>,
    status: StatusCode,
}

pub(crate) enum HistoryReadDetails {
    RawModified(ReadRawModifiedDetails),
    AtTime(ReadAtTimeDetails),
    Processed(ReadProcessedDetails),
    Events(ReadEventDetails),
    Annotations(ReadAnnotationDataDetails),
}

impl HistoryReadDetails {
    pub fn from_extension_object(obj: ExtensionObject) -> Result<Self, StatusCode> {
        match_extension_object_owned!(obj,
            v: ReadRawModifiedDetails => Ok(Self::RawModified(v)),
            v: ReadAtTimeDetails => Ok(Self::AtTime(v)),
            v: ReadProcessedDetails => Ok(Self::Processed(v)),
            v: ReadEventDetails => Ok(Self::Events(v)),
            v: ReadAnnotationDataDetails => Ok(Self::Annotations(v)),
            _ => Err(StatusCode::BadHistoryOperationInvalid)
        )
    }
}

/// Details object for history updates.
#[derive(Debug, Clone)]
pub enum HistoryUpdateDetails {
    /// Update data values.
    UpdateData(UpdateDataDetails),
    /// Update historical structure data.
    UpdateStructureData(UpdateStructureDataDetails),
    /// Update historical events.
    UpdateEvent(UpdateEventDetails),
    /// Delete raw/modified data values.
    DeleteRawModified(DeleteRawModifiedDetails),
    /// Delete at a specific list of timestamps.
    DeleteAtTime(DeleteAtTimeDetails),
    /// Delete historical events.
    DeleteEvent(DeleteEventDetails),
}

impl HistoryUpdateDetails {
    /// Try to create a `HistoryUpdateDetails` object from an extension object.
    pub fn from_extension_object(obj: ExtensionObject) -> Result<Self, StatusCode> {
        match_extension_object_owned!(obj,
            v: UpdateDataDetails => Ok(Self::UpdateData(v)),
            v: UpdateStructureDataDetails => Ok(Self::UpdateStructureData(v)),
            v: UpdateEventDetails => Ok(Self::UpdateEvent(v)),
            v: DeleteRawModifiedDetails => Ok(Self::DeleteRawModified(v)),
            v: DeleteAtTimeDetails => Ok(Self::DeleteAtTime(v)),
            v: DeleteEventDetails => Ok(Self::DeleteEvent(v)),
            _ => Err(StatusCode::BadHistoryOperationInvalid)
        )
    }

    /// Get the node ID of the details object, independent of type.
    pub fn node_id(&self) -> &NodeId {
        match self {
            HistoryUpdateDetails::UpdateData(d) => &d.node_id,
            HistoryUpdateDetails::UpdateStructureData(d) => &d.node_id,
            HistoryUpdateDetails::UpdateEvent(d) => &d.node_id,
            HistoryUpdateDetails::DeleteRawModified(d) => &d.node_id,
            HistoryUpdateDetails::DeleteAtTime(d) => &d.node_id,
            HistoryUpdateDetails::DeleteEvent(d) => &d.node_id,
        }
    }
}

/// Trait for values storable as history data.
pub trait HistoryResult: DynEncodable + Sized {
    /// Return an extension object containing the encoded data for the current object.
    fn into_extension_object(self) -> ExtensionObject {
        ExtensionObject::from_message(self)
    }
}

impl HistoryResult for HistoryData {}
impl HistoryResult for HistoryModifiedData {}
impl HistoryResult for HistoryEvent {}
// impl HistoryResult for HistoryModifiedEvent {}

impl HistoryNode {
    pub(crate) fn new(
        node: HistoryReadValueId,
        is_events: bool,
        cp: Option<ContinuationPoint>,
    ) -> Self {
        let mut status = StatusCode::BadNodeIdUnknown;

        if !matches!(node.index_range, NumericRange::None) && is_events {
            status = StatusCode::BadIndexRangeDataMismatch;
        }

        Self {
            node_id: node.node_id,
            index_range: node.index_range,
            data_encoding: node.data_encoding,
            input_continuation_point: cp,
            next_continuation_point: None,
            result: None,
            status,
        }
    }

    /// Get the node ID to read history from.
    pub fn node_id(&self) -> &NodeId {
        &self.node_id
    }

    /// Get the index range to read.
    pub fn index_range(&self) -> &NumericRange {
        &self.index_range
    }

    /// Get the specified data encoding to read.
    pub fn data_encoding(&self) -> &QualifiedName {
        &self.data_encoding
    }

    /// Get the current continuation point.
    pub fn continuation_point(&self) -> Option<&ContinuationPoint> {
        self.input_continuation_point.as_ref()
    }

    /// Get the next continuation point.
    pub fn next_continuation_point(&self) -> Option<&ContinuationPoint> {
        self.next_continuation_point.as_ref()
    }

    /// Set the next continuation point.
    pub fn set_next_continuation_point(&mut self, continuation_point: Option<ContinuationPoint>) {
        self.next_continuation_point = continuation_point;
    }

    /// Set the result to some history data object.
    pub fn set_result<T: HistoryResult>(&mut self, result: T) {
        self.result = Some(result.into_extension_object());
    }

    /// Set the result status.
    pub fn set_status(&mut self, status: StatusCode) {
        self.status = status;
    }

    /// Get the current result status.
    pub fn status(&self) -> StatusCode {
        self.status
    }

    pub(crate) fn into_result(mut self, session: &mut Session) -> HistoryReadResult {
        let cp = match self.next_continuation_point {
            Some(p) => {
                let id = random::byte_string(6);
                if session.add_history_continuation_point(&id, p).is_err() {
                    self.status = StatusCode::BadNoContinuationPoints;
                    ByteString::null()
                } else {
                    id
                }
            }
            None => ByteString::null(),
        };

        HistoryReadResult {
            status_code: self.status,
            continuation_point: cp,
            history_data: self.result.unwrap_or_else(ExtensionObject::null),
        }
    }
}

/// History update details for one node.
pub struct HistoryUpdateNode {
    details: HistoryUpdateDetails,
    status: StatusCode,
    operation_results: Option<Vec<StatusCode>>,
}

impl HistoryUpdateNode {
    pub(crate) fn new(details: HistoryUpdateDetails) -> Self {
        Self {
            details,
            status: StatusCode::BadNodeIdUnknown,
            operation_results: None,
        }
    }

    /// Set the result status of this history operation.
    pub fn set_status(&mut self, status: StatusCode) {
        self.status = status;
    }

    /// Get the current status.
    pub fn status(&self) -> StatusCode {
        self.status
    }

    /// Set the operation results. If present the length must match
    /// the length of the entries in the history update details.
    pub fn set_operation_results(&mut self, operation_results: Option<Vec<StatusCode>>) {
        self.operation_results = operation_results;
    }

    pub(crate) fn into_result(self) -> HistoryUpdateResult {
        HistoryUpdateResult {
            diagnostic_infos: None,
            status_code: self.status,
            operation_results: self.operation_results,
        }
    }

    /// Get a reference to the history update details describing the history update
    /// to execute.
    pub fn details(&self) -> &HistoryUpdateDetails {
        &self.details
    }
}
