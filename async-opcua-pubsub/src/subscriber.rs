//! UADP subscriber runtime for applying received DataSet fields to Variables.

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use opcua_core::sync::RwLock;
use opcua_server::address_space::{AddressSpace, NodeType};
use opcua_types::{
    AttributeId, BinaryDecodable, Context, DataValue, MessageSecurityMode, PubSubState, StatusCode,
};

use crate::{
    codec::uadp::{PublisherId, UadpDataSetMessage, UadpNetworkMessage},
    config::{DataSetReaderConfig, FieldTargetConfig, PubSubConnectionConfig, ReaderGroupConfig},
    transport::udp::is_custom_fragment_datagram,
};

/// Subscriber-side processing error captured in reader diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubscriberError {
    /// Received field count does not match configured target mappings.
    FieldCountMismatch,
    /// A configured target node was not found.
    TargetNotFound,
    /// A configured target node is not a Variable.
    TargetNotVariable,
    /// The configured target mapping is unsupported by this runtime.
    UnsupportedTarget,
    /// The reader did not receive a new DataSetMessage within MessageReceiveTimeout.
    MessageReceiveTimeout,
    /// Received metadata major version is incompatible with configured metadata.
    MetadataMajorVersionMismatch,
}

/// Observable per-DataSetReader status snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataSetReaderStatus {
    /// Part 14 PubSub state for this DataSetReader.
    pub state: PubSubState,
    /// Last accepted DataSetMessage sequence number.
    pub last_sequence_number: Option<u64>,
    /// Last accepted receive timestamp.
    pub last_receive_time: Option<Instant>,
    /// Last structured subscriber error.
    pub last_error: Option<SubscriberError>,
    /// Accepted DataSetMessages.
    pub accepted_count: u64,
    /// Messages filtered by reader criteria.
    pub filtered_count: u64,
    /// Malformed or unsupported messages.
    pub dropped_count: u64,
    /// Observed sequence gaps.
    pub sequence_gap_count: u64,
    /// Observed duplicate sequences.
    pub duplicate_count: u64,
    /// Observed out-of-order sequences.
    pub out_of_order_count: u64,
    /// MessageReceiveTimeout expirations.
    pub timeout_count: u64,
    /// Security verification, token, nonce, or replay failures.
    pub security_failure_count: u64,
    pub(crate) metadata_mismatch_since: Option<Instant>,
}

impl Default for DataSetReaderStatus {
    fn default() -> Self {
        Self {
            state: PubSubState::PreOperational,
            last_sequence_number: None,
            last_receive_time: None,
            last_error: None,
            accepted_count: 0,
            filtered_count: 0,
            dropped_count: 0,
            sequence_gap_count: 0,
            duplicate_count: 0,
            out_of_order_count: 0,
            timeout_count: 0,
            security_failure_count: 0,
            metadata_mismatch_since: None,
        }
    }
}

/// Result summary for one subscriber datagram or NetworkMessage.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SubscriberApplyOutcome {
    /// Number of reader filters that matched DataSetMessages.
    pub matched_readers: usize,
    /// Number of readers whose targets were updated.
    pub applied_readers: usize,
    /// Number of reader filters that rejected DataSetMessages.
    pub filtered_readers: usize,
    /// Datagram-level drop reason, if any.
    pub dropped_reason: Option<SubscriberError>,
}

/// Effective secure UADP settings for a DataSetReader.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SubscriberSecurityConfig {
    pub(crate) security_mode: MessageSecurityMode,
    pub(crate) security_policy_uri: String,
    pub(crate) security_group_id: String,
}

/// Runtime receiver, dispatcher, target applier, and status store for DataSetReaders.
pub struct SubscriberRuntime {
    address_space: Arc<RwLock<AddressSpace>>,
    reader_groups: Vec<ReaderGroupConfig>,
    statuses: HashMap<u16, DataSetReaderStatus>,
    timeouts: HashMap<u16, Duration>,
    metadata_major_versions: HashMap<u16, Option<u32>>,
}

impl SubscriberRuntime {
    /// Builds a subscriber runtime from connection configs.
    pub fn with_connections(
        address_space: Arc<RwLock<AddressSpace>>,
        connections: Vec<PubSubConnectionConfig>,
    ) -> Result<Self, StatusCode> {
        for connection in &connections {
            connection.validate_subscriber_config()?;
        }

        let mut reader_groups = Vec::new();
        let mut statuses = HashMap::new();
        let mut timeouts = HashMap::new();
        let mut metadata_major_versions = HashMap::new();

        for connection in connections {
            for reader_group in connection.reader_groups {
                for reader in &reader_group.dataset_readers {
                    statuses
                        .entry(reader.dataset_reader_id)
                        .or_insert_with(DataSetReaderStatus::default);
                    if let Some(timeout) = reader.message_receive_timeout {
                        timeouts.insert(reader.dataset_reader_id, timeout);
                    }
                    metadata_major_versions
                        .insert(reader.dataset_reader_id, reader.metadata_major_version);
                }
                reader_groups.push(reader_group);
            }
        }

        Ok(Self {
            address_space,
            reader_groups,
            statuses,
            timeouts,
            metadata_major_versions,
        })
    }

    /// Processes a plain UADP datagram.
    pub fn process_datagram(
        &mut self,
        payload: &[u8],
        ctx: &Context<'_>,
    ) -> Result<SubscriberApplyOutcome, StatusCode> {
        if is_custom_fragment_datagram(payload) {
            self.record_drop_for_all(SubscriberError::UnsupportedTarget);
            return Err(StatusCode::BadNotSupported);
        }

        let message =
            UadpNetworkMessage::decode(&mut &payload[..], ctx).map_err(|error| error.status())?;
        self.process_network_message(&message)
    }

    /// Processes an already decoded and verified UADP NetworkMessage.
    pub fn process_network_message(
        &mut self,
        message: &UadpNetworkMessage,
    ) -> Result<SubscriberApplyOutcome, StatusCode> {
        self.process_network_message_at(message, Instant::now())
    }

    /// Processes an already decoded and verified UADP NetworkMessage at a supplied time.
    pub fn process_network_message_at(
        &mut self,
        message: &UadpNetworkMessage,
        now: Instant,
    ) -> Result<SubscriberApplyOutcome, StatusCode> {
        let mut outcome = SubscriberApplyOutcome::default();

        for dataset_message in &message.dataset_messages {
            for reader in self
                .reader_groups
                .iter()
                .flat_map(|reader_group| reader_group.dataset_readers.iter())
                .cloned()
                .collect::<Vec<_>>()
            {
                if !reader_matches(&reader, message, dataset_message) {
                    outcome.filtered_readers += 1;
                    if let Some(status) = self.statuses.get_mut(&reader.dataset_reader_id) {
                        status.filtered_count += 1;
                    }
                    continue;
                }

                outcome.matched_readers += 1;
                match self.apply_reader(&reader, dataset_message, now) {
                    Ok(()) => outcome.applied_readers += 1,
                    Err(error) => {
                        if let Some(status) = self.statuses.get_mut(&reader.dataset_reader_id) {
                            status.last_error = Some(error);
                            status.dropped_count += 1;
                            status.state = PubSubState::Error;
                        }
                    }
                }
            }
        }

        Ok(outcome)
    }

    /// Returns a reader status snapshot.
    #[must_use]
    pub fn reader_status(&self, reader_id: u16) -> Option<DataSetReaderStatus> {
        self.statuses.get(&reader_id).cloned()
    }

    /// Records a security failure for specific reader ids.
    pub(crate) fn record_security_failure_for_readers(&mut self, reader_ids: &[u16]) {
        for reader_id in reader_ids {
            if let Some(status) = self.statuses.get_mut(reader_id) {
                status.security_failure_count += 1;
                status.last_error = None;
            }
        }
    }

    /// Checks MessageReceiveTimeout and pending metadata-version mismatch deadlines.
    pub fn check_timeouts_at(&mut self, now: Instant) {
        for (reader_id, status) in &mut self.statuses {
            let Some(timeout) = self.timeouts.get(reader_id).copied() else {
                continue;
            };

            if let Some(mismatch_since) = status.metadata_mismatch_since {
                if now.duration_since(mismatch_since) >= timeout {
                    status.state = PubSubState::Error;
                    status.last_error = Some(SubscriberError::MetadataMajorVersionMismatch);
                    continue;
                }
            }

            if status.state == PubSubState::Operational {
                if let Some(last_receive_time) = status.last_receive_time {
                    if now.duration_since(last_receive_time) >= timeout {
                        status.state = PubSubState::Error;
                        status.last_error = Some(SubscriberError::MessageReceiveTimeout);
                        status.timeout_count += 1;
                    }
                }
            }
        }
    }

    /// Observes a received metadata major version for one reader.
    pub fn observe_metadata_major_version_at(
        &mut self,
        reader_id: u16,
        observed_major_version: u32,
        now: Instant,
    ) -> Result<(), StatusCode> {
        let Some(configured_major_version) = self.metadata_major_versions.get(&reader_id).copied()
        else {
            return Err(StatusCode::BadNotFound);
        };
        let Some(status) = self.statuses.get_mut(&reader_id) else {
            return Err(StatusCode::BadNotFound);
        };

        if matches!(configured_major_version, Some(configured) if configured != observed_major_version)
        {
            status.metadata_mismatch_since.get_or_insert(now);
        } else {
            status.metadata_mismatch_since = None;
        }

        Ok(())
    }

    fn apply_reader(
        &mut self,
        reader: &DataSetReaderConfig,
        dataset_message: &UadpDataSetMessage,
        now: Instant,
    ) -> Result<(), SubscriberError> {
        let targets = reader.effective_target_variables();
        if targets.len() != dataset_message.fields.len() {
            return Err(SubscriberError::FieldCountMismatch);
        }

        let mut writes = Vec::with_capacity(targets.len());
        for target in &targets {
            validate_target_config(target)?;
            let Some(field) = dataset_message.fields.get(target.dataset_field_index) else {
                return Err(SubscriberError::FieldCountMismatch);
            };
            writes.push((target.target_node_id.clone(), field.clone()));
        }

        {
            let space = self.address_space.write();
            for (target_node_id, _) in &writes {
                let Some(node) = space.find(target_node_id) else {
                    return Err(SubscriberError::TargetNotFound);
                };
                if !matches!(&*node, NodeType::Variable(_)) {
                    return Err(SubscriberError::TargetNotVariable);
                }
            }
        }

        {
            let space = self.address_space.write();
            for (target_node_id, value) in writes {
                let Some(mut node) = space.find_mut(&target_node_id) else {
                    return Err(SubscriberError::TargetNotFound);
                };
                let NodeType::Variable(variable) = &mut *node else {
                    return Err(SubscriberError::TargetNotVariable);
                };
                variable.set_data_value(DataValue::value_only(value));
            }
        }

        if let Some(status) = self.statuses.get_mut(&reader.dataset_reader_id) {
            update_sequence_status(status, dataset_message.sequence_number);
            status.state = PubSubState::Operational;
            status.last_receive_time = Some(now);
            status.last_error = None;
            status.metadata_mismatch_since = None;
            status.accepted_count += 1;
        }

        Ok(())
    }

    fn record_drop_for_all(&mut self, error: SubscriberError) {
        for status in self.statuses.values_mut() {
            status.dropped_count += 1;
            status.last_error = Some(error);
        }
    }
}

/// Bind a decoded NetworkMessage's DataSets into the address space via matching DataSetReaders.
///
/// Returns the number of DataSetMessages applied.
pub fn apply_network_message(
    address_space: &mut AddressSpace,
    message: &UadpNetworkMessage,
    reader_groups: &[ReaderGroupConfig],
) -> usize {
    let mut applied = 0;

    for dataset_message in &message.dataset_messages {
        let Some(reader) = find_reader(reader_groups, message, dataset_message) else {
            continue;
        };

        let targets = reader.effective_target_variables();
        if targets.len() != dataset_message.fields.len() {
            continue;
        }

        for target in targets {
            let Some(field) = dataset_message.fields.get(target.dataset_field_index) else {
                continue;
            };
            if let Some(mut node) = address_space.find_mut(&target.target_node_id) {
                if let NodeType::Variable(variable) = &mut *node {
                    variable.set_data_value(DataValue::value_only(field.clone()));
                }
            }
        }

        applied += 1;
    }

    applied
}

/// Decode a UADP NetworkMessage and apply matching DataSets to target Variables.
pub fn decode_and_apply(
    address_space: &mut AddressSpace,
    payload: &[u8],
    ctx: &Context<'_>,
    reader_groups: &[ReaderGroupConfig],
) -> Result<usize, StatusCode> {
    let message =
        UadpNetworkMessage::decode(&mut &payload[..], ctx).map_err(|error| error.status())?;
    Ok(apply_network_message(
        address_space,
        &message,
        reader_groups,
    ))
}

fn find_reader<'a>(
    reader_groups: &'a [ReaderGroupConfig],
    message: &UadpNetworkMessage,
    dataset_message: &UadpDataSetMessage,
) -> Option<&'a DataSetReaderConfig> {
    reader_groups
        .iter()
        .flat_map(|reader_group| reader_group.dataset_readers.iter())
        .find(|reader| reader_matches(reader, message, dataset_message))
}

fn reader_matches(
    reader: &DataSetReaderConfig,
    message: &UadpNetworkMessage,
    dataset_message: &UadpDataSetMessage,
) -> bool {
    publisher_matches(reader.publisher_id.as_ref(), &message.publisher_id)
        && optional_u16_matches(reader.writer_group_id, message.writer_group_id)
        && optional_u16_matches(
            reader.network_message_number,
            message.network_message_number,
        )
        && dataset_writer_matches(reader.dataset_writer_id, dataset_message.dataset_writer_id)
}

fn publisher_matches(expected: Option<&PublisherId>, actual: &PublisherId) -> bool {
    match expected {
        None | Some(PublisherId::None) => true,
        Some(PublisherId::Byte(0))
        | Some(PublisherId::UInt16(0))
        | Some(PublisherId::UInt32(0))
        | Some(PublisherId::UInt64(0)) => true,
        Some(PublisherId::String(value)) if value.is_empty() => true,
        Some(expected) => expected == actual,
    }
}

fn optional_u16_matches(expected: Option<u16>, actual: u16) -> bool {
    match expected {
        Some(expected) => expected == actual,
        None => true,
    }
}

fn dataset_writer_matches(expected: u16, actual: u16) -> bool {
    expected == 0 || expected == actual
}

fn validate_target_config(target: &FieldTargetConfig) -> Result<(), SubscriberError> {
    if target.attribute_id != AttributeId::Value
        || matches!(target.index_range.as_deref(), Some(range) if !range.is_empty())
    {
        return Err(SubscriberError::UnsupportedTarget);
    }
    Ok(())
}

pub(crate) fn effective_security_config(
    reader_group: &ReaderGroupConfig,
    reader: &DataSetReaderConfig,
) -> Option<SubscriberSecurityConfig> {
    let security_mode = reader.security_mode.or(reader_group.security_mode)?;
    if !matches!(
        security_mode,
        MessageSecurityMode::Sign | MessageSecurityMode::SignAndEncrypt
    ) {
        return None;
    }

    let security_policy_uri = reader
        .security_policy_uri
        .as_deref()
        .or(reader_group.security_policy_uri.as_deref())?
        .to_string();
    let security_group_id = reader
        .security_group_id
        .as_deref()
        .or(reader_group.security_group_id.as_deref())?
        .to_string();

    Some(SubscriberSecurityConfig {
        security_mode,
        security_policy_uri,
        security_group_id,
    })
}

fn update_sequence_status(status: &mut DataSetReaderStatus, sequence_number: u16) {
    if let Some(last) = status.last_sequence_number {
        let last = last as u16;
        if sequence_number == last {
            status.duplicate_count += 1;
        } else {
            let expected = last.wrapping_add(1);
            if sequence_number != expected {
                let forward_distance = sequence_number.wrapping_sub(last);
                if forward_distance < (u16::MAX / 2) {
                    status.sequence_gap_count += 1;
                } else {
                    status.out_of_order_count += 1;
                }
            }
        }
    }

    status.last_sequence_number = Some(sequence_number as u64);
}
