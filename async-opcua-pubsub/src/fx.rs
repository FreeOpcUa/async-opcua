//! In-process OPC UA FX connection orchestration helpers.

use opcua_types::{ConfigurationVersionDataType, StatusCode};

use crate::{
    configuration_version_compatible, IdReservation, PubSubConnectionConfig, ReaderGroupConfig,
    WriterGroupConfig,
};

/// In-process OPC UA FX ConnectionManager core.
#[derive(Debug, Default)]
pub struct ConnectionManager {
    reservation: IdReservation,
}

/// Result of establishing one logical FX connection.
#[derive(Debug, Clone)]
pub struct EstablishedConnection {
    /// Logical connection identifier assigned by the caller.
    pub connection_id: String,
    /// Publishing side with reserved WriterGroupId/DataSetWriterIds assigned.
    pub writer_group: WriterGroupConfig,
    /// Subscribing side with each DataSetReader bound to its paired writer's reserved DataSetWriterId.
    pub reader_group: ReaderGroupConfig,
    /// ConfigurationVersion recorded per paired DataSet at establish time (for drift detection).
    pub dataset_versions: Vec<ConfigurationVersionDataType>,
}

impl ConnectionManager {
    /// Create an empty in-process ConnectionManager.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Reserve publishing-side ids, bind paired readers, and record DataSet versions.
    ///
    /// This follows the core OPC UA FX Part 81 Annex E.2.2.1 reserve-then-bind flow:
    /// WriterGroup/DataSetWriter ids are reserved for the publishing side first, then
    /// the paired subscribing DataSetReaders are bound to the reserved DataSetWriter ids.
    ///
    /// # Errors
    ///
    /// Returns `BadConfigurationError` when the writer/reader lists do not pair 1:1.
    /// Returns `BadInvalidArgument` if the requested DataSetWriter count cannot be
    /// represented by the FX3 reservation primitive. Returns `BadResourceUnavailable`
    /// if the reservation primitive cannot provide all requested ids.
    pub fn establish_connection(
        &mut self,
        existing: &[PubSubConnectionConfig],
        connection_id: impl Into<String>,
        mut writer_group: WriterGroupConfig,
        mut reader_group: ReaderGroupConfig,
    ) -> Result<EstablishedConnection, StatusCode> {
        let writer_count = writer_group.dataset_writers.len();
        if writer_count != reader_group.dataset_readers.len() {
            return Err(StatusCode::BadConfigurationError);
        }

        let writer_count =
            u16::try_from(writer_count).map_err(|_| StatusCode::BadInvalidArgument)?;
        let (writer_group_ids, dataset_writer_ids) =
            self.reservation.reserve(existing, 1, writer_count);
        let writer_group_id = writer_group_ids
            .first()
            .copied()
            .ok_or(StatusCode::BadResourceUnavailable)?;

        if dataset_writer_ids.len() != usize::from(writer_count) {
            return Err(StatusCode::BadResourceUnavailable);
        }

        writer_group.writer_group_id = writer_group_id;
        let mut dataset_versions = Vec::with_capacity(usize::from(writer_count));

        // ponytail: This is only the in-process control-layer core; AssetVerification,
        // ControlGroup locking, the complete EstablishConnections Method command surface,
        // NodeIdTranslation, and SecurityGroups/SKS are intentionally out of scope here.
        for ((writer, reader), dataset_writer_id) in writer_group
            .dataset_writers
            .iter_mut()
            .zip(reader_group.dataset_readers.iter_mut())
            .zip(dataset_writer_ids)
        {
            writer.dataset_writer_id = dataset_writer_id;
            reader.dataset_writer_id = dataset_writer_id;
            dataset_versions.push(writer.published_dataset.configuration_version.clone());
        }

        Ok(EstablishedConnection {
            connection_id: connection_id.into(),
            writer_group,
            reader_group,
            dataset_versions,
        })
    }
}

impl EstablishedConnection {
    /// Return true if every live DataSet version remains compatible with the recorded version.
    #[must_use]
    pub fn is_current(&self, live_versions: &[ConfigurationVersionDataType]) -> bool {
        self.dataset_versions.len() == live_versions.len()
            && self
                .dataset_versions
                .iter()
                .zip(live_versions)
                .all(|(recorded, live)| configuration_version_compatible(recorded, live))
    }
}
