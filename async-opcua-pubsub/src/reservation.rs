//! PubSub communication-id reservation helpers.

use std::collections::HashSet;

use opcua_types::ConfigurationVersionDataType;

use crate::config::PubSubConnectionConfig;

/// Session-scoped reservation state for PubSub WriterGroup and DataSetWriter ids.
#[derive(Debug, Default)]
pub struct IdReservation {
    writer_group_ids: HashSet<u16>,
    dataset_writer_ids: HashSet<u16>,
}

impl IdReservation {
    /// Reserve ids that are neither used by `connections` nor already reserved here.
    ///
    /// Returned ids are allocated lowest-unused-first. Values start at 1; 0 is not
    /// allocated for either id space.
    pub fn reserve(
        &mut self,
        connections: &[PubSubConnectionConfig],
        num_writer_groups: u16,
        num_dataset_writers: u16,
    ) -> (Vec<u16>, Vec<u16>) {
        let used_writer_group_ids = used_writer_group_ids(connections);
        let used_dataset_writer_ids = used_dataset_writer_ids(connections);

        let writer_group_ids = reserve_lowest_unused(
            &mut self.writer_group_ids,
            &used_writer_group_ids,
            num_writer_groups,
        );
        let dataset_writer_ids = reserve_lowest_unused(
            &mut self.dataset_writer_ids,
            &used_dataset_writer_ids,
            num_dataset_writers,
        );

        (writer_group_ids, dataset_writer_ids)
    }
}

/// Return true when a local DataSet metadata version can decode data for the expected version.
///
/// OPC UA Part 14 uses the major version as the compatibility boundary; minor-version
/// differences indicate compatible metadata changes.
pub fn configuration_version_compatible(
    local: &ConfigurationVersionDataType,
    expected: &ConfigurationVersionDataType,
) -> bool {
    local.major_version == expected.major_version
}

fn used_writer_group_ids(connections: &[PubSubConnectionConfig]) -> HashSet<u16> {
    connections
        .iter()
        .flat_map(|connection| {
            connection
                .writer_groups
                .iter()
                .map(|writer_group| writer_group.writer_group_id)
        })
        .collect()
}

fn used_dataset_writer_ids(connections: &[PubSubConnectionConfig]) -> HashSet<u16> {
    connections
        .iter()
        .flat_map(|connection| connection.writer_groups.iter())
        .flat_map(|writer_group| {
            writer_group
                .dataset_writers
                .iter()
                .map(|dataset_writer| dataset_writer.dataset_writer_id)
        })
        .collect()
}

fn reserve_lowest_unused(reserved: &mut HashSet<u16>, used: &HashSet<u16>, count: u16) -> Vec<u16> {
    let mut ids = Vec::with_capacity(usize::from(count));

    for candidate in 1..=u16::MAX {
        if ids.len() == usize::from(count) {
            break;
        }

        if used.contains(&candidate) || reserved.contains(&candidate) {
            continue;
        }

        reserved.insert(candidate);
        ids.push(candidate);
    }

    ids
}
