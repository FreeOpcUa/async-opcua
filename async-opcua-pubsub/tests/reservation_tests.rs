//! FX3 (Part 14 §9.1.3.7.5 ReserveIds + §6.2.3 ConfigurationVersion): independent oracle tests.

use opcua_pubsub::{
    configuration_version_compatible, DataSetWriterConfig, IdReservation, MessageEncoding,
    PubSubConnectionConfig, PublishedDataSetConfig, WriterGroupConfig,
};
use opcua_types::ConfigurationVersionDataType;

fn conn(writer_group_id: u16, dataset_writer_id: u16) -> PubSubConnectionConfig {
    PubSubConnectionConfig {
        connection_id: "c".into(),
        name: "c".into(),
        address: "udp://239.0.0.1:4840".into(),
        reader_groups: Vec::new(),
        writer_groups: vec![WriterGroupConfig {
            writer_group_id,
            publishing_interval: 100,
            encoding: MessageEncoding::Uadp,
            dataset_writers: vec![DataSetWriterConfig {
                dataset_writer_id,
                dataset_name: "ds".into(),
                published_dataset: PublishedDataSetConfig {
                    published_variables: vec![],
                    configuration_version: Default::default(),
                },
            }],
        }],
    }
}

#[test]
fn reserve_from_empty_config_starts_at_one() {
    let mut res = IdReservation::default();
    let (wg, dsw) = res.reserve(&[], 3, 2);
    assert_eq!(wg, vec![1, 2, 3]);
    assert_eq!(dsw, vec![1, 2]);
}

#[test]
fn reserve_skips_ids_used_in_config() {
    // Config already uses writer-group 1 and dataset-writer 2.
    let connections = [conn(1, 2)];
    let mut res = IdReservation::default();
    let (wg, dsw) = res.reserve(&connections, 2, 2);
    // 1 is taken -> next two writer-group ids are 2,3 (3 because... no: 2 is free for WG).
    assert_eq!(wg, vec![2, 3]);
    // dataset-writer 2 is taken -> 1,3.
    assert_eq!(dsw, vec![1, 3]);
}

#[test]
fn repeated_reservations_do_not_collide() {
    let mut res = IdReservation::default();
    let (wg1, _) = res.reserve(&[], 2, 0);
    let (wg2, _) = res.reserve(&[], 2, 0);
    assert_eq!(wg1, vec![1, 2]);
    // Second call must continue past the already-handed-out ids, not repeat them.
    assert_eq!(wg2, vec![3, 4]);
    // No id appears twice across calls.
    assert!(wg1.iter().all(|id| !wg2.contains(id)));
}

#[test]
fn configuration_version_major_match_is_compatible() {
    let a = ConfigurationVersionDataType {
        major_version: 5,
        minor_version: 1,
    };
    // Same major, differing minor -> compatible drift.
    let b = ConfigurationVersionDataType {
        major_version: 5,
        minor_version: 99,
    };
    assert!(configuration_version_compatible(&a, &b));

    // Different major -> incompatible.
    let c = ConfigurationVersionDataType {
        major_version: 6,
        minor_version: 1,
    };
    assert!(!configuration_version_compatible(&a, &c));
}
