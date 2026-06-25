//! UADP subscriber helpers for applying received DataSet fields to Variables.

use opcua_server::address_space::{AddressSpace, NodeType};
use opcua_types::{BinaryDecodable, Context, DataValue, StatusCode};

use crate::{
    codec::uadp::{PublisherId, UadpDataSetMessage, UadpNetworkMessage},
    config::{DataSetReaderConfig, ReaderGroupConfig},
};

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
        let Some(reader) = find_reader(reader_groups, &message.publisher_id, dataset_message)
        else {
            continue;
        };

        for (field, target_node) in dataset_message
            .fields
            .iter()
            .zip(reader.subscribed_variables.iter())
        {
            if let Some(mut node) = address_space.find_mut(target_node) {
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
    publisher_id: &PublisherId,
    dataset_message: &UadpDataSetMessage,
) -> Option<&'a DataSetReaderConfig> {
    reader_groups
        .iter()
        .flat_map(|reader_group| reader_group.dataset_readers.iter())
        .find(|reader| {
            reader.dataset_writer_id == dataset_message.dataset_writer_id
                && publisher_matches(reader.publisher_id.as_ref(), publisher_id)
        })
}

fn publisher_matches(expected: Option<&PublisherId>, actual: &PublisherId) -> bool {
    match expected {
        Some(expected) => expected == actual,
        None => true,
    }
}
