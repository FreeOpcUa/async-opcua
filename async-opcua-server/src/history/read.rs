use opcua_types::{
    DataValue, DateTime, ExtensionObject, HistoryData, HistoryModifiedData, ModificationInfo,
};

/// Sorts the slice of historical values chronologically or reverse-chronologically
/// based on the relationship between start_time and end_time.
/// - If start_time < end_time, sorts from oldest to newest (ascending source_timestamp).
/// - If start_time >= end_time, sorts from newest to oldest (descending source_timestamp).
pub fn sort_historical_values(values: &mut [DataValue], start_time: DateTime, end_time: DateTime) {
    if start_time < end_time {
        values.sort_by_key(|v| v.source_timestamp);
    } else {
        values.sort_by_key(|v| std::cmp::Reverse(v.source_timestamp));
    }
}

/// Formats a list of DataValues into an ExtensionObject containing either HistoryData
/// or HistoryModifiedData, depending on whether it is a modified values read request.
pub fn format_history_result(values: Vec<DataValue>, is_modified: bool) -> ExtensionObject {
    if is_modified {
        let history_modified_data = HistoryModifiedData {
            data_values: Some(values),
            modification_infos: modification_infos_or_none(Vec::new()),
        };
        ExtensionObject::from_message(history_modified_data)
    } else {
        let history_data = HistoryData {
            data_values: Some(values),
        };
        ExtensionObject::from_message(history_data)
    }
}

pub(crate) fn modification_infos_or_none(
    modification_infos: Vec<ModificationInfo>,
) -> Option<Vec<ModificationInfo>> {
    (!modification_infos.is_empty()).then_some(modification_infos)
}

#[cfg(test)]
mod tests {
    use super::*;
    use opcua_types::{HistoryUpdateType, ModificationInfo, UAString};

    #[test]
    fn modification_infos_or_none_preserves_none_for_empty_metadata() {
        assert_eq!(modification_infos_or_none(Vec::new()), None);
    }

    #[test]
    fn modification_infos_or_none_preserves_non_empty_metadata() {
        let info = ModificationInfo {
            modification_time: DateTime::from((2026, 6, 27, 0, 0, 0)),
            update_type: HistoryUpdateType::Update,
            user_name: UAString::from("operator"),
        };

        assert_eq!(
            modification_infos_or_none(vec![info.clone()]),
            Some(vec![info])
        );
    }
}
