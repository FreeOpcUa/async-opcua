use opcua_types::{DataValue, DateTime, ExtensionObject, HistoryData, HistoryModifiedData};

/// Sorts the slice of historical values chronologically or reverse-chronologically
/// based on the relationship between start_time and end_time.
/// - If start_time < end_time, sorts from oldest to newest (ascending source_timestamp).
/// - If start_time >= end_time, sorts from newest to oldest (descending source_timestamp).
pub fn sort_historical_values(values: &mut [DataValue], start_time: DateTime, end_time: DateTime) {
    if start_time < end_time {
        values.sort_by(|a, b| a.source_timestamp.cmp(&b.source_timestamp));
    } else {
        values.sort_by(|a, b| b.source_timestamp.cmp(&a.source_timestamp));
    }
}

/// Formats a list of DataValues into an ExtensionObject containing either HistoryData
/// or HistoryModifiedData, depending on whether it is a modified values read request.
pub fn format_history_result(values: Vec<DataValue>, is_modified: bool) -> ExtensionObject {
    if is_modified {
        let history_modified_data = HistoryModifiedData {
            data_values: Some(values),
            modification_infos: None,
        };
        ExtensionObject::from_message(history_modified_data)
    } else {
        let history_data = HistoryData {
            data_values: Some(values),
        };
        ExtensionObject::from_message(history_data)
    }
}
