//! Aggregate processing engine (Part 13).
//! Computes time-weighted average, minimum, maximum, and standard deviation over intervals.

use crate::aggregates::quality::compute_aggregate_quality;
use chrono::Duration as ChronoDuration;
use opcua_types::{DataValue, DateTime, NodeId, StatusCode, Variant};

// Standard AggregateFunction NodeIds (Part 13 / Part 6 NodeIds.csv). The implemented average is
// interpolated/time-weighted, so it maps to TimeAverage (2343), NOT simple Average (2342).
const AGG_TIME_AVERAGE: u32 = 2343;
const AGG_MINIMUM: u32 = 2346;
const AGG_MAXIMUM: u32 = 2347;
const AGG_STANDARD_DEVIATION_SAMPLE: u32 = 11426;

/// NodeId for the TimeAverage aggregate (interpolated, time-weighted — Part 13 §5.4.3.2).
pub fn aggregate_average() -> NodeId {
    NodeId::new(0, AGG_TIME_AVERAGE)
}

/// NodeId for the Minimum aggregate.
pub fn aggregate_minimum() -> NodeId {
    NodeId::new(0, AGG_MINIMUM)
}

/// NodeId for the Maximum aggregate.
pub fn aggregate_maximum() -> NodeId {
    NodeId::new(0, AGG_MAXIMUM)
}

/// NodeId for the StandardDeviationSample aggregate.
pub fn aggregate_std_dev() -> NodeId {
    NodeId::new(0, AGG_STANDARD_DEVIATION_SAMPLE)
}

/// Converts a Variant to f64 if it represents a numeric value.
pub fn variant_to_f64(variant: &Variant) -> Option<f64> {
    match variant {
        Variant::Double(v) => Some(*v),
        Variant::Float(v) => Some(*v as f64),
        Variant::Int32(v) => Some(*v as f64),
        Variant::UInt32(v) => Some(*v as f64),
        Variant::Int16(v) => Some(*v as f64),
        Variant::UInt16(v) => Some(*v as f64),
        Variant::SByte(v) => Some(*v as f64),
        Variant::Byte(v) => Some(*v as f64),
        Variant::Int64(v) => Some(*v as f64),
        Variant::UInt64(v) => Some(*v as f64),
        _ => None,
    }
}

/// Retrieves the timestamp of a DataValue, prioritizing source_timestamp then server_timestamp.
pub fn get_value_timestamp(value: &DataValue) -> DateTime {
    value
        .source_timestamp
        .or(value.server_timestamp)
        .unwrap_or_else(DateTime::now)
}

/// Partitions a time range into discrete processing intervals.
pub fn partition_intervals(
    start_time: DateTime,
    end_time: DateTime,
    processing_interval: f64,
) -> Vec<(DateTime, DateTime)> {
    if processing_interval <= 0.0 {
        return vec![(start_time, end_time)];
    }

    let mut intervals = Vec::new();
    let step = ChronoDuration::milliseconds(processing_interval as i64);

    if start_time <= end_time {
        let mut curr = start_time;
        while curr < end_time {
            let next = curr + step;
            let actual_next = if next > end_time { end_time } else { next };
            intervals.push((curr, actual_next));
            curr = actual_next;
            if curr >= end_time {
                break;
            }
        }
    } else {
        let mut curr = start_time;
        while curr > end_time {
            let next = curr - step;
            let actual_next = if next < end_time { end_time } else { next };
            intervals.push((curr, actual_next));
            curr = actual_next;
            if curr <= end_time {
                break;
            }
        }
    }

    intervals
}

/// Computes the time-weighted average for a set of data points in an interval.
pub fn calculate_time_weighted_average(
    points: &[(DateTime, f64)],
    start: DateTime,
    end: DateTime,
) -> Option<f64> {
    if points.is_empty() {
        return None;
    }

    let total_ms = (end - start).num_milliseconds() as f64;
    let total_ms = if total_ms < 0.0 { -total_ms } else { total_ms };
    if total_ms <= 0.0 {
        return None;
    }

    let mut sum = 0.0;
    let mut total_duration = 0.0;

    for i in 0..points.len() {
        let (t_curr, v_curr) = points[i];

        // Determine the start of the active window for this point
        let active_start = if i == 0 {
            if start <= end {
                if t_curr < start {
                    start
                } else {
                    t_curr
                }
            } else if t_curr > start {
                start
            } else {
                t_curr
            }
        } else {
            points[i].0
        };

        // Determine the end of the active window
        let active_end = if i == points.len() - 1 {
            end
        } else {
            points[i + 1].0
        };

        let duration = (active_end - active_start).num_milliseconds() as f64;
        let duration = if duration < 0.0 { -duration } else { duration };
        if duration > 0.0 {
            sum += v_curr * duration;
            total_duration += duration;
        }
    }

    if total_duration > 0.0 {
        Some(sum / total_duration)
    } else {
        let sum: f64 = points.iter().map(|(_, v)| v).sum();
        Some(sum / points.len() as f64)
    }
}

/// Computes the sample standard deviation for a slice of values.
pub fn calculate_std_dev_sample(values: &[f64]) -> Option<f64> {
    let n = values.len();
    if n < 2 {
        return None;
    }
    let mean = values.iter().sum::<f64>() / n as f64;
    let variance = values.iter().map(|&x| (x - mean).powi(2)).sum::<f64>() / (n - 1) as f64;
    Some(variance.sqrt())
}

/// Calculates the aggregate for a specific interval from raw values.
pub fn calculate_aggregate(
    values_in_interval: &[&DataValue],
    aggregate_type: &NodeId,
    interval_start: DateTime,
    interval_end: DateTime,
) -> DataValue {
    let statuses: Vec<Option<StatusCode>> = values_in_interval.iter().map(|v| v.status).collect();
    let quality = compute_aggregate_quality(&statuses);

    if quality == StatusCode::BadNoData {
        return DataValue {
            value: None,
            status: Some(StatusCode::BadNoData),
            source_timestamp: Some(interval_start),
            server_timestamp: Some(DateTime::now()),
            ..Default::default()
        };
    }

    let numeric_points: Vec<(DateTime, f64)> = values_in_interval
        .iter()
        .filter_map(|v| {
            let t = get_value_timestamp(v);
            let val = v.value.as_ref().and_then(variant_to_f64)?;
            Some((t, val))
        })
        .collect();

    if numeric_points.is_empty() {
        return DataValue {
            value: None,
            status: Some(StatusCode::BadNoData),
            source_timestamp: Some(interval_start),
            server_timestamp: Some(DateTime::now()),
            ..Default::default()
        };
    }

    let result_value = match aggregate_type.identifier {
        opcua_types::Identifier::Numeric(AGG_TIME_AVERAGE) => {
            calculate_time_weighted_average(&numeric_points, interval_start, interval_end)
        }
        opcua_types::Identifier::Numeric(AGG_MINIMUM) => numeric_points
            .iter()
            .map(|(_, v)| *v)
            .min_by(|a, b| a.partial_cmp(b).unwrap()),
        opcua_types::Identifier::Numeric(AGG_MAXIMUM) => numeric_points
            .iter()
            .map(|(_, v)| *v)
            .max_by(|a, b| a.partial_cmp(b).unwrap()),
        opcua_types::Identifier::Numeric(AGG_STANDARD_DEVIATION_SAMPLE) => {
            let raw_values: Vec<f64> = numeric_points.iter().map(|(_, v)| *v).collect();
            calculate_std_dev_sample(&raw_values)
        }
        _ => {
            return DataValue {
                value: None,
                status: Some(StatusCode::BadAggregateNotSupported),
                source_timestamp: Some(interval_start),
                server_timestamp: Some(DateTime::now()),
                ..Default::default()
            };
        }
    };

    match result_value {
        Some(val) => DataValue {
            value: Some(Variant::Double(val)),
            status: Some(quality),
            source_timestamp: Some(interval_start),
            server_timestamp: Some(DateTime::now()),
            ..Default::default()
        },
        None => DataValue {
            value: None,
            status: Some(StatusCode::BadNoData),
            source_timestamp: Some(interval_start),
            server_timestamp: Some(DateTime::now()),
            ..Default::default()
        },
    }
}
