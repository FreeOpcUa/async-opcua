//! Aggregate processing engine (Part 13).
//! Computes time-weighted average, minimum, maximum, and standard deviation over intervals.

use crate::aggregates::quality::compute_aggregate_quality;
use chrono::Duration as ChronoDuration;
use opcua_types::{AggregateConfiguration, DataValue, DateTime, NodeId, StatusCode, Variant};

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

/// Input values and interval metadata for aggregate calculations.
pub struct AggregateInput<'a> {
    /// Raw values whose timestamp falls inside the interval, time-sorted.
    pub values: &'a [&'a DataValue],
    /// Last raw value at/before interval_start (start-bound source). None until Phase C.
    pub prior: Option<&'a DataValue>,
    /// First raw value after interval_end. None until Phase C.
    pub next: Option<&'a DataValue>,
    /// Start timestamp of the processing interval.
    pub interval_start: DateTime,
    /// End timestamp of the processing interval.
    pub interval_end: DateTime,
    /// Aggregate configuration supplied by the ReadProcessed request.
    pub config: &'a AggregateConfiguration,
}

struct AggregatePreamble {
    quality: StatusCode,
    numeric_points: Vec<(DateTime, f64)>,
}

fn bad_no_data(interval_start: DateTime) -> DataValue {
    DataValue {
        value: None,
        status: Some(StatusCode::BadNoData),
        source_timestamp: Some(interval_start),
        server_timestamp: Some(DateTime::now()),
        ..Default::default()
    }
}

fn bad_aggregate_not_supported(interval_start: DateTime) -> DataValue {
    DataValue {
        value: None,
        status: Some(StatusCode::BadAggregateNotSupported),
        source_timestamp: Some(interval_start),
        server_timestamp: Some(DateTime::now()),
        ..Default::default()
    }
}

fn aggregate_preamble(input: &AggregateInput<'_>) -> Result<AggregatePreamble, DataValue> {
    let statuses: Vec<Option<StatusCode>> = input.values.iter().map(|v| v.status).collect();
    let quality = compute_aggregate_quality(&statuses);

    if quality == StatusCode::BadNoData {
        return Err(bad_no_data(input.interval_start));
    }

    let numeric_points: Vec<(DateTime, f64)> = input
        .values
        .iter()
        .filter_map(|v| {
            let t = get_value_timestamp(v);
            let val = v.value.as_ref().and_then(variant_to_f64)?;
            Some((t, val))
        })
        .collect();

    if numeric_points.is_empty() {
        return Err(bad_no_data(input.interval_start));
    }

    Ok(AggregatePreamble {
        quality,
        numeric_points,
    })
}

fn aggregate_result(
    result_value: Option<f64>,
    quality: StatusCode,
    interval_start: DateTime,
) -> DataValue {
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

fn agg_time_average(input: &AggregateInput<'_>) -> DataValue {
    let preamble = match aggregate_preamble(input) {
        Ok(preamble) => preamble,
        Err(value) => return value,
    };

    aggregate_result(
        calculate_time_weighted_average(
            &preamble.numeric_points,
            input.interval_start,
            input.interval_end,
        ),
        preamble.quality,
        input.interval_start,
    )
}

fn agg_minimum(input: &AggregateInput<'_>) -> DataValue {
    let preamble = match aggregate_preamble(input) {
        Ok(preamble) => preamble,
        Err(value) => return value,
    };

    aggregate_result(
        preamble
            .numeric_points
            .iter()
            .map(|(_, v)| *v)
            .min_by(|a, b| a.partial_cmp(b).unwrap()),
        preamble.quality,
        input.interval_start,
    )
}

fn agg_maximum(input: &AggregateInput<'_>) -> DataValue {
    let preamble = match aggregate_preamble(input) {
        Ok(preamble) => preamble,
        Err(value) => return value,
    };

    aggregate_result(
        preamble
            .numeric_points
            .iter()
            .map(|(_, v)| *v)
            .max_by(|a, b| a.partial_cmp(b).unwrap()),
        preamble.quality,
        input.interval_start,
    )
}

fn agg_std_dev_sample(input: &AggregateInput<'_>) -> DataValue {
    let preamble = match aggregate_preamble(input) {
        Ok(preamble) => preamble,
        Err(value) => return value,
    };

    let raw_values: Vec<f64> = preamble.numeric_points.iter().map(|(_, v)| *v).collect();
    aggregate_result(
        calculate_std_dev_sample(&raw_values),
        preamble.quality,
        input.interval_start,
    )
}

/// Dispatches an aggregate calculation to the implementation for the requested aggregate NodeId.
pub fn dispatch_aggregate(aggregate_type: &NodeId, input: &AggregateInput<'_>) -> DataValue {
    match aggregate_type.identifier {
        opcua_types::Identifier::Numeric(AGG_TIME_AVERAGE) => agg_time_average(input),
        opcua_types::Identifier::Numeric(AGG_MINIMUM) => agg_minimum(input),
        opcua_types::Identifier::Numeric(AGG_MAXIMUM) => agg_maximum(input),
        opcua_types::Identifier::Numeric(AGG_STANDARD_DEVIATION_SAMPLE) => {
            agg_std_dev_sample(input)
        }
        _ => bad_aggregate_not_supported(input.interval_start),
    }
}

/// Computes processed aggregate values for each partitioned interval.
pub fn compute_processed_intervals(
    raw_values: &[DataValue],
    aggregate_type: &NodeId,
    config: &AggregateConfiguration,
    start_time: DateTime,
    end_time: DateTime,
    processing_interval: f64,
) -> Vec<DataValue> {
    partition_intervals(start_time, end_time, processing_interval)
        .into_iter()
        .map(|(interval_start, interval_end)| {
            let (min_t, max_t) = if interval_start <= interval_end {
                (interval_start, interval_end)
            } else {
                (interval_end, interval_start)
            };

            let values_in_interval: Vec<&DataValue> = raw_values
                .iter()
                .filter(|value| {
                    let timestamp = get_value_timestamp(value);
                    timestamp >= min_t && timestamp < max_t
                })
                .collect();

            let input = AggregateInput {
                values: &values_in_interval,
                prior: None,
                next: None,
                interval_start,
                interval_end,
                config,
            };

            dispatch_aggregate(aggregate_type, &input)
        })
        .collect()
}
