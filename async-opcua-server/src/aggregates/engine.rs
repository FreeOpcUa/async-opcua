//! Aggregate processing engine (Part 13).
//! Computes time-weighted average, minimum, maximum, and standard deviation over intervals.

use crate::aggregates::quality::compute_aggregate_quality;
use chrono::Duration as ChronoDuration;
use opcua_types::{AggregateConfiguration, DataValue, DateTime, NodeId, StatusCode, Variant};

// Standard AggregateFunction NodeIds (Part 13 / Part 6 NodeIds.csv). The implemented average is
// interpolated/time-weighted, so it maps to TimeAverage (2343), NOT simple Average (2342).
const AGG_TIME_AVERAGE: u32 = 2343;
const AGG_AVERAGE: u32 = 2342;
const AGG_MINIMUM: u32 = 2346;
const AGG_MAXIMUM: u32 = 2347;
const AGG_MINIMUM_ACTUAL_TIME: u32 = 2348;
const AGG_MAXIMUM_ACTUAL_TIME: u32 = 2349;
const AGG_RANGE: u32 = 2350;
const AGG_COUNT: u32 = 2352;
const AGG_DELTA: u32 = 2359;
const AGG_WORST_QUALITY: u32 = 2364;
const AGG_STANDARD_DEVIATION_SAMPLE: u32 = 11426;
const AGG_STANDARD_DEVIATION_POPULATION: u32 = 11427;
const AGG_VARIANCE_SAMPLE: u32 = 11428;
const AGG_VARIANCE_POPULATION: u32 = 11429;

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

fn good_numeric_points<'a>(input: &AggregateInput<'a>) -> Vec<(DateTime, f64, &'a DataValue)> {
    input
        .values
        .iter()
        .filter_map(|v| {
            if v.status.is_none_or(|status| status.is_good()) {
                let t = get_value_timestamp(v);
                let val = v.value.as_ref().and_then(variant_to_f64)?;
                Some((t, val, *v))
            } else {
                None
            }
        })
        .collect()
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

fn aggregate_quality(input: &AggregateInput<'_>) -> StatusCode {
    let statuses: Vec<Option<StatusCode>> = input.values.iter().map(|v| v.status).collect();
    compute_aggregate_quality(&statuses)
}

fn agg_average(input: &AggregateInput<'_>) -> DataValue {
    let points = good_numeric_points(input);
    if points.is_empty() {
        return bad_no_data(input.interval_start);
    }

    let mean = points.iter().map(|(_, value, _)| value).sum::<f64>() / points.len() as f64;
    aggregate_result(Some(mean), aggregate_quality(input), input.interval_start)
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

fn agg_range(input: &AggregateInput<'_>) -> DataValue {
    let points = good_numeric_points(input);
    if points.is_empty() {
        return bad_no_data(input.interval_start);
    }

    let (min, max) = points
        .iter()
        .map(|(_, value, _)| *value)
        .fold((f64::INFINITY, f64::NEG_INFINITY), |(min, max), value| {
            (min.min(value), max.max(value))
        });
    aggregate_result(
        Some(max - min),
        aggregate_quality(input),
        input.interval_start,
    )
}

fn agg_delta(input: &AggregateInput<'_>) -> DataValue {
    let points = good_numeric_points(input);
    let Some((_, first, _)) = points.first() else {
        return bad_no_data(input.interval_start);
    };
    let Some((_, last, _)) = points.last() else {
        return bad_no_data(input.interval_start);
    };

    aggregate_result(
        Some(last - first),
        aggregate_quality(input),
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

fn agg_minimum_actual_time(input: &AggregateInput<'_>) -> DataValue {
    let points = good_numeric_points(input);
    let Some((timestamp, _, source)) =
        points
            .iter()
            .min_by(|(left_time, left_value, _), (right_time, right_value, _)| {
                left_value
                    .total_cmp(right_value)
                    .then_with(|| left_time.cmp(right_time))
            })
    else {
        return bad_no_data(input.interval_start);
    };

    // ponytail: MultipleValues aggregate-bit is not set yet when duplicate minima exist.
    DataValue {
        value: source.value.clone(),
        status: Some(aggregate_quality(input)),
        source_timestamp: Some(*timestamp),
        server_timestamp: Some(DateTime::now()),
        ..Default::default()
    }
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

fn agg_maximum_actual_time(input: &AggregateInput<'_>) -> DataValue {
    let points = good_numeric_points(input);
    let Some((timestamp, _, source)) =
        points
            .iter()
            .max_by(|(left_time, left_value, _), (right_time, right_value, _)| {
                left_value
                    .total_cmp(right_value)
                    .then_with(|| right_time.cmp(left_time))
            })
    else {
        return bad_no_data(input.interval_start);
    };

    // ponytail: MultipleValues aggregate-bit is not set yet when duplicate maxima exist.
    DataValue {
        value: source.value.clone(),
        status: Some(aggregate_quality(input)),
        source_timestamp: Some(*timestamp),
        server_timestamp: Some(DateTime::now()),
        ..Default::default()
    }
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

fn sample_variance(values: &[f64]) -> Option<f64> {
    let n = values.len();
    if n < 2 {
        return None;
    }

    let mean = values.iter().sum::<f64>() / n as f64;
    Some(
        values
            .iter()
            .map(|value| (value - mean).powi(2))
            .sum::<f64>()
            / (n - 1) as f64,
    )
}

fn population_variance(values: &[f64]) -> Option<f64> {
    let n = values.len();
    if n == 0 {
        return None;
    }

    let mean = values.iter().sum::<f64>() / n as f64;
    Some(
        values
            .iter()
            .map(|value| (value - mean).powi(2))
            .sum::<f64>()
            / n as f64,
    )
}

fn agg_variance_sample(input: &AggregateInput<'_>) -> DataValue {
    let values: Vec<f64> = good_numeric_points(input)
        .iter()
        .map(|(_, value, _)| *value)
        .collect();
    aggregate_result(
        sample_variance(&values),
        aggregate_quality(input),
        input.interval_start,
    )
}

fn agg_std_dev_population(input: &AggregateInput<'_>) -> DataValue {
    let values: Vec<f64> = good_numeric_points(input)
        .iter()
        .map(|(_, value, _)| *value)
        .collect();
    aggregate_result(
        population_variance(&values).map(f64::sqrt),
        aggregate_quality(input),
        input.interval_start,
    )
}

fn agg_variance_population(input: &AggregateInput<'_>) -> DataValue {
    let values: Vec<f64> = good_numeric_points(input)
        .iter()
        .map(|(_, value, _)| *value)
        .collect();
    aggregate_result(
        population_variance(&values),
        aggregate_quality(input),
        input.interval_start,
    )
}

fn quality_rank(status: StatusCode) -> u8 {
    if status.is_bad() {
        2
    } else if status.is_uncertain() {
        1
    } else {
        0
    }
}

fn agg_count(input: &AggregateInput<'_>) -> DataValue {
    let good_count = good_numeric_points(input).len() as i32;
    // ponytail: Count's before-start/after-end BadNoData nuance needs historian range metadata.
    DataValue {
        value: Some(Variant::Int32(good_count)),
        status: Some(StatusCode::Good),
        source_timestamp: Some(input.interval_start),
        server_timestamp: Some(DateTime::now()),
        ..Default::default()
    }
}

fn agg_worst_quality(input: &AggregateInput<'_>) -> DataValue {
    let Some(worst) = input
        .values
        .iter()
        .map(|value| value.status.unwrap_or(StatusCode::Good))
        .max_by_key(|status| quality_rank(*status))
    else {
        return bad_no_data(input.interval_start);
    };

    DataValue {
        value: Some(Variant::StatusCode(worst)),
        status: Some(StatusCode::Good),
        source_timestamp: Some(input.interval_start),
        server_timestamp: Some(DateTime::now()),
        ..Default::default()
    }
}

/// Dispatches an aggregate calculation to the implementation for the requested aggregate NodeId.
pub fn dispatch_aggregate(aggregate_type: &NodeId, input: &AggregateInput<'_>) -> DataValue {
    match aggregate_type.identifier {
        opcua_types::Identifier::Numeric(AGG_AVERAGE) => agg_average(input),
        opcua_types::Identifier::Numeric(AGG_TIME_AVERAGE) => agg_time_average(input),
        opcua_types::Identifier::Numeric(AGG_MINIMUM) => agg_minimum(input),
        opcua_types::Identifier::Numeric(AGG_MAXIMUM) => agg_maximum(input),
        opcua_types::Identifier::Numeric(AGG_MINIMUM_ACTUAL_TIME) => agg_minimum_actual_time(input),
        opcua_types::Identifier::Numeric(AGG_MAXIMUM_ACTUAL_TIME) => agg_maximum_actual_time(input),
        opcua_types::Identifier::Numeric(AGG_RANGE) => agg_range(input),
        // AnnotationCount (2351) is intentionally unsupported until annotations are modeled.
        opcua_types::Identifier::Numeric(AGG_COUNT) => agg_count(input),
        opcua_types::Identifier::Numeric(AGG_DELTA) => agg_delta(input),
        opcua_types::Identifier::Numeric(AGG_WORST_QUALITY) => agg_worst_quality(input),
        opcua_types::Identifier::Numeric(AGG_STANDARD_DEVIATION_SAMPLE) => {
            agg_std_dev_sample(input)
        }
        opcua_types::Identifier::Numeric(AGG_STANDARD_DEVIATION_POPULATION) => {
            agg_std_dev_population(input)
        }
        opcua_types::Identifier::Numeric(AGG_VARIANCE_SAMPLE) => agg_variance_sample(input),
        opcua_types::Identifier::Numeric(AGG_VARIANCE_POPULATION) => agg_variance_population(input),
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
