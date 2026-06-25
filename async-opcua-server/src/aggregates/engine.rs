//! Aggregate processing engine (Part 13).
//! Computes time-weighted average, minimum, maximum, and standard deviation over intervals.

use crate::aggregates::quality::compute_aggregate_quality;
use chrono::Duration as ChronoDuration;
use opcua_types::{AggregateConfiguration, DataValue, DateTime, NodeId, StatusCode, Variant};

// Standard AggregateFunction NodeIds (Part 13 / Part 6 NodeIds.csv). The implemented average is
// interpolated/time-weighted, so it maps to TimeAverage (2343), NOT simple Average (2342).
const AGG_TIME_AVERAGE: u32 = 2343;
const AGG_TOTAL: u32 = 2344;
const AGG_INTERPOLATIVE: u32 = 2341;
const AGG_AVERAGE: u32 = 2342;
const AGG_MINIMUM: u32 = 2346;
const AGG_MAXIMUM: u32 = 2347;
const AGG_MINIMUM_ACTUAL_TIME: u32 = 2348;
const AGG_MAXIMUM_ACTUAL_TIME: u32 = 2349;
const AGG_RANGE: u32 = 2350;
const AGG_COUNT: u32 = 2352;
const AGG_DELTA: u32 = 2359;
const AGG_WORST_QUALITY: u32 = 2364;
const AGG_TIME_AVERAGE2: u32 = 11285;
const AGG_MINIMUM2: u32 = 11286;
const AGG_MAXIMUM2: u32 = 11287;
const AGG_RANGE2: u32 = 11288;
const AGG_WORST_QUALITY2: u32 = 11292;
const AGG_TOTAL2: u32 = 11304;
const AGG_MINIMUM_ACTUAL_TIME2: u32 = 11305;
const AGG_MAXIMUM_ACTUAL_TIME2: u32 = 11306;
const AGG_START_BOUND: u32 = 11505;
const AGG_END_BOUND: u32 = 11506;
const AGG_DELTA_BOUNDS: u32 = 11507;
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
    /// Last raw value at/before the interval's earlier boundary.
    pub prior: Option<&'a DataValue>,
    /// First raw value after the interval's later boundary.
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

fn simple_bounded_points(input: &AggregateInput<'_>) -> Vec<(DateTime, f64)> {
    let good_points = good_numeric_points(input);
    let mut points = Vec::with_capacity(good_points.len() + usize::from(input.prior.is_some()));

    if let Some(value) = simple_bound_at(input.prior) {
        points.push((input.interval_start, value));
    }

    points.extend(
        good_points
            .into_iter()
            .map(|(timestamp, value, _)| (timestamp, value)),
    );
    points
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

/// Area under the stepped curve over [interval_start, interval_end] and the covered duration (seconds).
/// Returns None if there is no usable value. Stepped: each knot's value is held until the next knot.
fn stepped_area_seconds(input: &AggregateInput<'_>) -> Option<(f64 /*area*/, f64 /*seconds*/)> {
    if input.interval_end <= input.interval_start {
        // ponytail: Backward aggregate intervals need explicit Part 13 handling; do not guess here.
        return None;
    }

    let good_points = good_numeric_points(input);
    let start_value = input
        .prior
        .and_then(|value| value.value.as_ref())
        .and_then(variant_to_f64)
        .or_else(|| good_points.first().map(|(_, value, _)| *value))?;

    let mut knots = Vec::with_capacity(good_points.len() + 2);
    knots.push((input.interval_start, start_value));
    knots.extend(
        good_points
            .iter()
            .filter(|(timestamp, _, _)| {
                *timestamp > input.interval_start && *timestamp < input.interval_end
            })
            .map(|(timestamp, value, _)| (*timestamp, *value)),
    );
    let last_value = knots.last().map(|(_, value)| *value)?;
    knots.push((input.interval_end, last_value));

    let area = knots
        .windows(2)
        .map(|window| {
            let (left_time, left_value) = window[0];
            let (right_time, _) = window[1];
            left_value * (right_time.ticks() - left_time.ticks()) as f64 / 10_000_000.0
        })
        .sum::<f64>();
    let seconds = (input.interval_end.ticks() - input.interval_start.ticks()) as f64 / 10_000_000.0;

    // ponytail: Bad-region reduction per OPC UA Part 13 §5.4.3.6/§5.4.3.7 is deferred to the
    // status-aware phase; stepped coverage currently spans the full interval.
    Some((area, seconds))
}

fn agg_average(input: &AggregateInput<'_>) -> DataValue {
    let points = good_numeric_points(input);
    if points.is_empty() {
        return bad_no_data(input.interval_start);
    }

    let mean = points.iter().map(|(_, value, _)| value).sum::<f64>() / points.len() as f64;
    aggregate_result(Some(mean), aggregate_quality(input), input.interval_start)
}

fn time_average_value(input: &AggregateInput<'_>) -> DataValue {
    let Some((area, seconds)) = stepped_area_seconds(input) else {
        return bad_no_data(input.interval_start);
    };

    if seconds <= 0.0 {
        return bad_no_data(input.interval_start);
    }

    aggregate_result(
        Some(area / seconds),
        aggregate_quality(input),
        input.interval_start,
    )
}

fn agg_time_average(input: &AggregateInput<'_>) -> DataValue {
    time_average_value(input)
}

fn agg_time_average2(input: &AggregateInput<'_>) -> DataValue {
    time_average_value(input)
}

fn total_value(input: &AggregateInput<'_>) -> DataValue {
    let Some((area, _)) = stepped_area_seconds(input) else {
        return bad_no_data(input.interval_start);
    };

    // OPC UA Part 13 §5.4.3.8 defines Total as TimeAverage * ProcessingInterval(seconds), so the
    // returned area is normalized to [source units] * seconds.
    aggregate_result(Some(area), aggregate_quality(input), input.interval_start)
}

fn agg_total(input: &AggregateInput<'_>) -> DataValue {
    total_value(input)
}

fn agg_total2(input: &AggregateInput<'_>) -> DataValue {
    total_value(input)
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

fn agg_range2(input: &AggregateInput<'_>) -> DataValue {
    let points = simple_bounded_points(input);
    if points.is_empty() {
        return bad_no_data(input.interval_start);
    }

    let (min, max) = points
        .iter()
        .map(|(_, value)| *value)
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

fn agg_minimum2(input: &AggregateInput<'_>) -> DataValue {
    let points = simple_bounded_points(input);
    if points.is_empty() {
        return bad_no_data(input.interval_start);
    }

    aggregate_result(
        points
            .iter()
            .map(|(_, value)| *value)
            .min_by(|a, b| a.total_cmp(b)),
        aggregate_quality(input),
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

fn agg_minimum_actual_time2(input: &AggregateInput<'_>) -> DataValue {
    let points = simple_bounded_points(input);
    let Some((timestamp, value)) =
        points
            .iter()
            .min_by(|(left_time, left_value), (right_time, right_value)| {
                left_value
                    .total_cmp(right_value)
                    .then_with(|| left_time.cmp(right_time))
            })
    else {
        return bad_no_data(input.interval_start);
    };

    // ponytail: synthetic-bound source-Variant retention deferred; return Double for all candidates.
    DataValue {
        value: Some(Variant::Double(*value)),
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

fn agg_maximum2(input: &AggregateInput<'_>) -> DataValue {
    let points = simple_bounded_points(input);
    if points.is_empty() {
        return bad_no_data(input.interval_start);
    }

    aggregate_result(
        points
            .iter()
            .map(|(_, value)| *value)
            .max_by(|a, b| a.total_cmp(b)),
        aggregate_quality(input),
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

fn agg_maximum_actual_time2(input: &AggregateInput<'_>) -> DataValue {
    let points = simple_bounded_points(input);
    let Some((timestamp, value)) =
        points
            .iter()
            .min_by(|(left_time, left_value), (right_time, right_value)| {
                right_value
                    .total_cmp(left_value)
                    .then_with(|| left_time.cmp(right_time))
            })
    else {
        return bad_no_data(input.interval_start);
    };

    // ponytail: synthetic-bound source-Variant retention deferred; return Double for all candidates.
    DataValue {
        value: Some(Variant::Double(*value)),
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

fn agg_worst_quality2(input: &AggregateInput<'_>) -> DataValue {
    let prior_status = input
        .prior
        .map(|value| value.status.unwrap_or(StatusCode::Good));
    let Some(worst) = input
        .values
        .iter()
        .map(|value| value.status.unwrap_or(StatusCode::Good))
        .chain(prior_status)
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

fn agg_start_bound(input: &AggregateInput<'_>) -> DataValue {
    aggregate_result(
        simple_bound_at(input.prior),
        aggregate_quality(input),
        input.interval_start,
    )
}

fn end_bound_value(input: &AggregateInput<'_>) -> Option<f64> {
    good_numeric_points(input)
        .last()
        .map(|(_, value, _)| *value)
        .or_else(|| simple_bound_at(input.prior))
}

fn good_simple_bound_at(before: Option<&DataValue>) -> Option<f64> {
    before.and_then(|value| {
        if value.status.is_none_or(|status| status.is_good()) {
            simple_bound_at(Some(value))
        } else {
            None
        }
    })
}

fn good_end_bound_value(input: &AggregateInput<'_>) -> Option<f64> {
    good_numeric_points(input)
        .last()
        .map(|(_, value, _)| *value)
        .or_else(|| good_simple_bound_at(input.prior))
}

fn agg_end_bound(input: &AggregateInput<'_>) -> DataValue {
    aggregate_result(
        end_bound_value(input),
        aggregate_quality(input),
        input.interval_start,
    )
}

fn agg_delta_bounds(input: &AggregateInput<'_>) -> DataValue {
    let Some(start) = good_simple_bound_at(input.prior) else {
        return bad_no_data(input.interval_start);
    };
    let Some(end) = good_end_bound_value(input) else {
        return bad_no_data(input.interval_start);
    };

    aggregate_result(
        Some(end - start),
        aggregate_quality(input),
        input.interval_start,
    )
}

fn agg_interpolative(input: &AggregateInput<'_>) -> DataValue {
    let after = input
        .values
        .iter()
        .find(|value| value.value.as_ref().and_then(variant_to_f64).is_some())
        .copied()
        .or(input.next);

    let value = interpolated_bound_at(
        input.interval_start,
        input.prior,
        after,
        input.config.use_sloped_extrapolation,
    )
    .map(|(value, _)| value);

    aggregate_result(value, aggregate_quality(input), input.interval_start)
}

/// Linear interpolation of the value at `boundary` between the raw point before it and the one after.
/// Returns `(value, is_interpolated)`. With only `before`, returns a stepped hold; sloped
/// extrapolation using two prior values is refined later.
fn interpolated_bound_at(
    boundary: DateTime,
    before: Option<&DataValue>,
    after: Option<&DataValue>,
    use_sloped: bool,
) -> Option<(f64, bool)> {
    let _ = use_sloped;

    let before = before.and_then(|value| {
        value
            .value
            .as_ref()
            .and_then(variant_to_f64)
            .map(|numeric| (get_value_timestamp(value), numeric))
    });
    let after = after.and_then(|value| {
        value
            .value
            .as_ref()
            .and_then(variant_to_f64)
            .map(|numeric| (get_value_timestamp(value), numeric))
    });

    match (before, after) {
        (Some((before_time, before_value)), Some((after_time, after_value))) => {
            let before_ticks = before_time.ticks();
            let after_ticks = after_time.ticks();
            if before_ticks == after_ticks {
                return Some((before_value, false));
            }

            let ratio =
                (boundary.ticks() - before_ticks) as f64 / (after_ticks - before_ticks) as f64;
            Some((before_value + (after_value - before_value) * ratio, true))
        }
        (Some((_, before_value)), None) => {
            // ponytail: C1 keeps this as stepped hold; sloped extrapolation with two priors is later.
            Some((before_value, false))
        }
        (None, Some((_, after_value))) => Some((after_value, false)),
        (None, None) => None,
    }
}

/// The simple bounding value at `boundary`: the `before` raw value held constant.
fn simple_bound_at(before: Option<&DataValue>) -> Option<f64> {
    before
        .and_then(|value| value.value.as_ref())
        .and_then(variant_to_f64)
}

/// Dispatches an aggregate calculation to the implementation for the requested aggregate NodeId.
pub fn dispatch_aggregate(aggregate_type: &NodeId, input: &AggregateInput<'_>) -> DataValue {
    match aggregate_type.identifier {
        opcua_types::Identifier::Numeric(AGG_INTERPOLATIVE) => agg_interpolative(input),
        opcua_types::Identifier::Numeric(AGG_AVERAGE) => agg_average(input),
        opcua_types::Identifier::Numeric(AGG_TIME_AVERAGE) => agg_time_average(input),
        opcua_types::Identifier::Numeric(AGG_TOTAL) => agg_total(input),
        opcua_types::Identifier::Numeric(AGG_MINIMUM) => agg_minimum(input),
        opcua_types::Identifier::Numeric(AGG_MAXIMUM) => agg_maximum(input),
        opcua_types::Identifier::Numeric(AGG_MINIMUM_ACTUAL_TIME) => agg_minimum_actual_time(input),
        opcua_types::Identifier::Numeric(AGG_MAXIMUM_ACTUAL_TIME) => agg_maximum_actual_time(input),
        opcua_types::Identifier::Numeric(AGG_RANGE) => agg_range(input),
        opcua_types::Identifier::Numeric(AGG_TIME_AVERAGE2) => agg_time_average2(input),
        opcua_types::Identifier::Numeric(AGG_MINIMUM2) => agg_minimum2(input),
        opcua_types::Identifier::Numeric(AGG_MAXIMUM2) => agg_maximum2(input),
        opcua_types::Identifier::Numeric(AGG_RANGE2) => agg_range2(input),
        opcua_types::Identifier::Numeric(AGG_WORST_QUALITY2) => agg_worst_quality2(input),
        opcua_types::Identifier::Numeric(AGG_TOTAL2) => agg_total2(input),
        opcua_types::Identifier::Numeric(AGG_MINIMUM_ACTUAL_TIME2) => {
            agg_minimum_actual_time2(input)
        }
        opcua_types::Identifier::Numeric(AGG_MAXIMUM_ACTUAL_TIME2) => {
            agg_maximum_actual_time2(input)
        }
        // AnnotationCount (2351) is intentionally unsupported until annotations are modeled.
        opcua_types::Identifier::Numeric(AGG_COUNT) => agg_count(input),
        opcua_types::Identifier::Numeric(AGG_DELTA) => agg_delta(input),
        opcua_types::Identifier::Numeric(AGG_WORST_QUALITY) => agg_worst_quality(input),
        opcua_types::Identifier::Numeric(AGG_START_BOUND) => agg_start_bound(input),
        opcua_types::Identifier::Numeric(AGG_END_BOUND) => agg_end_bound(input),
        opcua_types::Identifier::Numeric(AGG_DELTA_BOUNDS) => agg_delta_bounds(input),
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

            let prior = raw_values
                .iter()
                .rev()
                .find(|value| get_value_timestamp(value) <= min_t);
            let next = raw_values
                .iter()
                .find(|value| get_value_timestamp(value) > max_t);

            let input = AggregateInput {
                values: &values_in_interval,
                prior,
                next,
                interval_start,
                interval_end,
                config,
            };

            dispatch_aggregate(aggregate_type, &input)
        })
        .collect()
}
