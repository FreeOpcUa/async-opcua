//! Integration and unit tests for OPC-UA mathematical aggregates (time-weighted average, min, max, std dev) and quality calculations.

use opcua_server::aggregates::engine::{
    aggregate_average, aggregate_maximum, aggregate_minimum, aggregate_std_dev,
    calculate_std_dev_sample, calculate_time_weighted_average, compute_processed_intervals,
    dispatch_aggregate, partition_intervals, AggregateInput,
};
use opcua_server::aggregates::quality::compute_aggregate_quality;
use opcua_types::{AggregateConfiguration, DataValue, DateTime, NodeId, StatusCode, Variant};

/// Phase-A shim: the old `calculate_aggregate(values, type, start, end)` is now
/// `dispatch_aggregate` over an `AggregateInput`. These lock-in tests keep their exact
/// expected values to prove the refactor introduced no behavior change.
fn calculate_aggregate(
    values: &[&DataValue],
    aggregate_type: &NodeId,
    start: DateTime,
    end: DateTime,
) -> DataValue {
    let config = AggregateConfiguration::default();
    dispatch_aggregate(
        aggregate_type,
        &AggregateInput {
            values,
            prior: None,
            next: None,
            interval_start: start,
            interval_end: end,
            config: &config,
        },
    )
}

#[test]
fn aggregate_node_ids_match_the_standard_registry() {
    // Conformance: the aggregate NodeIds must be the canonical Part 6 AggregateFunction ids, not
    // arbitrary numbers. The implemented average is time-weighted, so it is TimeAverage (2343), not
    // simple Average (2342). Minimum=2346, Maximum=2347, StandardDeviationSample=11426.
    assert_eq!(aggregate_average(), NodeId::new(0u16, 2343u32));
    assert_eq!(aggregate_minimum(), NodeId::new(0u16, 2346u32));
    assert_eq!(aggregate_maximum(), NodeId::new(0u16, 2347u32));
    assert_eq!(aggregate_std_dev(), NodeId::new(0u16, 11426u32));

    // A request for a supported standard id is computed; an unimplemented id (2351 =
    // AggregateFunction_AnnotationCount, needs annotation history) reports BadAggregateNotSupported.
    let start = DateTime::from((2026, 6, 6, 12, 0, 0));
    let end = DateTime::from((2026, 6, 6, 12, 0, 10));
    let v = DataValue {
        value: Some(Variant::Double(10.0)),
        source_timestamp: Some(start),
        status: Some(StatusCode::Good),
        ..Default::default()
    };
    assert_eq!(
        calculate_aggregate(&[&v], &aggregate_minimum(), start, end).status,
        Some(StatusCode::Good)
    );
    // Count (2352) is now supported (Phase B).
    assert_eq!(
        calculate_aggregate(&[&v], &NodeId::new(0u16, 2352u32), start, end).status,
        Some(StatusCode::Good)
    );
    // AnnotationCount (2351) is intentionally not implemented.
    assert_eq!(
        calculate_aggregate(&[&v], &NodeId::new(0u16, 2351u32), start, end).status,
        Some(StatusCode::BadAggregateNotSupported)
    );
}

#[test]
fn test_partition_intervals_forward() {
    let start = DateTime::from((2026, 6, 6, 12, 0, 0));
    let end = DateTime::from((2026, 6, 6, 12, 0, 3));
    let processing_interval = 1000.0; // 1 second

    let intervals = partition_intervals(start, end, processing_interval);
    assert_eq!(intervals.len(), 3);

    // Interval 1: 12:00:00 to 12:00:01
    assert_eq!(intervals[0].0, start);
    assert_eq!(intervals[0].1, DateTime::from((2026, 6, 6, 12, 0, 1)));

    // Interval 3: 12:00:02 to 12:00:03
    assert_eq!(intervals[2].0, DateTime::from((2026, 6, 6, 12, 0, 2)));
    assert_eq!(intervals[2].1, end);
}

#[test]
fn test_partition_intervals_backward() {
    let start = DateTime::from((2026, 6, 6, 12, 0, 3));
    let end = DateTime::from((2026, 6, 6, 12, 0, 0));
    let processing_interval = 1000.0; // 1 second

    let intervals = partition_intervals(start, end, processing_interval);
    assert_eq!(intervals.len(), 3);

    // Interval 1: 12:00:03 to 12:00:02
    assert_eq!(intervals[0].0, start);
    assert_eq!(intervals[0].1, DateTime::from((2026, 6, 6, 12, 0, 2)));

    // Interval 3: 12:00:01 to 12:00:00
    assert_eq!(intervals[2].0, DateTime::from((2026, 6, 6, 12, 0, 1)));
    assert_eq!(intervals[2].1, end);
}

#[test]
fn test_partition_intervals_backward_no_loop() {
    let start = DateTime::from((2026, 6, 6, 12, 0, 0));
    let end = DateTime::from((2026, 6, 6, 12, 0, 0));
    let intervals = partition_intervals(start, end, 1000.0);
    assert_eq!(intervals.len(), 0);
}

#[test]
fn test_calculate_time_weighted_average() {
    let start = DateTime::from((2026, 6, 6, 12, 0, 0));
    let end = DateTime::from((2026, 6, 6, 12, 0, 10));

    // Points:
    // (12:00:00, 10.0) -> active for 2s (until 12:00:02)
    // (12:00:02, 20.0) -> active for 5s (until 12:00:07)
    // (12:00:07, 30.0) -> active for 3s (until 12:00:10)
    let points = vec![
        (DateTime::from((2026, 6, 6, 12, 0, 0)), 10.0),
        (DateTime::from((2026, 6, 6, 12, 0, 2)), 20.0),
        (DateTime::from((2026, 6, 6, 12, 0, 7)), 30.0),
    ];

    let avg = calculate_time_weighted_average(&points, start, end).unwrap();
    // expected: (10.0 * 2000.0 + 20.0 * 5000.0 + 30.0 * 3000.0) / 10000.0 = (20000 + 100000 + 90000) / 10000 = 210000 / 10000 = 21.0
    assert_eq!(avg, 21.0);
}

#[test]
fn test_calculate_std_dev_sample() {
    let values = vec![2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0];
    let std_dev = calculate_std_dev_sample(&values).unwrap();
    // Mean = 5.0. Sum of squared diffs: (2-5)^2 + (4-5)^2*3 + (5-5)^2*2 + (7-5)^2 + (9-5)^2 = 9 + 3 + 0 + 4 + 16 = 32.
    // Variance = 32 / (8 - 1) = 32 / 7 = 4.5714
    // Std Dev = sqrt(32/7) = 2.138
    assert!((std_dev - 2.138089).abs() < 1e-5);

    // Std dev of < 2 points should be None
    assert!(calculate_std_dev_sample(&[5.0]).is_none());
}

#[test]
fn test_compute_aggregate_quality() {
    // 1. All Good
    let q =
        compute_aggregate_quality(&[Some(StatusCode::Good), None, Some(StatusCode::GoodClamped)]);
    assert_eq!(q, StatusCode::Good);

    // 2. All Bad
    let q = compute_aggregate_quality(&[Some(StatusCode::BadNoData), Some(StatusCode::BadTimeout)]);
    assert_eq!(q, StatusCode::BadNoData);

    // 3. Mixed
    let q =
        compute_aggregate_quality(&[Some(StatusCode::Good), Some(StatusCode::BadDataUnavailable)]);
    assert_eq!(q, StatusCode::UncertainDataSubNormal);
}

#[test]
fn test_calculate_aggregate_average() {
    let start = DateTime::from((2026, 6, 6, 12, 0, 0));
    let end = DateTime::from((2026, 6, 6, 12, 0, 10));

    let val1 = DataValue {
        value: Some(Variant::Double(10.0)),
        source_timestamp: Some(DateTime::from((2026, 6, 6, 12, 0, 0))),
        status: Some(StatusCode::Good),
        ..Default::default()
    };
    let val2 = DataValue {
        value: Some(Variant::Double(20.0)),
        source_timestamp: Some(DateTime::from((2026, 6, 6, 12, 0, 5))),
        status: Some(StatusCode::Good),
        ..Default::default()
    };

    let result = calculate_aggregate(&[&val1, &val2], &aggregate_average(), start, end);

    assert_eq!(result.status, Some(StatusCode::Good));
    // Time-weighted: 10.0 for 5s, 20.0 for 5s -> avg = 15.0
    assert_eq!(result.value, Some(Variant::Double(15.0)));
}

#[test]
fn test_calculate_aggregate_min_max() {
    let start = DateTime::from((2026, 6, 6, 12, 0, 0));
    let end = DateTime::from((2026, 6, 6, 12, 0, 10));

    let val1 = DataValue {
        value: Some(Variant::Double(50.0)),
        source_timestamp: Some(DateTime::from((2026, 6, 6, 12, 0, 1))),
        ..Default::default()
    };
    let val2 = DataValue {
        value: Some(Variant::Double(10.0)),
        source_timestamp: Some(DateTime::from((2026, 6, 6, 12, 0, 3))),
        ..Default::default()
    };
    let val3 = DataValue {
        value: Some(Variant::Double(35.0)),
        source_timestamp: Some(DateTime::from((2026, 6, 6, 12, 0, 6))),
        ..Default::default()
    };

    let min_res = calculate_aggregate(&[&val1, &val2, &val3], &aggregate_minimum(), start, end);
    assert_eq!(min_res.value, Some(Variant::Double(10.0)));

    let max_res = calculate_aggregate(&[&val1, &val2, &val3], &aggregate_maximum(), start, end);
    assert_eq!(max_res.value, Some(Variant::Double(50.0)));
}

// ---------------------------------------------------------------------------
// Phase B: simple in-interval aggregates. Expected values hand-computed and
// cross-checked against OPC 10000-13 §5.4.3 (verified via the opc-ua-reference
// MCP). Canonical interval [12:00:00, 12:00:10) with Good values
// 10@0s, 20@2s, 30@5s, 5@7s unless noted.
// ---------------------------------------------------------------------------

fn good(value: f64, sec: u16) -> DataValue {
    DataValue {
        value: Some(Variant::Double(value)),
        source_timestamp: Some(DateTime::from((2026, 6, 6, 12, 0, sec))),
        status: Some(StatusCode::Good),
        ..Default::default()
    }
}

fn phase_b_interval() -> (DateTime, DateTime) {
    (
        DateTime::from((2026, 6, 6, 12, 0, 0)),
        DateTime::from((2026, 6, 6, 12, 0, 10)),
    )
}

const ID_AVERAGE: u32 = 2342;
const ID_MIN_ACTUAL_TIME: u32 = 2348;
const ID_MAX_ACTUAL_TIME: u32 = 2349;
const ID_RANGE: u32 = 2350;
const ID_COUNT: u32 = 2352;
const ID_WORST_QUALITY: u32 = 2364;
const ID_DELTA: u32 = 2359;
const ID_STDDEV_POP: u32 = 11427;
const ID_VARIANCE_SAMPLE: u32 = 11428;
const ID_VARIANCE_POP: u32 = 11429;

#[test]
fn phase_b_count_average_range_delta() {
    let (start, end) = phase_b_interval();
    let (v0, v2, v5, v7) = (good(10.0, 0), good(20.0, 2), good(30.0, 5), good(5.0, 7));
    let vals = [&v0, &v2, &v5, &v7];

    // Count = number of Good raw values, as Int32, timestamp = interval start.
    let count = calculate_aggregate(&vals, &NodeId::new(0u16, ID_COUNT), start, end);
    assert_eq!(count.value, Some(Variant::Int32(4)));
    assert_eq!(count.status, Some(StatusCode::Good));
    assert_eq!(count.source_timestamp, Some(start));

    // Average = arithmetic mean = 65/4 = 16.25.
    let avg = calculate_aggregate(&vals, &NodeId::new(0u16, ID_AVERAGE), start, end);
    assert_eq!(avg.value, Some(Variant::Double(16.25)));

    // Range = max - min = 30 - 5 = 25.
    let range = calculate_aggregate(&vals, &NodeId::new(0u16, ID_RANGE), start, end);
    assert_eq!(range.value, Some(Variant::Double(25.0)));

    // Delta = last - first = 5 - 10 = -5 (signed).
    let delta = calculate_aggregate(&vals, &NodeId::new(0u16, ID_DELTA), start, end);
    assert_eq!(delta.value, Some(Variant::Double(-5.0)));
}

#[test]
fn phase_b_actual_time_returns_value_timestamp_not_interval_start() {
    let (start, end) = phase_b_interval();
    let (v0, v2, v5, v7) = (good(10.0, 0), good(20.0, 2), good(30.0, 5), good(5.0, 7));
    let vals = [&v0, &v2, &v5, &v7];

    // MinimumActualTime: value 5.0 occurring at 12:00:07 — timestamp must be the value's, not start.
    let min = calculate_aggregate(&vals, &NodeId::new(0u16, ID_MIN_ACTUAL_TIME), start, end);
    assert_eq!(min.value, Some(Variant::Double(5.0)));
    assert_eq!(
        min.source_timestamp,
        Some(DateTime::from((2026, 6, 6, 12, 0, 7)))
    );
    assert_ne!(min.source_timestamp, Some(start));

    // MaximumActualTime: value 30.0 occurring at 12:00:05.
    let max = calculate_aggregate(&vals, &NodeId::new(0u16, ID_MAX_ACTUAL_TIME), start, end);
    assert_eq!(max.value, Some(Variant::Double(30.0)));
    assert_eq!(
        max.source_timestamp,
        Some(DateTime::from((2026, 6, 6, 12, 0, 5)))
    );
}

#[test]
fn phase_b_variance_and_stddev() {
    let (start, end) = phase_b_interval();
    let (v0, v2, v5, v7) = (good(10.0, 0), good(20.0, 2), good(30.0, 5), good(5.0, 7));
    let vals = [&v0, &v2, &v5, &v7];
    // mean = 16.25; sum of squared deviations = 368.75.
    // sample variance = 368.75 / 3 = 122.91666...; population variance = 368.75 / 4 = 92.1875.
    let var_s = calculate_aggregate(&vals, &NodeId::new(0u16, ID_VARIANCE_SAMPLE), start, end);
    match var_s.value {
        Some(Variant::Double(v)) => assert!((v - 122.916_666_666).abs() < 1e-6, "got {v}"),
        other => panic!("expected Double, got {other:?}"),
    }
    let var_p = calculate_aggregate(&vals, &NodeId::new(0u16, ID_VARIANCE_POP), start, end);
    assert_eq!(var_p.value, Some(Variant::Double(92.1875)));

    let sd_p = calculate_aggregate(&vals, &NodeId::new(0u16, ID_STDDEV_POP), start, end);
    match sd_p.value {
        Some(Variant::Double(v)) => assert!((v - 92.1875_f64.sqrt()).abs() < 1e-9, "got {v}"),
        other => panic!("expected Double, got {other:?}"),
    }

    // Sample variance needs >= 2 points.
    let single = good(10.0, 0);
    let var_s1 = calculate_aggregate(
        &[&single],
        &NodeId::new(0u16, ID_VARIANCE_SAMPLE),
        start,
        end,
    );
    assert_eq!(var_s1.status, Some(StatusCode::BadNoData));
}

#[test]
fn phase_b_non_good_values_excluded_and_downgrade_status() {
    let (start, end) = phase_b_interval();
    let g = good(10.0, 0);
    let bad = DataValue {
        value: Some(Variant::Double(20.0)),
        source_timestamp: Some(DateTime::from((2026, 6, 6, 12, 0, 5))),
        status: Some(StatusCode::BadDataUnavailable),
        ..Default::default()
    };
    let vals = [&g, &bad];

    // Average ignores the non-Good value (only 10.0 counts) but the result status is downgraded.
    let avg = calculate_aggregate(&vals, &NodeId::new(0u16, ID_AVERAGE), start, end);
    assert_eq!(avg.value, Some(Variant::Double(10.0)));
    assert_eq!(avg.status, Some(StatusCode::UncertainDataSubNormal));

    // Count excludes the non-Good value.
    let count = calculate_aggregate(&vals, &NodeId::new(0u16, ID_COUNT), start, end);
    assert_eq!(count.value, Some(Variant::Int32(1)));

    // WorstQuality returns the worst StatusCode as the value, with the interval-start timestamp.
    let wq = calculate_aggregate(&vals, &NodeId::new(0u16, ID_WORST_QUALITY), start, end);
    assert_eq!(
        wq.value,
        Some(Variant::StatusCode(StatusCode::BadDataUnavailable))
    );
    assert_eq!(wq.status, Some(StatusCode::Good));
    assert_eq!(wq.source_timestamp, Some(start));
}

#[test]
fn phase_b_empty_interval() {
    let (start, end) = phase_b_interval();
    let empty: [&DataValue; 0] = [];

    // Count of an empty interval is 0, Good (§5.4.3.21), not BadNoData.
    let count = calculate_aggregate(&empty, &NodeId::new(0u16, ID_COUNT), start, end);
    assert_eq!(count.value, Some(Variant::Int32(0)));
    assert_eq!(count.status, Some(StatusCode::Good));

    // Value-bearing aggregates report BadNoData on an empty interval.
    for id in [
        ID_AVERAGE,
        ID_RANGE,
        ID_DELTA,
        ID_MIN_ACTUAL_TIME,
        ID_MAX_ACTUAL_TIME,
    ] {
        let r = calculate_aggregate(&empty, &NodeId::new(0u16, id), start, end);
        assert_eq!(r.status, Some(StatusCode::BadNoData), "id {id}");
    }
}

// ---------------------------------------------------------------------------
// Phase C: bounded aggregates. Driven through compute_processed_intervals so the
// real prior/next bound wiring is exercised. Raw series has a point BEFORE the
// interval (the prior bound). Interval [12:00:02, 12:00:12) (one interval).
// Raw: 10@0s (prior), 20@5s, 30@10s. Expected values hand-computed, cross-checked
// against OPC 10000-13 §5.4.3.4/6/8/28-30 (verified via the opc-ua-reference MCP).
// ---------------------------------------------------------------------------

fn phase_c_series() -> Vec<DataValue> {
    vec![good(10.0, 0), good(20.0, 5), good(30.0, 10)]
}

fn phase_c_one_interval(id: u32) -> DataValue {
    let series = phase_c_series();
    let start = DateTime::from((2026, 6, 6, 12, 0, 2));
    let end = DateTime::from((2026, 6, 6, 12, 0, 12));
    let cfg = AggregateConfiguration::default();
    let mut out =
        compute_processed_intervals(&series, &NodeId::new(0u16, id), &cfg, start, end, 10_000.0);
    assert_eq!(out.len(), 1, "expected exactly one interval for id {id}");
    out.remove(0)
}

#[test]
fn phase_c_start_end_delta_bounds() {
    // StartBound (simple) at 12:00:02 = prior value held = 10.
    assert_eq!(
        phase_c_one_interval(11505).value,
        Some(Variant::Double(10.0))
    );
    // EndBound (simple) at 12:00:12 = last in-interval value held = 30.
    assert_eq!(
        phase_c_one_interval(11506).value,
        Some(Variant::Double(30.0))
    );
    // DeltaBounds = EndBound - StartBound = 30 - 10 = 20.
    assert_eq!(
        phase_c_one_interval(11507).value,
        Some(Variant::Double(20.0))
    );
}

#[test]
fn phase_c_interpolative_at_interval_start() {
    // Interpolative at start=2s, linear between prior 10@0s and first in-interval 20@5s:
    // ratio = (2-0)/(5-0) = 0.4 -> 10 + (20-10)*0.4 = 14.0.
    let r = phase_c_one_interval(2341);
    match r.value {
        Some(Variant::Double(v)) => assert!((v - 14.0).abs() < 1e-9, "got {v}"),
        other => panic!("expected Double, got {other:?}"),
    }
}

#[test]
fn phase_c_time_average_uses_leading_bound_region() {
    // Corrected TimeAverage (stepped, with the prior bound covering the leading region [2s,5s]):
    // area = 10*(5-2) + 20*(10-5) + 30*(12-10) = 30 + 100 + 60 = 190; /10s = 19.0.
    // (The old, non-conformant impl ignored the prior and the [2s,5s] region.)
    let avg = phase_c_one_interval(2343);
    match avg.value {
        Some(Variant::Double(v)) => assert!((v - 19.0).abs() < 1e-9, "got {v}"),
        other => panic!("expected Double, got {other:?}"),
    }
    // Total = the same area = 190 (value-seconds).
    let total = phase_c_one_interval(2344);
    match total.value {
        Some(Variant::Double(v)) => assert!((v - 190.0).abs() < 1e-9, "got {v}"),
        other => panic!("expected Double, got {other:?}"),
    }
}

#[test]
fn phase_c_interpolative_before_data_is_bad_no_data() {
    // No prior and no data at all -> Bad_NoData (§5.4.3.4 before start of data).
    let empty: Vec<DataValue> = vec![];
    let start = DateTime::from((2026, 6, 6, 12, 0, 2));
    let end = DateTime::from((2026, 6, 6, 12, 0, 12));
    let cfg = AggregateConfiguration::default();
    let out =
        compute_processed_intervals(&empty, &NodeId::new(0u16, 2341), &cfg, start, end, 10_000.0);
    assert_eq!(out[0].status, Some(StatusCode::BadNoData));
}

// ---------------------------------------------------------------------------
// Phase D: the "2" / SimpleBounds family. The prior value (before the interval)
// is the extreme, so the "2" variants include it where the base ones don't.
// Interval [12:00:02, 12:00:12); raw: 5@0s (prior), 10@5s, 20@10s.
// Hand-computed, cross-checked vs OPC 10000-13 §5.4.3.7/15-19/36 (MCP-verified).
// ---------------------------------------------------------------------------

fn phase_d_one_interval(id: u32) -> DataValue {
    let series = vec![good(5.0, 0), good(10.0, 5), good(20.0, 10)];
    let start = DateTime::from((2026, 6, 6, 12, 0, 2));
    let end = DateTime::from((2026, 6, 6, 12, 0, 12));
    let cfg = AggregateConfiguration::default();
    let mut out =
        compute_processed_intervals(&series, &NodeId::new(0u16, id), &cfg, start, end, 10_000.0);
    assert_eq!(out.len(), 1, "expected one interval for id {id}");
    out.remove(0)
}

#[test]
fn phase_d_minimum2_includes_simple_bound() {
    // Minimum2 (11286) includes the simple start bound (prior 5) -> 5.
    assert_eq!(
        phase_d_one_interval(11286).value,
        Some(Variant::Double(5.0))
    );
    // Base Minimum (2346) excludes the bound -> 10 (only in-interval values).
    assert_eq!(
        phase_d_one_interval(2346).value,
        Some(Variant::Double(10.0))
    );
    // Maximum2 (11287) = 20; Range2 (11288) = 20 - 5 = 15.
    assert_eq!(
        phase_d_one_interval(11287).value,
        Some(Variant::Double(20.0))
    );
    assert_eq!(
        phase_d_one_interval(11288).value,
        Some(Variant::Double(15.0))
    );
}

#[test]
fn phase_d_min_actual_time2_uses_bound_timestamp() {
    // MinimumActualTime2 (11305): the min is the start bound (5) -> timestamp = interval_start.
    let r = phase_d_one_interval(11305);
    assert_eq!(r.value, Some(Variant::Double(5.0)));
    assert_eq!(
        r.source_timestamp,
        Some(DateTime::from((2026, 6, 6, 12, 0, 2)))
    );
    // MaximumActualTime2 (11306): max 20 at its actual time 12:00:10.
    let mx = phase_d_one_interval(11306);
    assert_eq!(mx.value, Some(Variant::Double(20.0)));
    assert_eq!(
        mx.source_timestamp,
        Some(DateTime::from((2026, 6, 6, 12, 0, 10)))
    );
}

#[test]
fn phase_d_time_average2_total2_match_stepped_area() {
    // stepped area with prior 5 held from 2s: 5*(5-2) + 10*(10-5) + 20*(12-10) = 15+50+40 = 105.
    // TimeAverage2 = 105/10 = 10.5; Total2 = 105. Both equal the corrected TimeAverage/Total
    // (same series) since our default is stepped/simple bounds.
    let ta2 = phase_d_one_interval(11285);
    match ta2.value {
        Some(Variant::Double(v)) => assert!((v - 10.5).abs() < 1e-9, "got {v}"),
        other => panic!("expected Double, got {other:?}"),
    }
    let total2 = phase_d_one_interval(11304);
    match total2.value {
        Some(Variant::Double(v)) => assert!((v - 105.0).abs() < 1e-9, "got {v}"),
        other => panic!("expected Double, got {other:?}"),
    }
    // TimeAverage2 == corrected TimeAverage(2343) for the same series.
    let ta = phase_d_one_interval(2343);
    assert_eq!(ta.value, ta2.value);
}

#[test]
fn phase_d_no_prior_degrades_to_in_interval() {
    // No prior before the interval -> Minimum2 degrades to the in-interval minimum.
    let series = vec![good(10.0, 5), good(20.0, 10)];
    let start = DateTime::from((2026, 6, 6, 12, 0, 2));
    let end = DateTime::from((2026, 6, 6, 12, 0, 12));
    let cfg = AggregateConfiguration::default();
    let out = compute_processed_intervals(
        &series,
        &NodeId::new(0u16, 11286),
        &cfg,
        start,
        end,
        10_000.0,
    );
    assert_eq!(out[0].value, Some(Variant::Double(10.0)));
}
