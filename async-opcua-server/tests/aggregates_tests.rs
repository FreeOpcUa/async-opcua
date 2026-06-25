//! Integration and unit tests for OPC-UA mathematical aggregates (time-weighted average, min, max, std dev) and quality calculations.

use opcua_server::aggregates::engine::{
    aggregate_average, aggregate_maximum, aggregate_minimum, aggregate_std_dev,
    calculate_std_dev_sample, calculate_time_weighted_average, dispatch_aggregate,
    partition_intervals, AggregateInput,
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

    // A request for the correct standard id is computed; the previously-mis-used id 2352 (which is
    // actually AggregateFunction_Count, not implemented) must report BadAggregateNotSupported.
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
    assert_eq!(
        calculate_aggregate(&[&v], &NodeId::new(0u16, 2352u32), start, end).status,
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
