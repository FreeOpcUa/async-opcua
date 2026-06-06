//! Quality code computation logic for aggregates (Part 11/13).

use opcua_types::StatusCode;

/// Computes the aggregate quality code based on the raw data points' status codes.
pub fn compute_aggregate_quality(statuses: &[Option<StatusCode>]) -> StatusCode {
    if statuses.is_empty() {
        return StatusCode::BadNoData;
    }

    let mut good_count = 0;
    let mut bad_count = 0;
    let mut _uncertain_count = 0;

    for status_opt in statuses {
        let status = status_opt.unwrap_or(StatusCode::Good);
        if status.is_good() {
            good_count += 1;
        } else if status.is_bad() {
            bad_count += 1;
        } else {
            _uncertain_count += 1;
        }
    }

    let total = statuses.len();
    if bad_count == total {
        StatusCode::BadNoData
    } else if good_count == total {
        StatusCode::Good
    } else {
        StatusCode::UncertainDataSubNormal
    }
}
