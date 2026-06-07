//! Common advanced-compliance status code aliases.

use opcua_types::StatusCode;

#[allow(non_upper_case_globals)]
/// The server does not support the requested filter.
pub const BadFilterNotSupported: StatusCode = StatusCode::BadMonitoredItemFilterUnsupported;

#[allow(non_upper_case_globals)]
/// User does not have permission to perform the requested operation.
pub const BadUserAccessDenied: StatusCode = StatusCode::BadUserAccessDenied;
