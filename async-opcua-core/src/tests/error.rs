use opcua_types::StatusCode;

use crate::error::{BadFilterNotSupported, BadUserAccessDenied};

#[test]
fn advanced_compliance_error_constants_have_expected_status_codes() {
    assert_eq!(
        BadFilterNotSupported,
        StatusCode::BadMonitoredItemFilterUnsupported
    );
    assert_eq!(BadFilterNotSupported.bits(), 0x8044_0000);

    assert_eq!(BadUserAccessDenied, StatusCode::BadUserAccessDenied);
    assert_eq!(BadUserAccessDenied.bits(), 0x801f_0000);
}
