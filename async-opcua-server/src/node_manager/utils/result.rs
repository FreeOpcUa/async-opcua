use opcua_types::{DiagnosticBits, DiagnosticInfo};

pub(crate) trait IntoResult {
    type Result;

    fn into_result(self) -> (Self::Result, Option<DiagnosticInfo>);
}

pub(crate) fn consume_results<T: IntoResult>(
    items: Vec<T>,
    bits: DiagnosticBits,
) -> (Option<Vec<T::Result>>, Option<Vec<DiagnosticInfo>>) {
    if bits.is_empty() {
        (
            Some(items.into_iter().map(|i| i.into_result().0).collect()),
            None,
        )
    } else {
        let (r, d) = items
            .into_iter()
            .map(|v| {
                let (res, diag) = v.into_result();
                let mut diag = diag.unwrap_or_default();
                filter_diagnostic_info(bits, &mut diag);
                (res, diag)
            })
            .unzip();
        (Some(r), Some(d))
    }
}

pub(crate) fn filter_diagnostic_info(bits: DiagnosticBits, info: &mut DiagnosticInfo) {
    if !bits.contains(DiagnosticBits::OPERATIONAL_LEVEL_SYMBOLIC_ID) {
        info.symbolic_id = None;
    }
    if !bits.contains(DiagnosticBits::OPERATIONAL_LEVEL_LOCALIZED_TEXT) {
        info.localized_text = None;
    }
    if !bits.contains(DiagnosticBits::OPERATIONAL_LEVEL_ADDITIONAL_INFO) {
        info.additional_info = None;
    }
    if !bits.contains(DiagnosticBits::OPERATIONAL_LEVEL_INNER_STATUS_CODE) {
        info.inner_status_code = None;
    }
    if !bits.contains(DiagnosticBits::OPERATIONAL_LEVEL_INNER_DIAGNOSTICS) {
        info.inner_diagnostic_info = None;
    } else if let Some(d) = info.inner_diagnostic_info.as_mut() {
        filter_diagnostic_info(bits, &mut *d);
    }
}
