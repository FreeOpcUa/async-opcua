//! Implementation of data change filters, and `Deadband`

use crate::{DataChangeFilter, DataChangeTrigger, DataValue, DeadbandType, StatusCode, Variant};

#[derive(Debug, Clone)]
/// Parsed percent deadband. Percent deadband works by applying a deadband
/// based on the EURange of the node.
pub struct PercentDeadband {
    // Computed from high and low. high = low + range
    low: f64,
    range: f64,
    // Trigger, between 0 and 1
    trigger: f64,
}

#[derive(Debug, Clone)]
/// Deadband type, used in data change filters.
pub enum Deadband {
    /// No deadband.
    None,
    /// A positive number deadbanding on absolute change.
    Absolute(f64),
    /// Deadband based on a percent of EURange.
    Percent(PercentDeadband),
}

impl Deadband {
    fn is_changed_option(&self, v1: Option<&Variant>, v2: Option<&Variant>) -> bool {
        match (v1, v2) {
            (Some(_), None) | (None, Some(_)) => true,
            (None, None) => {
                // If it's always none then it hasn't changed
                false
            }
            (Some(v1), Some(v2)) => {
                // Otherwise test the filter
                self.is_changed(v1, v2)
            }
        }
    }

    fn is_changed(&self, v1: &Variant, v2: &Variant) -> bool {
        if let (Some(v1), Some(v2)) = (v1.as_array(), v2.as_array()) {
            // From the standard:
            // "If the item is an array of values, the entire array is returned if
            // any array element exceeds the AbsoluteDeadband, or the size or dimension of the
            // array changes.". Equivalent for PercentDeadband.
            if v1.len() != v2.len() {
                return true;
            }

            for (v1, v2) in v1.iter().zip(v2.iter()) {
                if self.is_changed(v1, v2) {
                    return true;
                }
            }
            false
        } else {
            match self {
                Deadband::None => v1 != v2,
                Deadband::Absolute(deadband) => {
                    let (Some(v1), Some(v2)) = (v1.as_f64(), v2.as_f64()) else {
                        return true;
                    };
                    (v1 - v2).abs() > *deadband
                }
                Deadband::Percent(percent_deadband) => {
                    let (Some(v1), Some(v2)) = (v1.as_f64(), v2.as_f64()) else {
                        return true;
                    };
                    let v1_pct = (v1 - percent_deadband.low) / percent_deadband.range;
                    let v2_pct = (v2 - percent_deadband.low) / percent_deadband.range;
                    (v1_pct - v2_pct).abs() > percent_deadband.trigger
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
/// Parsed variant of the data change filter that can be directly checked for data changes.
pub struct ParsedDataChangeFilter {
    /// What is considered a change.
    pub trigger: DataChangeTrigger,
    /// Deadband filter.
    pub deadband: Deadband,
}

impl ParsedDataChangeFilter {
    /// Check if this data change filter considers `v1` different from `v2`.
    pub fn is_changed(&self, v1: &DataValue, v2: &DataValue) -> bool {
        match self.trigger {
            DataChangeTrigger::Status => v1.status != v2.status,
            DataChangeTrigger::StatusValue => {
                v1.status != v2.status
                    || self
                        .deadband
                        .is_changed_option(v1.value.as_ref(), v2.value.as_ref())
            }
            DataChangeTrigger::StatusValueTimestamp => {
                v1.status != v2.status
                    || v1.source_timestamp != v2.source_timestamp
                    || v1.source_picoseconds != v2.source_picoseconds
                    || self
                        .deadband
                        .is_changed_option(v1.value.as_ref(), v2.value.as_ref())
            }
        }
    }

    /// Parse from a raw data change filter and the EURange of the node, if present.
    pub fn parse(
        filter: DataChangeFilter,
        eu_range: Option<(f64, f64)>,
    ) -> Result<Self, StatusCode> {
        let as_int: i32 = filter
            .deadband_type
            .try_into()
            .map_err(|_| StatusCode::BadDeadbandFilterInvalid)?;
        let ty =
            DeadbandType::try_from(as_int).map_err(|_| StatusCode::BadDeadbandFilterInvalid)?;
        let deadband = match ty {
            DeadbandType::None => Deadband::None,
            DeadbandType::Absolute => {
                if filter.deadband_value < 0.0 {
                    return Err(StatusCode::BadDeadbandFilterInvalid);
                }
                Deadband::Absolute(filter.deadband_value)
            }
            DeadbandType::Percent => {
                if filter.deadband_value < 0.0 || filter.deadband_value > 100.0 {
                    return Err(StatusCode::BadDeadbandFilterInvalid);
                }
                let Some((low, high)) = eu_range else {
                    return Err(StatusCode::BadDeadbandFilterInvalid);
                };
                if low >= high {
                    return Err(StatusCode::BadDeadbandFilterInvalid);
                }
                Deadband::Percent(PercentDeadband {
                    low,
                    range: high - low,
                    trigger: filter.deadband_value / 100.0,
                })
            }
        };
        Ok(Self {
            trigger: filter.trigger,
            deadband,
        })
    }
}
