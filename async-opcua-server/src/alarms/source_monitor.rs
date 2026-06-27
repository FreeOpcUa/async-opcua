//! Alarm source-monitoring abstraction for re-evaluating alarms from InputNode value changes.

use crate::address_space::AddressSpace;
use opcua_core::events::AlarmEvent;
use opcua_core::sync::RwLock;
use opcua_types::{DataValue, NodeId, Variant};
use std::collections::HashMap;
use std::sync::Arc;

/// Alarm that can be re-evaluated when its bound source Variable changes.
pub trait SourceMonitoredAlarm: Send + Sync {
    /// The bound InputNode -- the source Variable this alarm monitors (Part 9 Section 5.8.2).
    fn source_node(&self) -> &NodeId;

    /// The condition instance monitored from the source node.
    fn condition_id(&self) -> &NodeId;

    /// Re-evaluate against a new source value; returns the AlarmEvent to dispatch, or None
    /// (no transition / disabled / value not usable). Implementations delegate to the alarm's
    /// existing `update_value` and add no new evaluation logic.
    fn re_evaluate(
        &self,
        address_space: &mut AddressSpace,
        value: &DataValue,
    ) -> Option<AlarmEvent>;
}

/// Extract an f64 from a written source DataValue for numeric-limit re-evaluation.
/// Returns None (skip re-evaluation, never panic) when the value is absent, the status is Bad,
/// or the Variant is not a numeric scalar. (Part 9 §5.8.2 — alarm InputNode is a numeric source.)
pub fn source_value_as_f64(value: &DataValue) -> Option<f64> {
    if value.status.is_some_and(|status| status.is_bad()) {
        return None;
    }

    match value.value.as_ref()? {
        Variant::Double(value) => Some(*value),
        Variant::Float(value) => Some(f64::from(*value)),
        Variant::SByte(value) => Some(f64::from(*value)),
        Variant::Byte(value) => Some(f64::from(*value)),
        Variant::Int16(value) => Some(f64::from(*value)),
        Variant::UInt16(value) => Some(f64::from(*value)),
        Variant::Int32(value) => Some(f64::from(*value)),
        Variant::UInt32(value) => Some(f64::from(*value)),
        Variant::Int64(value) => Some(*value as f64),
        Variant::UInt64(value) => Some(*value as f64),
        _ => None,
    }
}

/// Alarms grouped by the source Variable NodeId they monitor.
pub struct AlarmSourceRegistry {
    bindings: RwLock<HashMap<NodeId, Vec<Arc<dyn SourceMonitoredAlarm>>>>,
}

impl Default for AlarmSourceRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl AlarmSourceRegistry {
    /// Creates an empty source-to-alarm registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            bindings: RwLock::new(HashMap::new()),
        }
    }

    /// Registers an alarm under a source Variable NodeId.
    pub fn register(&self, source: NodeId, alarm: Arc<dyn SourceMonitoredAlarm>) {
        self.bindings.write().entry(source).or_default().push(alarm);
    }

    /// Removes the alarm bound to `condition_id` from a source Variable.
    pub fn unregister(&self, source: &NodeId, condition_id: &NodeId) {
        let mut bindings = self.bindings.write();
        let remove_source = if let Some(alarms) = bindings.get_mut(source) {
            // ponytail: condition_id is the stable unregister key; Arc pointer identity is
            // not used because callers are not required to pass back the original Arc handle.
            alarms.retain(|alarm| alarm.condition_id() != condition_id);
            alarms.is_empty()
        } else {
            false
        };

        if remove_source {
            bindings.remove(source);
        }
    }

    /// Returns the alarms registered for a source Variable NodeId.
    #[must_use]
    pub fn alarms_for(&self, source: &NodeId) -> Vec<Arc<dyn SourceMonitoredAlarm>> {
        self.bindings
            .read()
            .get(source)
            .cloned()
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opcua_types::{StatusCode, Variant};

    struct SmokeAlarm {
        source: NodeId,
        condition: NodeId,
    }

    impl SourceMonitoredAlarm for SmokeAlarm {
        fn source_node(&self) -> &NodeId {
            &self.source
        }

        fn condition_id(&self) -> &NodeId {
            &self.condition
        }

        fn re_evaluate(
            &self,
            _address_space: &mut AddressSpace,
            _value: &DataValue,
        ) -> Option<AlarmEvent> {
            None
        }
    }

    #[test]
    fn alarm_source_registry_api_compiles() {
        let registry = AlarmSourceRegistry::default();
        let source = NodeId::new(2, "Source");
        let condition = NodeId::new(2, "Condition");
        let alarm: Arc<dyn SourceMonitoredAlarm> = Arc::new(SmokeAlarm {
            source: source.clone(),
            condition: condition.clone(),
        });

        registry.register(source.clone(), alarm);
        let _alarms = registry.alarms_for(&source);
        registry.unregister(&source, &condition);
    }

    fn smoke(source: &NodeId, condition: &str) -> Arc<dyn SourceMonitoredAlarm> {
        Arc::new(SmokeAlarm {
            source: source.clone(),
            condition: NodeId::new(2, condition),
        })
    }

    // T006 (Part 9 §4.4): the source→alarm index supports multiple alarms per source and removes
    // exactly one by condition id; unknown sources return empty.
    #[test]
    fn registry_indexes_multiple_alarms_per_source_and_unregisters_one() {
        let registry = AlarmSourceRegistry::default();
        let src_a = NodeId::new(2, "SourceA");
        let src_b = NodeId::new(2, "SourceB");

        registry.register(src_a.clone(), smoke(&src_a, "AlarmA1"));
        registry.register(src_a.clone(), smoke(&src_a, "AlarmA2"));
        registry.register(src_b.clone(), smoke(&src_b, "AlarmB1"));

        assert_eq!(
            registry.alarms_for(&src_a).len(),
            2,
            "both alarms on A are indexed"
        );
        assert_eq!(registry.alarms_for(&src_b).len(), 1);
        assert!(registry.alarms_for(&NodeId::new(2, "Nope")).is_empty());

        registry.unregister(&src_a, &NodeId::new(2, "AlarmA1"));
        let remaining = registry.alarms_for(&src_a);
        assert_eq!(remaining.len(), 1, "only AlarmA1 removed");
        assert_eq!(remaining[0].condition_id(), &NodeId::new(2, "AlarmA2"));
        assert_eq!(registry.alarms_for(&src_b).len(), 1);
    }

    #[test]
    fn source_value_as_f64_skips_unusable_values() {
        assert_eq!(
            source_value_as_f64(&DataValue::from((Variant::Double(1.0), StatusCode::Bad))),
            None
        );
        assert_eq!(source_value_as_f64(&DataValue::null()), None);
        assert_eq!(source_value_as_f64(&DataValue::from(Variant::Empty)), None);
        assert_eq!(source_value_as_f64(&DataValue::from("not numeric")), None);
        assert_eq!(source_value_as_f64(&DataValue::from(true)), None);
        assert_eq!(
            source_value_as_f64(&DataValue::from(Variant::from(vec![1_i32, 2_i32]))),
            None
        );
    }

    #[test]
    fn source_value_as_f64_maps_numeric_scalar_variants() {
        let cases = [
            (Variant::Double(1.25), 1.25),
            (Variant::Float(2.5), 2.5),
            (Variant::SByte(-3), -3.0),
            (Variant::Byte(4), 4.0),
            (Variant::Int16(-5), -5.0),
            (Variant::UInt16(6), 6.0),
            (Variant::Int32(-7), -7.0),
            (Variant::UInt32(8), 8.0),
            (Variant::Int64(-9), -9.0),
            (Variant::UInt64(10), 10.0),
        ];

        for (variant, expected) in cases {
            assert_eq!(
                source_value_as_f64(&DataValue::from(variant)),
                Some(expected)
            );
        }
    }
}
