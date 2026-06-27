//! Discrete-alarm evaluation and address-space wiring for OffNormalAlarmType and
//! TripAlarmType.

use crate::address_space::{AddressSpace, VariableBuilder};
use crate::alarms::replace_condition_type_definition;
use crate::alarms::source_monitor::SourceMonitoredAlarm;
use crate::alarms::state_machine::ConditionStateMachine;
use opcua_core::events::AlarmEvent;
use opcua_types::{
    DataTypeId, DataValue, DateTime, LocalizedText, NodeId, ObjectTypeId, VariableTypeId, Variant,
};
use std::sync::Mutex;

const ACTIVE_SEVERITY: u16 = 500;
const INACTIVE_SEVERITY: u16 = 0;

/// Selects the concrete discrete alarm ObjectType.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscreteAlarmKind {
    /// OffNormalAlarmType, active when the value differs from NormalState.
    OffNormal,
    /// TripAlarmType, an OffNormalAlarmType subtype with the same active-state mechanics.
    Trip,
}

/// Address-space nodes and runtime state for an off-normal discrete alarm.
#[derive(Debug)]
pub struct DiscreteAlarm {
    /// Base A&C lifecycle state machine.
    pub condition: ConditionStateMachine,
    normal: Variant,
    type_id: NodeId,
    prev_active: Mutex<bool>,
}

impl DiscreteAlarm {
    /// Returns the base condition state machine for registry integration.
    #[must_use]
    pub fn condition_state_machine(&self) -> ConditionStateMachine {
        self.condition.clone()
    }

    /// Creates an OffNormalAlarmType or TripAlarmType instance and its NormalState property.
    pub fn create_in_address_space(
        address_space: &mut AddressSpace,
        ns: u16,
        device: &str,
        alarm_name: &str,
        source_node_id: NodeId,
        kind: DiscreteAlarmKind,
        normal: Variant,
    ) -> Self {
        let condition = ConditionStateMachine::create_in_address_space(
            address_space,
            device,
            alarm_name,
            source_node_id,
            alarm_name,
        );
        let type_id = kind.type_id();

        replace_condition_type_definition(address_space, &condition.condition_id, type_id.clone());

        let base_s = format!("Alarm_{}_{}", device, alarm_name);
        let normal_state_id = NodeId::new(ns, format!("{}_NormalState", base_s));
        let data_type = normal
            .data_type()
            .map(|data_type| data_type.node_id)
            .unwrap_or_else(|| NodeId::from(DataTypeId::BaseDataType));

        VariableBuilder::new(&normal_state_id, "NormalState", "NormalState")
            .data_type(data_type)
            .has_type_definition(VariableTypeId::PropertyType)
            .value(normal.clone())
            .writable()
            .property_of(condition.condition_id.clone())
            .insert(address_space);

        Self {
            condition,
            normal,
            type_id,
            prev_active: Mutex::new(false),
        }
    }

    /// Evaluates and writes a new discrete value, returning an alarm event when active state changes.
    pub fn update_value(
        &self,
        address_space: &mut AddressSpace,
        value: Variant,
    ) -> Option<AlarmEvent> {
        if !self.condition.get_enabled(address_space) {
            return None;
        }

        let active = value != self.normal;
        {
            let mut prev_active = self.prev_active.lock().unwrap();
            if active == *prev_active {
                return None;
            }
            *prev_active = active;
        }

        let severity = if active {
            ACTIVE_SEVERITY
        } else {
            INACTIVE_SEVERITY
        };
        let message = LocalizedText::new("en", if active { "Off-normal state" } else { "Normal" });

        let was_active = self.condition.get_active(address_space);
        let was_acked = self.condition.get_acked(address_space);
        if was_active && !was_acked && !active {
            self.condition.create_branch(address_space);
        }
        self.condition.set_active(address_space, active);
        self.condition.set_severity(address_space, severity);
        self.condition.set_message(address_space, message.clone());

        if active {
            self.condition.set_acked(address_space, false);
            self.condition.set_confirmed(address_space, false);
        }

        let acked = self.condition.get_acked(address_space);
        let confirmed = self.condition.get_confirmed(address_space);
        let retain = active || !acked || !confirmed;
        self.condition.set_retain(address_space, retain);

        let event_id = uuid::Uuid::new_v4().as_bytes().to_vec();
        self.condition.set_current_event_id(&event_id);

        Some(AlarmEvent {
            event_id,
            event_type: self.type_id.clone(),
            source_node: self.condition.source_node_id.clone(),
            source_name: self.condition.condition_name.clone(),
            time: DateTime::now(),
            message,
            severity,
            condition_id: self.condition.condition_id.clone(),
            branch_id: NodeId::null(),
            condition_name: self.condition.condition_name.clone(),
            active_state: active,
            acked_state: acked,
            confirmed_state: confirmed,
            retain,
        })
    }
}

impl SourceMonitoredAlarm for DiscreteAlarm {
    fn source_node(&self) -> &NodeId {
        &self.condition.source_node_id
    }

    fn condition_id(&self) -> &NodeId {
        &self.condition.condition_id
    }

    fn re_evaluate(
        &self,
        address_space: &mut AddressSpace,
        value: &DataValue,
    ) -> Option<AlarmEvent> {
        if value.status.is_some_and(|status| status.is_bad()) {
            return None;
        }

        match value.value.as_ref()? {
            Variant::Empty => None,
            variant => self.update_value(address_space, variant.clone()),
        }
    }
}

impl DiscreteAlarmKind {
    fn type_id(self) -> NodeId {
        match self {
            Self::OffNormal => NodeId::from(ObjectTypeId::OffNormalAlarmType),
            Self::Trip => NodeId::from(ObjectTypeId::TripAlarmType),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alarms::source_monitor::SourceMonitoredAlarm;
    use opcua_types::{DataValue, StatusCode};

    fn test_address_space() -> AddressSpace {
        let mut address_space = AddressSpace::new();
        address_space.add_namespace("http://opcfoundation.org/UA/", 0);
        address_space.add_namespace("urn:test", 2);
        address_space
    }

    #[test]
    fn source_monitor_re_evaluate_delegates_raw_discrete_variant_and_skips_bad_status() {
        let mut address_space = test_address_space();
        let alarm = DiscreteAlarm::create_in_address_space(
            &mut address_space,
            2,
            "DeviceA",
            "RunState",
            NodeId::new(2, "DeviceA.Running"),
            DiscreteAlarmKind::OffNormal,
            Variant::from(false),
        );

        let active_event = SourceMonitoredAlarm::re_evaluate(
            &alarm,
            &mut address_space,
            &DataValue::from((Variant::from(true), StatusCode::Good)),
        )
        .expect("off-normal value should activate the discrete alarm");
        assert!(active_event.active_state);

        let repeat_event = SourceMonitoredAlarm::re_evaluate(
            &alarm,
            &mut address_space,
            &DataValue::from((Variant::from(true), StatusCode::Good)),
        );
        assert!(
            repeat_event.is_none(),
            "unchanged active state should not emit a second event"
        );

        let bad_status_event = SourceMonitoredAlarm::re_evaluate(
            &alarm,
            &mut address_space,
            &DataValue::from((Variant::from(false), StatusCode::Bad)),
        );
        assert!(
            bad_status_event.is_none(),
            "Bad status source values should be skipped"
        );
    }
}
