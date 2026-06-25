//! Condition State Machine implementation.
//! Manages active alarms, EnabledState, ActiveState, AckedState, and ConfirmedState in the AddressSpace.

use crate::address_space::{AddressSpace, ObjectBuilder, VariableBuilder};
use opcua_nodes::NodeType;
use opcua_types::{DataTypeId, LocalizedText, NodeId, StatusCode, VariableTypeId, Variant};
use std::sync::{Arc, Mutex};

/// Current state of an AlarmCondition ShelvedStateMachineType instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShelvingState {
    /// Alarm is not shelved.
    Unshelved,
    /// Alarm is shelved until it next becomes inactive.
    OneShotShelved,
    /// Alarm is shelved until its timer expires or it is explicitly unshelved.
    TimedShelved,
}

impl ShelvingState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Unshelved => "Unshelved",
            Self::OneShotShelved => "OneShotShelved",
            Self::TimedShelved => "TimedShelved",
        }
    }
}

/// Manages an OPC-UA Alarm Condition instance and its state variables.
#[derive(Debug, Clone)]
pub struct ConditionStateMachine {
    /// NodeId of the condition instance.
    pub condition_id: NodeId,
    /// NodeId of the monitored source node.
    pub source_node_id: NodeId,
    /// Human-readable condition name.
    pub condition_name: String,
    /// NodeId of the EnabledState variable.
    pub enabled_state_id: NodeId,
    /// NodeId of the ActiveState variable.
    pub active_state_id: NodeId,
    /// NodeId of the AckedState variable.
    pub acked_state_id: NodeId,
    /// NodeId of the ConfirmedState variable.
    pub confirmed_state_id: NodeId,
    /// NodeId of the Severity variable.
    pub severity_id: NodeId,
    /// NodeId of the Message variable.
    pub message_id: NodeId,
    /// NodeId of the Retain variable.
    pub retain_id: NodeId,
    /// NodeId of the SuppressedState variable.
    pub suppressed_state_id: NodeId,
    /// NodeId of the OutOfServiceState variable.
    pub out_of_service_state_id: NodeId,
    /// NodeId of the SuppressedOrShelved variable.
    pub suppressed_or_shelved_id: NodeId,
    /// NodeId of the ShelvingState object.
    pub shelving_state_id: NodeId,
    /// NodeId of the ShelvingState.CurrentState variable.
    pub shelving_current_state_id: NodeId,
    /// NodeId of the ShelvingState.UnshelveTime property.
    pub unshelve_time_id: NodeId,
    /// EventId of the condition's current (most recent) reportable state, shared across clones.
    /// Acknowledge/Confirm validate the client-supplied EventId against this (Part 9 §5.5.2).
    current_event_id: Arc<Mutex<Vec<u8>>>,
}

impl ConditionStateMachine {
    /// Creates and registers a new Alarm Condition state machine instance in the AddressSpace.
    pub fn create_in_address_space(
        address_space: &mut AddressSpace,
        device: &str,
        alarm_type: &str,
        source_node_id: NodeId,
        condition_name: &str,
    ) -> Self {
        let ns_idx = 2; // Dynamic namespace
        let base_s = format!("Alarm_{}_{}", device, alarm_type);

        let condition_id = NodeId::new(ns_idx, base_s.clone());
        let enabled_state_id = NodeId::new(ns_idx, format!("{}_EnabledState", base_s));
        let active_state_id = NodeId::new(ns_idx, format!("{}_ActiveState", base_s));
        let acked_state_id = NodeId::new(ns_idx, format!("{}_AckedState", base_s));
        let confirmed_state_id = NodeId::new(ns_idx, format!("{}_ConfirmedState", base_s));
        let severity_id = NodeId::new(ns_idx, format!("{}_Severity", base_s));
        let message_id = NodeId::new(ns_idx, format!("{}_Message", base_s));
        let retain_id = NodeId::new(ns_idx, format!("{}_Retain", base_s));
        let suppressed_state_id = NodeId::new(ns_idx, format!("{}_SuppressedState", base_s));
        let out_of_service_state_id = NodeId::new(ns_idx, format!("{}_OutOfServiceState", base_s));
        let suppressed_or_shelved_id =
            NodeId::new(ns_idx, format!("{}_SuppressedOrShelved", base_s));
        let shelving_state_id = NodeId::new(ns_idx, format!("{}_ShelvingState", base_s));
        let shelving_current_state_id =
            NodeId::new(ns_idx, format!("{}_ShelvingState_CurrentState", base_s));
        let unshelve_time_id =
            NodeId::new(ns_idx, format!("{}_ShelvingState_UnshelveTime", base_s));

        // 1. Create Condition Object (AlarmConditionType i=2915)
        let alarm_obj = ObjectBuilder::new(
            &condition_id,
            format!("Alarm_{}_{}", device, alarm_type),
            condition_name,
        )
        .has_type_definition(NodeId::new(0, 2915))
        .component_of(source_node_id.clone())
        .build();
        address_space.insert::<_, NodeId>(alarm_obj, None);

        // 2. Create EnabledState (TwoStateVariableType)
        let enabled_var = VariableBuilder::new(&enabled_state_id, "EnabledState", "EnabledState")
            .data_type(opcua_types::DataTypeId::Boolean)
            .value(true) // Enabled by default
            .writable()
            .build();
        address_space.insert(
            enabled_var,
            Some(&[(
                &condition_id,
                &NodeId::new(0, 47),
                opcua_nodes::ReferenceDirection::Inverse,
            )]),
        );

        // 3. Create ActiveState (TwoStateVariableType)
        let active_var = VariableBuilder::new(&active_state_id, "ActiveState", "ActiveState")
            .data_type(opcua_types::DataTypeId::Boolean)
            .value(false) // Inactive by default
            .writable()
            .build();
        address_space.insert(
            active_var,
            Some(&[(
                &condition_id,
                &NodeId::new(0, 47),
                opcua_nodes::ReferenceDirection::Inverse,
            )]),
        );

        // 4. Create AckedState (TwoStateVariableType)
        let acked_var = VariableBuilder::new(&acked_state_id, "AckedState", "AckedState")
            .data_type(opcua_types::DataTypeId::Boolean)
            .value(false) // Unacknowledged by default
            .writable()
            .build();
        address_space.insert(
            acked_var,
            Some(&[(
                &condition_id,
                &NodeId::new(0, 47),
                opcua_nodes::ReferenceDirection::Inverse,
            )]),
        );

        // 5. Create ConfirmedState (TwoStateVariableType)
        let confirmed_var =
            VariableBuilder::new(&confirmed_state_id, "ConfirmedState", "ConfirmedState")
                .data_type(opcua_types::DataTypeId::Boolean)
                .value(false) // Unconfirmed by default
                .writable()
                .build();
        address_space.insert(
            confirmed_var,
            Some(&[(
                &condition_id,
                &NodeId::new(0, 47),
                opcua_nodes::ReferenceDirection::Inverse,
            )]),
        );

        // 6. Create Severity variable
        let severity_var = VariableBuilder::new(&severity_id, "Severity", "Severity")
            .data_type(opcua_types::DataTypeId::UInt16)
            .value(100u16)
            .writable()
            .build();
        address_space.insert(
            severity_var,
            Some(&[(
                &condition_id,
                &NodeId::new(0, 47),
                opcua_nodes::ReferenceDirection::Inverse,
            )]),
        );

        // 7. Create Message variable
        let message_var = VariableBuilder::new(&message_id, "Message", "Message")
            .data_type(opcua_types::DataTypeId::LocalizedText)
            .value(LocalizedText::new("en", "Normal operating state"))
            .writable()
            .build();
        address_space.insert(
            message_var,
            Some(&[(
                &condition_id,
                &NodeId::new(0, 47),
                opcua_nodes::ReferenceDirection::Inverse,
            )]),
        );

        // 8. Create Retain variable
        let retain_var = VariableBuilder::new(&retain_id, "Retain", "Retain")
            .data_type(opcua_types::DataTypeId::Boolean)
            .value(false)
            .writable()
            .build();
        address_space.insert(
            retain_var,
            Some(&[(
                &condition_id,
                &NodeId::new(0, 47),
                opcua_nodes::ReferenceDirection::Inverse,
            )]),
        );

        // 9. Create display-suppression state nodes.
        let suppressed_var =
            VariableBuilder::new(&suppressed_state_id, "SuppressedState", "SuppressedState")
                .data_type(DataTypeId::Boolean)
                .has_type_definition(VariableTypeId::TwoStateVariableType)
                .value(false)
                .writable()
                .build();
        address_space.insert(
            suppressed_var,
            Some(&[(
                &condition_id,
                &NodeId::new(0, 47),
                opcua_nodes::ReferenceDirection::Inverse,
            )]),
        );

        let out_of_service_var = VariableBuilder::new(
            &out_of_service_state_id,
            "OutOfServiceState",
            "OutOfServiceState",
        )
        .data_type(DataTypeId::Boolean)
        .has_type_definition(VariableTypeId::TwoStateVariableType)
        .value(false)
        .writable()
        .build();
        address_space.insert(
            out_of_service_var,
            Some(&[(
                &condition_id,
                &NodeId::new(0, 47),
                opcua_nodes::ReferenceDirection::Inverse,
            )]),
        );

        let suppressed_or_shelved_var = VariableBuilder::new(
            &suppressed_or_shelved_id,
            "SuppressedOrShelved",
            "SuppressedOrShelved",
        )
        .data_type(DataTypeId::Boolean)
        .value(false)
        .writable()
        .build();
        address_space.insert(
            suppressed_or_shelved_var,
            Some(&[(
                &condition_id,
                &NodeId::new(0, 47),
                opcua_nodes::ReferenceDirection::Inverse,
            )]),
        );

        let shelving_obj = ObjectBuilder::new(&shelving_state_id, "ShelvingState", "ShelvingState")
            .has_type_definition(NodeId::new(0, 2929))
            .build();
        address_space.insert(
            shelving_obj,
            Some(&[(
                &condition_id,
                &NodeId::new(0, 47),
                opcua_nodes::ReferenceDirection::Inverse,
            )]),
        );

        let shelving_current_state_var =
            VariableBuilder::new(&shelving_current_state_id, "CurrentState", "CurrentState")
                .data_type(DataTypeId::LocalizedText)
                .has_type_definition(VariableTypeId::StateVariableType)
                .value(LocalizedText::new("en", ShelvingState::Unshelved.as_str()))
                .writable()
                .build();
        address_space.insert(
            shelving_current_state_var,
            Some(&[(
                &shelving_state_id,
                &NodeId::new(0, 47),
                opcua_nodes::ReferenceDirection::Inverse,
            )]),
        );

        let unshelve_time_var =
            VariableBuilder::new(&unshelve_time_id, "UnshelveTime", "UnshelveTime")
                .data_type(DataTypeId::Double)
                .has_type_definition(VariableTypeId::PropertyType)
                .value(0.0f64)
                .writable()
                .build();
        address_space.insert(
            unshelve_time_var,
            Some(&[(
                &shelving_state_id,
                &NodeId::new(0, 46),
                opcua_nodes::ReferenceDirection::Inverse,
            )]),
        );

        Self {
            condition_id,
            source_node_id,
            condition_name: condition_name.to_string(),
            enabled_state_id,
            active_state_id,
            acked_state_id,
            confirmed_state_id,
            severity_id,
            message_id,
            retain_id,
            suppressed_state_id,
            out_of_service_state_id,
            suppressed_or_shelved_id,
            shelving_state_id,
            shelving_current_state_id,
            unshelve_time_id,
            current_event_id: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Records the EventId of the most recent reportable state (set when an event is generated).
    pub fn set_current_event_id(&self, event_id: &[u8]) {
        *self.current_event_id.lock().unwrap() = event_id.to_vec();
    }

    /// Whether `event_id` matches the condition's current reportable EventId. A condition that has not
    /// yet emitted an event (empty) matches nothing — Acknowledge/Confirm then fail Bad_EventIdUnknown.
    pub fn current_event_id_matches(&self, event_id: &[u8]) -> bool {
        let current = self.current_event_id.lock().unwrap();
        !current.is_empty() && current.as_slice() == event_id
    }

    /// Returns the EventId of the condition's current reportable state.
    pub fn current_event_id(&self) -> Vec<u8> {
        self.current_event_id.lock().unwrap().clone()
    }

    /// Gets whether the condition is enabled.
    pub fn get_enabled(&self, address_space: &AddressSpace) -> bool {
        self.get_bool_value(address_space, &self.enabled_state_id)
    }

    /// Sets whether the condition is enabled.
    pub fn set_enabled(&self, address_space: &mut AddressSpace, enabled: bool) {
        self.set_bool_value(address_space, &self.enabled_state_id, enabled);
    }

    /// Gets whether the condition is active.
    pub fn get_active(&self, address_space: &AddressSpace) -> bool {
        self.get_bool_value(address_space, &self.active_state_id)
    }

    /// Sets whether the condition is active.
    pub fn set_active(&self, address_space: &mut AddressSpace, active: bool) {
        self.set_bool_value(address_space, &self.active_state_id, active);
    }

    /// Gets whether the condition is acknowledged.
    pub fn get_acked(&self, address_space: &AddressSpace) -> bool {
        self.get_bool_value(address_space, &self.acked_state_id)
    }

    /// Sets whether the condition is acknowledged.
    pub fn set_acked(&self, address_space: &mut AddressSpace, acked: bool) {
        self.set_bool_value(address_space, &self.acked_state_id, acked);
    }

    /// Gets whether the condition is confirmed.
    pub fn get_confirmed(&self, address_space: &AddressSpace) -> bool {
        self.get_bool_value(address_space, &self.confirmed_state_id)
    }

    /// Sets whether the condition is confirmed.
    pub fn set_confirmed(&self, address_space: &mut AddressSpace, confirmed: bool) {
        self.set_bool_value(address_space, &self.confirmed_state_id, confirmed);
    }

    /// Gets the current severity of the condition.
    pub fn get_severity(&self, address_space: &AddressSpace) -> u16 {
        if let Some(node) = address_space.find(&self.severity_id) {
            if let NodeType::Variable(ref var) = *node {
                if let Some(Variant::UInt16(v)) = var
                    .value(
                        opcua_types::TimestampsToReturn::Neither,
                        &opcua_types::NumericRange::None,
                        &opcua_types::DataEncoding::Binary,
                        0.0,
                    )
                    .value
                {
                    return v;
                }
            }
        };
        0
    }

    /// Sets the current severity of the condition.
    pub fn set_severity(&self, address_space: &mut AddressSpace, severity: u16) {
        if let Some(mut node) = address_space.find_mut(&self.severity_id) {
            if let NodeType::Variable(ref mut var) = &mut *node {
                let _ = var.set_value(&opcua_types::NumericRange::None, Variant::from(severity));
            }
        };
    }

    /// Gets the current localized message of the condition.
    pub fn get_message(&self, address_space: &AddressSpace) -> LocalizedText {
        if let Some(node) = address_space.find(&self.message_id) {
            if let NodeType::Variable(ref var) = *node {
                if let Some(Variant::LocalizedText(ref t)) = var
                    .value(
                        opcua_types::TimestampsToReturn::Neither,
                        &opcua_types::NumericRange::None,
                        &opcua_types::DataEncoding::Binary,
                        0.0,
                    )
                    .value
                {
                    return (**t).clone();
                }
            }
        };
        LocalizedText::null()
    }

    /// Sets the current localized message of the condition.
    pub fn set_message(&self, address_space: &mut AddressSpace, message: LocalizedText) {
        if let Some(mut node) = address_space.find_mut(&self.message_id) {
            if let NodeType::Variable(ref mut var) = &mut *node {
                let _ = var.set_value(&opcua_types::NumericRange::None, Variant::from(message));
            }
        };
    }

    /// Gets whether the condition is retained.
    pub fn get_retain(&self, address_space: &AddressSpace) -> bool {
        self.get_bool_value(address_space, &self.retain_id)
    }

    /// Sets whether the condition is retained.
    pub fn set_retain(&self, address_space: &mut AddressSpace, retain: bool) {
        self.set_bool_value(address_space, &self.retain_id, retain);
    }

    /// Gets whether the condition is system-suppressed.
    pub fn get_suppressed(&self, address_space: &AddressSpace) -> bool {
        self.get_bool_value(address_space, &self.suppressed_state_id)
    }

    /// Sets whether the condition is system-suppressed.
    pub fn set_suppressed(&self, address_space: &mut AddressSpace, suppressed: bool) {
        self.set_bool_value(address_space, &self.suppressed_state_id, suppressed);
        self.recompute_suppressed_or_shelved(address_space);
    }

    /// Gets whether the condition is maintenance-suppressed.
    pub fn get_out_of_service(&self, address_space: &AddressSpace) -> bool {
        self.get_bool_value(address_space, &self.out_of_service_state_id)
    }

    /// Sets whether the condition is maintenance-suppressed.
    pub fn set_out_of_service(&self, address_space: &mut AddressSpace, out_of_service: bool) {
        self.set_bool_value(address_space, &self.out_of_service_state_id, out_of_service);
        self.recompute_suppressed_or_shelved(address_space);
    }

    /// Gets whether the condition is suppressed or shelved.
    pub fn get_suppressed_or_shelved(&self, address_space: &AddressSpace) -> bool {
        self.get_bool_value(address_space, &self.suppressed_or_shelved_id)
    }

    /// Gets the current shelving state.
    pub fn get_shelving_state(&self, address_space: &AddressSpace) -> ShelvingState {
        if let Some(node) = address_space.find(&self.shelving_current_state_id) {
            if let NodeType::Variable(ref var) = *node {
                if let Some(Variant::LocalizedText(ref text)) = var
                    .value(
                        opcua_types::TimestampsToReturn::Neither,
                        &opcua_types::NumericRange::None,
                        &opcua_types::DataEncoding::Binary,
                        0.0,
                    )
                    .value
                {
                    return match text.text.value().as_deref() {
                        Some("OneShotShelved") => ShelvingState::OneShotShelved,
                        Some("TimedShelved") => ShelvingState::TimedShelved,
                        _ => ShelvingState::Unshelved,
                    };
                }
            }
        };
        ShelvingState::Unshelved
    }

    /// Sets the current shelving state.
    pub fn set_shelving_state(&self, address_space: &mut AddressSpace, state: ShelvingState) {
        if let Some(mut node) = address_space.find_mut(&self.shelving_current_state_id) {
            if let NodeType::Variable(ref mut var) = &mut *node {
                let _ = var.set_value(
                    &opcua_types::NumericRange::None,
                    Variant::from(LocalizedText::new("en", state.as_str())),
                );
            }
        };
        self.recompute_suppressed_or_shelved(address_space);
    }

    /// Gets the remaining timed-shelve duration in milliseconds.
    pub fn get_unshelve_time(&self, address_space: &AddressSpace) -> f64 {
        if let Some(node) = address_space.find(&self.unshelve_time_id) {
            if let NodeType::Variable(ref var) = *node {
                if let Some(Variant::Double(v)) = var
                    .value(
                        opcua_types::TimestampsToReturn::Neither,
                        &opcua_types::NumericRange::None,
                        &opcua_types::DataEncoding::Binary,
                        0.0,
                    )
                    .value
                {
                    return v;
                }
            }
        };
        0.0
    }

    /// Sets the remaining timed-shelve duration in milliseconds.
    pub fn set_unshelve_time(&self, address_space: &mut AddressSpace, unshelve_time_ms: f64) {
        if let Some(mut node) = address_space.find_mut(&self.unshelve_time_id) {
            if let NodeType::Variable(ref mut var) = &mut *node {
                let _ = var.set_value(
                    &opcua_types::NumericRange::None,
                    Variant::from(unshelve_time_ms),
                );
            }
        };
    }

    /// Recomputes SuppressedOrShelved from suppression and shelving state.
    pub fn recompute_suppressed_or_shelved(&self, address_space: &mut AddressSpace) {
        let suppressed_or_shelved = self.get_suppressed(address_space)
            || self.get_out_of_service(address_space)
            || self.get_shelving_state(address_space) != ShelvingState::Unshelved;
        self.set_bool_value(
            address_space,
            &self.suppressed_or_shelved_id,
            suppressed_or_shelved,
        );
    }

    /// Shelves the condition until the alarm next goes inactive.
    pub fn one_shot_shelve(&self, address_space: &mut AddressSpace) -> StatusCode {
        if self.get_shelving_state(address_space) == ShelvingState::OneShotShelved {
            return StatusCode::BadConditionAlreadyShelved;
        }

        self.set_shelving_state(address_space, ShelvingState::OneShotShelved);
        self.set_unshelve_time(address_space, 0.0);
        self.recompute_suppressed_or_shelved(address_space);
        StatusCode::Good
    }

    /// Shelves the condition for the supplied duration in milliseconds.
    pub fn timed_shelve(
        &self,
        address_space: &mut AddressSpace,
        shelving_time_ms: f64,
    ) -> StatusCode {
        if shelving_time_ms <= 0.0 {
            return StatusCode::BadShelvingTimeOutOfRange;
        }
        if self.get_shelving_state(address_space) == ShelvingState::TimedShelved {
            return StatusCode::BadConditionAlreadyShelved;
        }

        self.set_shelving_state(address_space, ShelvingState::TimedShelved);
        self.set_unshelve_time(address_space, shelving_time_ms);
        self.recompute_suppressed_or_shelved(address_space);
        StatusCode::Good
    }

    /// Returns a shelved condition to Unshelved.
    pub fn unshelve(&self, address_space: &mut AddressSpace) -> StatusCode {
        if self.get_shelving_state(address_space) == ShelvingState::Unshelved {
            return StatusCode::BadConditionNotShelved;
        }

        self.set_shelving_state(address_space, ShelvingState::Unshelved);
        self.set_unshelve_time(address_space, 0.0);
        self.recompute_suppressed_or_shelved(address_space);
        StatusCode::Good
    }

    fn get_bool_value(&self, address_space: &AddressSpace, id: &NodeId) -> bool {
        if let Some(node) = address_space.find(id) {
            if let NodeType::Variable(ref var) = *node {
                if let Some(Variant::Boolean(b)) = var
                    .value(
                        opcua_types::TimestampsToReturn::Neither,
                        &opcua_types::NumericRange::None,
                        &opcua_types::DataEncoding::Binary,
                        0.0,
                    )
                    .value
                {
                    return b;
                }
            }
        };
        false
    }

    fn set_bool_value(&self, address_space: &mut AddressSpace, id: &NodeId, value: bool) {
        if let Some(mut node) = address_space.find_mut(id) {
            if let NodeType::Variable(ref mut var) = &mut *node {
                let _ = var.set_value(&opcua_types::NumericRange::None, Variant::from(value));
            }
        };
    }
}
