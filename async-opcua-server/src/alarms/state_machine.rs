//! Condition State Machine implementation.
//! Manages active alarms, EnabledState, ActiveState, AckedState, and ConfirmedState in the AddressSpace.

use crate::address_space::{AddressSpace, ObjectBuilder, VariableBuilder};
use opcua_nodes::NodeType;
use opcua_types::{LocalizedText, NodeId, Variant};

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
            .value(true)
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
        }
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
