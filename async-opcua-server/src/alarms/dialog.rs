//! DialogConditionType address-space wiring and response handling.

use crate::address_space::{AddressSpace, VariableBuilder};
use crate::alarms::replace_condition_type_definition;
use crate::alarms::state_machine::ConditionStateMachine;
use opcua_core::events::AlarmEvent;
use opcua_core::sync::RwLock;
use opcua_nodes::NodeType;
use opcua_types::{
    DataTypeId, DateTime, LocalizedText, NodeId, StatusCode, VariableTypeId, Variant,
    VariantScalarTypeId,
};
use std::collections::HashMap;
use std::sync::Arc;

const DIALOG_CONDITION_TYPE_ID: u32 = 2830;
const ACTIVE_DIALOG_SEVERITY: u16 = 100;
const INACTIVE_DIALOG_SEVERITY: u16 = 0;

/// Address-space nodes and runtime state for a Part 9 DialogConditionType instance.
#[derive(Debug, Clone)]
pub struct DialogCondition {
    /// Base condition lifecycle state machine.
    pub condition: ConditionStateMachine,
    /// DialogState TwoStateVariableType node.
    pub dialog_state_id: NodeId,
    /// LastResponse property node.
    pub last_response_id: NodeId,
    dialog_state_id_id: NodeId,
    prompt: LocalizedText,
    response_options: Vec<LocalizedText>,
}

impl DialogCondition {
    /// Returns the base condition state machine for registry and refresh integration.
    #[must_use]
    pub fn condition_state_machine(&self) -> ConditionStateMachine {
        self.condition.clone()
    }

    /// Creates a DialogConditionType instance and its mandatory dialog components.
    #[allow(clippy::too_many_arguments)]
    pub fn create_in_address_space(
        address_space: &mut AddressSpace,
        ns: u16,
        device: &str,
        name: &str,
        source_node_id: NodeId,
        prompt: LocalizedText,
        response_options: Vec<LocalizedText>,
        default_response: i32,
        ok_response: i32,
        cancel_response: i32,
    ) -> Self {
        let condition = ConditionStateMachine::create_in_address_space(
            address_space,
            device,
            name,
            source_node_id,
            name,
        );

        replace_condition_type_definition(
            address_space,
            &condition.condition_id,
            NodeId::new(0, DIALOG_CONDITION_TYPE_ID),
        );
        condition.set_active(address_space, false);
        condition.set_acked(address_space, true);
        condition.set_confirmed(address_space, true);
        condition.set_retain(address_space, false);
        condition.set_severity(address_space, INACTIVE_DIALOG_SEVERITY);
        condition.set_message(address_space, prompt.clone());

        let base_s = format!("Alarm_{}_{}", device, name);
        let dialog_state_id = NodeId::new(ns, format!("{}_DialogState", base_s));
        let dialog_state_id_id = NodeId::new(ns, format!("{}_DialogState_Id", base_s));
        let dialog_state_true_state_id =
            NodeId::new(ns, format!("{}_DialogState_TrueState", base_s));
        let dialog_state_false_state_id =
            NodeId::new(ns, format!("{}_DialogState_FalseState", base_s));
        let prompt_id = NodeId::new(ns, format!("{}_Prompt", base_s));
        let response_option_set_id = NodeId::new(ns, format!("{}_ResponseOptionSet", base_s));
        let default_response_id = NodeId::new(ns, format!("{}_DefaultResponse", base_s));
        let ok_response_id = NodeId::new(ns, format!("{}_OkResponse", base_s));
        let cancel_response_id = NodeId::new(ns, format!("{}_CancelResponse", base_s));
        let last_response_id = NodeId::new(ns, format!("{}_LastResponse", base_s));

        VariableBuilder::new(&dialog_state_id, "DialogState", "DialogState")
            .data_type(DataTypeId::LocalizedText)
            .has_type_definition(VariableTypeId::TwoStateVariableType)
            .value(dialog_state_text(false))
            .writable()
            .component_of(condition.condition_id.clone())
            .insert(address_space);

        VariableBuilder::new(&dialog_state_id_id, "Id", "Id")
            .data_type(DataTypeId::Boolean)
            .has_type_definition(VariableTypeId::PropertyType)
            .value(false)
            .writable()
            .property_of(dialog_state_id.clone())
            .insert(address_space);

        add_localized_text_property(
            address_space,
            &dialog_state_true_state_id,
            &dialog_state_id,
            "TrueState",
            dialog_state_text(true),
        );
        add_localized_text_property(
            address_space,
            &dialog_state_false_state_id,
            &dialog_state_id,
            "FalseState",
            dialog_state_text(false),
        );
        add_localized_text_property(
            address_space,
            &prompt_id,
            &condition.condition_id,
            "Prompt",
            prompt.clone(),
        );
        add_localized_text_array_property(
            address_space,
            &response_option_set_id,
            &condition.condition_id,
            "ResponseOptionSet",
            &response_options,
        );
        add_i32_property(
            address_space,
            &default_response_id,
            &condition.condition_id,
            "DefaultResponse",
            default_response,
        );
        add_i32_property(
            address_space,
            &last_response_id,
            &condition.condition_id,
            "LastResponse",
            default_response,
        );
        add_i32_property(
            address_space,
            &ok_response_id,
            &condition.condition_id,
            "OkResponse",
            ok_response,
        );
        add_i32_property(
            address_space,
            &cancel_response_id,
            &condition.condition_id,
            "CancelResponse",
            cancel_response,
        );

        Self {
            condition,
            dialog_state_id,
            last_response_id,
            dialog_state_id_id,
            prompt,
            response_options,
        }
    }

    /// Activates the dialog and returns the event for the new active state.
    pub fn activate(&self, address_space: &mut AddressSpace) -> AlarmEvent {
        self.set_dialog_state_active(address_space, true);
        self.condition.set_active(address_space, true);
        self.condition.set_acked(address_space, true);
        self.condition.set_confirmed(address_space, true);
        self.condition.set_retain(address_space, true);
        self.condition
            .set_severity(address_space, ACTIVE_DIALOG_SEVERITY);
        self.condition
            .set_message(address_space, self.prompt.clone());

        let event_id = uuid::Uuid::new_v4().as_bytes().to_vec();
        self.condition.set_current_event_id(&event_id);
        self.build_event(address_space, event_id, self.prompt.clone(), true, true)
    }

    /// Selects a response option and ends the dialog.
    pub fn respond(
        &self,
        address_space: &mut AddressSpace,
        selected_response: i32,
    ) -> Result<AlarmEvent, StatusCode> {
        let index = self.validate_response(address_space, selected_response)?;
        let message = self.response_options[index].clone();
        Ok(self.complete_response(address_space, selected_response, message))
    }

    /// Selects a response option, applies a comment, and ends the dialog.
    pub fn respond2(
        &self,
        address_space: &mut AddressSpace,
        selected_response: i32,
        comment: LocalizedText,
    ) -> Result<AlarmEvent, StatusCode> {
        self.validate_response(address_space, selected_response)?;
        Ok(self.complete_response(address_space, selected_response, comment))
    }

    /// Gets whether DialogState/Id is active.
    #[must_use]
    pub fn get_dialog_state_active(&self, address_space: &AddressSpace) -> bool {
        read_bool_value(address_space, &self.dialog_state_id_id)
    }

    /// Sets DialogState and DialogState/Id.
    pub fn set_dialog_state_active(&self, address_space: &mut AddressSpace, active: bool) {
        set_variable_value(
            address_space,
            &self.dialog_state_id,
            Variant::from(dialog_state_text(active)),
        );
        set_variable_value(
            address_space,
            &self.dialog_state_id_id,
            Variant::from(active),
        );
    }

    fn validate_response(
        &self,
        address_space: &AddressSpace,
        selected_response: i32,
    ) -> Result<usize, StatusCode> {
        if !self.get_dialog_state_active(address_space) {
            return Err(StatusCode::BadDialogNotActive);
        }

        if selected_response < 0 {
            return Err(StatusCode::BadDialogResponseInvalid);
        }

        let index = selected_response as usize;
        if index >= self.response_options.len() {
            return Err(StatusCode::BadDialogResponseInvalid);
        }

        Ok(index)
    }

    fn complete_response(
        &self,
        address_space: &mut AddressSpace,
        selected_response: i32,
        message: LocalizedText,
    ) -> AlarmEvent {
        set_variable_value(
            address_space,
            &self.last_response_id,
            Variant::from(selected_response),
        );
        self.set_dialog_state_active(address_space, false);
        self.condition.set_active(address_space, false);
        self.condition.set_acked(address_space, true);
        self.condition.set_confirmed(address_space, true);
        self.condition.set_retain(address_space, false);
        self.condition
            .set_severity(address_space, INACTIVE_DIALOG_SEVERITY);
        self.condition.set_message(address_space, message.clone());

        let event_id = uuid::Uuid::new_v4().as_bytes().to_vec();
        self.condition.set_current_event_id(&event_id);
        self.build_event(address_space, event_id, message, false, false)
    }

    fn build_event(
        &self,
        address_space: &AddressSpace,
        event_id: Vec<u8>,
        message: LocalizedText,
        active: bool,
        retain: bool,
    ) -> AlarmEvent {
        AlarmEvent {
            event_id,
            event_type: NodeId::new(0, DIALOG_CONDITION_TYPE_ID),
            source_node: self.condition.source_node_id.clone(),
            source_name: self.condition.condition_name.clone(),
            time: DateTime::now(),
            message,
            severity: self.condition.get_severity(address_space),
            condition_id: self.condition.condition_id.clone(),
            branch_id: NodeId::null(),
            condition_name: self.condition.condition_name.clone(),
            active_state: active,
            acked_state: true,
            confirmed_state: true,
            retain,
        }
    }
}

/// App-populated set of dialogs available to Respond and Respond2 method handlers.
#[derive(Debug, Clone)]
pub struct DialogRegistry {
    dialogs: Arc<RwLock<HashMap<NodeId, DialogCondition>>>,
}

impl Default for DialogRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl DialogRegistry {
    /// Creates an empty dialog registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            dialogs: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Registers or replaces a dialog by its condition id.
    pub fn register(&self, dialog: DialogCondition) {
        self.dialogs
            .write()
            .insert(dialog.condition.condition_id.clone(), dialog);
    }

    /// Returns a registered dialog by condition id.
    #[must_use]
    pub fn get(&self, condition_id: &NodeId) -> Option<DialogCondition> {
        self.dialogs.read().get(condition_id).cloned()
    }
}

fn dialog_state_text(active: bool) -> LocalizedText {
    LocalizedText::new("en", if active { "Active" } else { "Inactive" })
}

fn add_localized_text_property(
    address_space: &mut AddressSpace,
    node_id: &NodeId,
    parent_id: &NodeId,
    name: &str,
    value: LocalizedText,
) {
    VariableBuilder::new(node_id, name, name)
        .data_type(DataTypeId::LocalizedText)
        .has_type_definition(VariableTypeId::PropertyType)
        .value(value)
        .writable()
        .property_of(parent_id.clone())
        .insert(address_space);
}

fn add_localized_text_array_property(
    address_space: &mut AddressSpace,
    node_id: &NodeId,
    parent_id: &NodeId,
    name: &str,
    value: &[LocalizedText],
) {
    let values = value.iter().cloned().map(Variant::from).collect::<Vec<_>>();

    VariableBuilder::new(node_id, name, name)
        .data_type(DataTypeId::LocalizedText)
        .has_type_definition(VariableTypeId::PropertyType)
        .value((VariantScalarTypeId::LocalizedText, values))
        .writable()
        .property_of(parent_id.clone())
        .insert(address_space);
}

fn add_i32_property(
    address_space: &mut AddressSpace,
    node_id: &NodeId,
    parent_id: &NodeId,
    name: &str,
    value: i32,
) {
    VariableBuilder::new(node_id, name, name)
        .data_type(DataTypeId::Int32)
        .has_type_definition(VariableTypeId::PropertyType)
        .value(value)
        .writable()
        .property_of(parent_id.clone())
        .insert(address_space);
}

fn read_bool_value(address_space: &AddressSpace, id: &NodeId) -> bool {
    if let Some(node) = address_space.find(id) {
        if let NodeType::Variable(ref var) = *node {
            if let Some(Variant::Boolean(value)) = var
                .value(
                    opcua_types::TimestampsToReturn::Neither,
                    &opcua_types::NumericRange::None,
                    &opcua_types::DataEncoding::Binary,
                    0.0,
                )
                .value
            {
                return value;
            }
        }
    };
    false
}

fn set_variable_value(address_space: &mut AddressSpace, id: &NodeId, value: Variant) {
    if let Some(mut node) = address_space.find_mut(id) {
        if let NodeType::Variable(ref mut var) = &mut *node {
            let _ = var.set_value(&opcua_types::NumericRange::None, value);
        }
    };
}
