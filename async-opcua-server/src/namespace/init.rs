//! Server namespace initializer.
//! Provides helper functions to register Alarm Conditions and associate their callbacks in the node manager.

use crate::address_space::AddressSpace;
use crate::alarms::ConditionStateMachine;
use opcua_types::{MethodId, NodeId, ReferenceTypeId};
use std::sync::Arc;

/// Registers a new Alarm Condition state machine and exposes the standard Acknowledge/Confirm methods.
pub fn register_alarm_condition(
    address_space: &Arc<opcua_core::sync::RwLock<AddressSpace>>,
    _node_manager: &crate::node_manager::memory::SimpleNodeManager,
    device: &str,
    alarm_type: &str,
    source_node_id: NodeId,
    condition_name: &str,
) -> ConditionStateMachine {
    // 1. Create the state machine nodes in the Address Space
    let state_machine = {
        let mut space = opcua_core::trace_write_lock!(address_space);
        ConditionStateMachine::create_in_address_space(
            &mut space,
            device,
            alarm_type,
            source_node_id,
            condition_name,
        )
    };

    // 2. Expose the standard shared Acknowledge/Confirm method declarations on the condition.
    {
        let mut space = opcua_core::trace_write_lock!(address_space);
        space.insert_reference(
            &state_machine.condition_id,
            &MethodId::AcknowledgeableConditionType_Acknowledge.into(),
            ReferenceTypeId::HasComponent,
        );
        space.insert_reference(
            &state_machine.condition_id,
            &MethodId::AcknowledgeableConditionType_Confirm.into(),
            ReferenceTypeId::HasComponent,
        );
    }

    state_machine
}
