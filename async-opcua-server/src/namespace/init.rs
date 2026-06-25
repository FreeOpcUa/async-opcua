//! Server namespace initializer.
//! Provides helper functions to register Alarm Conditions and associate their callbacks in the node manager.

use crate::address_space::AddressSpace;
use crate::alarms::{
    ConditionStateMachine, DiscreteAlarm, DiscreteAlarmKind, LimitAlarm, LimitConfig, LimitMode,
};
use opcua_types::{MethodId, NodeId, ReferenceTypeId, Variant};
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

/// Registers a new LimitAlarm condition and exposes the standard Acknowledge/Confirm methods.
pub fn register_limit_alarm(
    address_space: &Arc<opcua_core::sync::RwLock<AddressSpace>>,
    _node_manager: &crate::node_manager::memory::SimpleNodeManager,
    device: &str,
    alarm_name: &str,
    source_node_id: NodeId,
    cfg: LimitConfig,
) -> LimitAlarm {
    let alarm = {
        let mut space = opcua_core::trace_write_lock!(address_space);
        let ns = 2;

        match cfg.mode {
            LimitMode::Exclusive => LimitAlarm::create_exclusive_in_address_space(
                &mut space,
                ns,
                device,
                alarm_name,
                source_node_id,
                cfg,
            ),
            LimitMode::NonExclusive => LimitAlarm::create_non_exclusive_in_address_space(
                &mut space,
                ns,
                device,
                alarm_name,
                source_node_id,
                cfg,
            ),
        }
    };

    {
        let mut space = opcua_core::trace_write_lock!(address_space);
        space.insert_reference(
            &alarm.condition.condition_id,
            &MethodId::AcknowledgeableConditionType_Acknowledge.into(),
            ReferenceTypeId::HasComponent,
        );
        space.insert_reference(
            &alarm.condition.condition_id,
            &MethodId::AcknowledgeableConditionType_Confirm.into(),
            ReferenceTypeId::HasComponent,
        );
    }

    alarm
}

/// Registers a new DiscreteAlarm condition and exposes the standard Acknowledge/Confirm methods.
pub fn register_discrete_alarm(
    address_space: &Arc<opcua_core::sync::RwLock<AddressSpace>>,
    _node_manager: &crate::node_manager::memory::SimpleNodeManager,
    device: &str,
    alarm_name: &str,
    source_node_id: NodeId,
    kind: DiscreteAlarmKind,
    normal: Variant,
) -> DiscreteAlarm {
    let alarm = {
        let mut space = opcua_core::trace_write_lock!(address_space);
        let ns = 2;

        DiscreteAlarm::create_in_address_space(
            &mut space,
            ns,
            device,
            alarm_name,
            source_node_id,
            kind,
            normal,
        )
    };

    {
        let mut space = opcua_core::trace_write_lock!(address_space);
        space.insert_reference(
            &alarm.condition.condition_id,
            &MethodId::AcknowledgeableConditionType_Acknowledge.into(),
            ReferenceTypeId::HasComponent,
        );
        space.insert_reference(
            &alarm.condition.condition_id,
            &MethodId::AcknowledgeableConditionType_Confirm.into(),
            ReferenceTypeId::HasComponent,
        );
    }

    alarm
}
