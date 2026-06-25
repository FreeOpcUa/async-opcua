//! Alarms and Conditions (Part 9) module for the OPC-UA server.

use crate::address_space::AddressSpace;
use opcua_types::{NodeId, ReferenceTypeId};

pub mod dialog;
pub mod discrete;
pub mod dispatch;
pub mod limit;
pub mod methods;
pub mod refresh_events;
pub mod registry;
pub mod state_machine;
pub mod transitions;

const ALARM_CONDITION_TYPE_ID: u32 = 2915;

pub(crate) fn replace_condition_type_definition(
    address_space: &mut AddressSpace,
    condition_id: &NodeId,
    new_type: NodeId,
) {
    let old_type = NodeId::new(0, ALARM_CONDITION_TYPE_ID);
    let reference_type = NodeId::from(ReferenceTypeId::HasTypeDefinition);

    address_space.delete_reference(condition_id, &old_type, &reference_type);
    address_space.insert_reference(condition_id, &new_type, ReferenceTypeId::HasTypeDefinition);
}

pub use dialog::{DialogCondition, DialogRegistry};
pub use discrete::{DiscreteAlarm, DiscreteAlarmKind};
pub use dispatch::{dispatch_alarm_event, ServerAlarmEvent};
pub use limit::{
    read_eurange, ActiveLimits, LimitAlarm, LimitConfig, LimitDef, LimitEvaluator, LimitLevel,
    LimitMode, LimitOutcome, NonExclusiveState,
};
#[cfg(feature = "generated-address-space")]
pub use methods::{register_condition_methods, register_dialog_condition_methods};
pub use methods::{AlarmMethodHandler, ConditionRefreshHandler};
pub use refresh_events::{RefreshEndEvent, RefreshStartEvent};
pub use registry::ConditionRegistry;
pub use state_machine::{Branch, ConditionStateMachine, ShelvingState};
