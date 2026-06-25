//! Alarms and Conditions (Part 9) module for the OPC-UA server.

pub mod discrete;
pub mod dispatch;
pub mod limit;
pub mod methods;
pub mod refresh_events;
pub mod registry;
pub mod state_machine;
pub mod transitions;

pub use discrete::{DiscreteAlarm, DiscreteAlarmKind};
pub use dispatch::{dispatch_alarm_event, ServerAlarmEvent};
pub use limit::{
    ActiveLimits, LimitAlarm, LimitConfig, LimitDef, LimitEvaluator, LimitLevel, LimitMode,
    LimitOutcome, NonExclusiveState,
};
#[cfg(feature = "generated-address-space")]
pub use methods::register_condition_methods;
pub use methods::{AlarmMethodHandler, ConditionRefreshHandler};
pub use refresh_events::{RefreshEndEvent, RefreshStartEvent};
pub use registry::ConditionRegistry;
pub use state_machine::{ConditionStateMachine, ShelvingState};
