//! Alarms and Conditions (Part 9) module for the OPC-UA server.

pub mod dispatch;
pub mod methods;
pub mod refresh_events;
pub mod registry;
pub mod state_machine;
pub mod transitions;

pub use dispatch::{dispatch_alarm_event, ServerAlarmEvent};
#[cfg(feature = "generated-address-space")]
pub use methods::register_condition_methods;
pub use methods::{AlarmMethodHandler, ConditionRefreshHandler};
pub use refresh_events::{RefreshEndEvent, RefreshStartEvent};
pub use registry::ConditionRegistry;
pub use state_machine::ConditionStateMachine;
