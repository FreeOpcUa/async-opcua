//! Alarms and Conditions (Part 9) module for the OPC-UA server.

pub mod dispatch;
pub mod methods;
pub mod state_machine;
pub mod transitions;

pub use dispatch::{dispatch_alarm_event, ServerAlarmEvent};
pub use methods::AlarmMethodHandler;
pub use state_machine::ConditionStateMachine;
