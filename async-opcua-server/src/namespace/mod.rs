//! Server namespace management module.

pub mod init;

pub use init::{
    register_alarm_condition, register_discrete_alarm, register_limit_alarm,
    register_limit_alarm_checked,
};
