//! Alarms and Conditions (Part 9) module for the OPC-UA client.

pub mod client;

pub use client::{get_alarm_event_select_clauses, parse_alarm_event};
