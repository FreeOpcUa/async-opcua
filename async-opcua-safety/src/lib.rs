//! SIL 3 OPC-UA Safety Profile (Part 15) implementation

/// Safety Protocol Data Unit (SPDU) definition
pub mod spdu;

/// SIL 3 CRC calculation module
pub mod crc;

/// SpduBuilder for constructing SPDUs
pub mod builder;

/// SafetyValidator for validating SPDUs against safety constraints
pub mod validator;

pub use builder::SpduBuilder;
pub use crc::calculate_crc;
pub use spdu::Spdu;
pub use validator::{SafetyError, SafetyValidator};
