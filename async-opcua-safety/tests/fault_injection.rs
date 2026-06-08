//! Fault injection integration tests for the OPC-UA Safety Profile (Part 15).
//!
//! This test asserts that the SafetyValidator rejects corrupted, delayed,
//! or out-of-order SPDUs.

use async_opcua_safety::{SpduBuilder, SafetyValidator, SafetyError, Spdu};

#[test]
fn test_valid_spdu_passes() {
    let safety_data = vec![0xDE, 0xAD, 0xBE, 0xEF];
    let spdu = SpduBuilder::new(safety_data)
        .with_sequence_number(1)
        .with_timestamp(100)
        .build();

    let mut validator = SafetyValidator::new(1, 50);
    // A valid SPDU with matching seq, timestamp within limit, and valid CRC should pass.
    assert!(validator.validate(&spdu, 120).is_ok());
}

#[test]
fn test_invalid_crc_rejected() {
    let safety_data = vec![0xDE, 0xAD, 0xBE, 0xEF];
    // Build a valid SPDU
    let spdu = SpduBuilder::new(safety_data)
        .with_sequence_number(1)
        .with_timestamp(100)
        .build();

    // Corrupt the CRC by changing it
    let corrupted_spdu = Spdu::new(
        spdu.safety_data.clone(),
        spdu.sequence_number,
        spdu.timestamp,
        spdu.crc ^ 0xFFFFFFFF,
    );

    let mut validator = SafetyValidator::new(1, 50);
    // The validator MUST detect the invalid CRC.
    assert_eq!(
        validator.validate(&corrupted_spdu, 120),
        Err(SafetyError::InvalidCrc)
    );
}

#[test]
fn test_sequence_mismatch_rejected() {
    let safety_data = vec![0xDE, 0xAD, 0xBE, 0xEF];
    let spdu = SpduBuilder::new(safety_data)
        .with_sequence_number(5) // Sent seq 5, but validator expects 1
        .with_timestamp(100)
        .build();

    let mut validator = SafetyValidator::new(1, 50);
    // The validator MUST reject out-of-order sequence numbers.
    assert_eq!(
        validator.validate(&spdu, 120),
        Err(SafetyError::SequenceMismatch)
    );
}

#[test]
fn test_timestamp_delay_rejected() {
    let safety_data = vec![0xDE, 0xAD, 0xBE, 0xEF];
    let spdu = SpduBuilder::new(safety_data)
        .with_sequence_number(1)
        .with_timestamp(100)
        .build();

    let mut validator = SafetyValidator::new(1, 50);
    // At time 160, elapsed time is 60, which exceeds max_delay of 50.
    // The validator MUST reject delayed messages.
    assert_eq!(
        validator.validate(&spdu, 160),
        Err(SafetyError::Timeout)
    );
}
