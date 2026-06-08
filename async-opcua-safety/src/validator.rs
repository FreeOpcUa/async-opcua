use crate::spdu::Spdu;

/// Safety validation error types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SafetyError {
    /// The CRC checksum did not match the expected value
    InvalidCrc,
    /// The sequence number did not match the expected sequence number
    SequenceMismatch,
    /// The packet timestamp exceeded the maximum allowed delay
    Timeout,
}

/// Safety validator targeting SIL 3 requirements
pub struct SafetyValidator {
    expected_sequence_number: u32,
    max_delay: u64,
}

impl SafetyValidator {
    /// Create a new SafetyValidator
    pub fn new(start_seq: u32, max_delay: u64) -> Self {
        Self {
            expected_sequence_number: start_seq,
            max_delay,
        }
    }

    /// Set the expected sequence number manually
    pub fn set_expected_sequence_number(&mut self, seq: u32) {
        self.expected_sequence_number = seq;
    }

    /// Retrieve the expected sequence number
    pub fn expected_sequence_number(&self) -> u32 {
        self.expected_sequence_number
    }

    /// Validate the SPDU against CRC, sequence number, and timeout
    pub fn validate(&mut self, spdu: &Spdu, current_time: u64) -> Result<(), SafetyError> {
        // 1. Validate CRC
        let computed_crc = crate::crc::calculate_crc(&spdu.to_bytes_for_crc());
        if computed_crc != spdu.crc {
            return Err(SafetyError::InvalidCrc);
        }

        // 2. Validate Sequence Number
        if spdu.sequence_number != self.expected_sequence_number {
            return Err(SafetyError::SequenceMismatch);
        }

        // 3. Validate Timeout
        let delay = if current_time < spdu.timestamp {
            // Under flow or future packet, fail safety checks if discrepancy is too high
            if spdu.timestamp - current_time > self.max_delay {
                return Err(SafetyError::Timeout);
            }
            0
        } else {
            current_time - spdu.timestamp
        };

        if delay > self.max_delay {
            return Err(SafetyError::Timeout);
        }

        // If all validation checks pass, increment the expected sequence number for the next packet
        self.expected_sequence_number = self.expected_sequence_number.wrapping_add(1);

        Ok(())
    }
}
