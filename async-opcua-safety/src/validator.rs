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

    /// Validate the SPDU against CRC, sequence number, and timeout.
    ///
    /// Safety / threat model (OPC UA Part 15, IEC 61784-3 "black channel"):
    /// - The CRC is an UNKEYED integrity check (corruption detection over a black channel). It is NOT a
    ///   MAC; authenticity/confidentiality are the underlying secure channel's responsibility. This is
    ///   by design — do not treat the CRC as authentication.
    /// - Sequence validation is intentionally STRICT and FAIL-SAFE: any gap/reorder/replay is rejected
    ///   (`SequenceMismatch`) and the expected number is NOT advanced. Recovery from a gap is supposed to
    ///   happen via the SafetyConsumer re-synchronisation (Monitoring-Number request) handshake, which a
    ///   higher layer drives — NOT by silently accepting out-of-sequence SPDUs here. Do NOT "fix" this
    ///   into a tolerant sliding window: for a SIL-3 channel that would be a safety regression (the
    ///   permanent-reject-until-resync behaviour is the safe state). The re-sync handshake itself is a
    ///   deferred Part-15 feature, tracked separately.
    pub fn validate(&mut self, spdu: &Spdu, current_time: u64) -> Result<(), SafetyError> {
        // 1. Validate CRC (black-channel corruption check; see method docs — not a MAC).
        let computed_crc = crate::crc::calculate_crc(&spdu.to_bytes_for_crc());
        if computed_crc != spdu.crc {
            return Err(SafetyError::InvalidCrc);
        }

        // 2. Validate Sequence Number (strict + fail-safe by design; see method docs).
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
