//! Utility for managing sequence numbers

use opcua_types::{Error, StatusCode};
use tracing::trace;

#[derive(Debug, Clone)]
/// Utility for managing sequence numbers
pub struct SequenceNumberHandle {
    is_legacy: bool,
    current_value: u32,
}

impl SequenceNumberHandle {
    /// Create a new sequence number handle
    /// Uses either legacy or non-legacy sequence numbers, see
    /// https://reference.opcfoundation.org/Core/Part6/v105/docs/6.7.2.4
    pub fn new(is_legacy: bool) -> Self {
        Self {
            is_legacy,
            current_value: if is_legacy { 1 } else { 0 },
        }
    }

    #[allow(unused)]
    pub(crate) fn new_at(is_legacy: bool, value: u32) -> Self {
        let max_value = if is_legacy { u32::MAX - 1024 } else { u32::MAX };
        Self {
            is_legacy,
            current_value: value % max_value,
        }
    }

    /// Get the maximum value of the sequence number.
    /// This is the maximum value the sequence number can have, after which it will overflow.
    pub fn max_value(&self) -> u32 {
        if self.is_legacy {
            u32::MAX - 1024
        } else {
            u32::MAX
        }
    }

    /// Get whether the sequence number handle uses legacy sequence numbers or not.
    pub fn is_legacy(&self) -> bool {
        self.is_legacy
    }

    pub(crate) fn set_is_legacy(&mut self, is_legacy: bool) {
        if is_legacy == self.is_legacy {
            return;
        }

        let old_min_value = self.min_value();
        self.is_legacy = is_legacy;
        if self.current_value > self.max_value() {
            // If the current value is greater than the max value, wrap around to the min value
            self.current_value = self.min_value() + (self.current_value - self.max_value() - 1);
        } else if self.current_value <= self.min_value() {
            self.current_value = self.min_value();
        // If we're at the min value, assume this is completely new, which is when this
        // method should generally be called, so set to the new min value.
        // This will typically happen when switching from legacy to non-legacy on the server.
        // The very first message from the client will inform the server of a non-legacy securitypolicy,
        // so the server needs to switch to non-legacy sequence numbers. Typically the channel will
        // not have sent any messages yet, so the sequence number will be at the min value.
        } else if self.current_value == old_min_value {
            self.current_value = self.min_value();
        }
    }

    /// Get the minimum value of the sequence number.
    pub fn min_value(&self) -> u32 {
        if self.is_legacy {
            1
        } else {
            0
        }
    }

    /// Get the current sequence number, which
    /// is the next value that will be used.
    pub fn current(&self) -> u32 {
        self.current_value
    }

    /// Set the value of the sequence number handle.
    pub fn set(&mut self, value: u32) {
        self.current_value = value;
    }

    /// Increment the sequence number by the given value.
    pub fn increment(&mut self, value: u32) {
        let remaining = self.max_value() - self.current_value;
        if remaining < value {
            // If the increment would overflow, wrap around to the min value
            self.current_value = self.min_value() + value - remaining - 1;
        } else {
            // Else just increment normally.
            self.current_value += value;
        }
    }

    /// Validate the incoming sequence number against the expected value, and increment the sequence number if valid.
    pub fn validate_and_increment(&mut self, incoming_sequence_number: u32) -> Result<(), Error> {
        let expected = self.current();
        if incoming_sequence_number != expected {
            // If the expected sequence number is the minimum value, and we are in legacy mode, then allow
            // any value less than 1024.
            // This is to handle the weird case in the OPC-UA standard stating that the
            // first sequence number after we wrap around from the max can be any value less than 1024.
            if self.is_legacy() && expected == self.min_value() && incoming_sequence_number < 1024 {
                self.set(incoming_sequence_number);
            } else {
                trace!(
                    "Expected sequence number {}, got {}",
                    expected,
                    incoming_sequence_number
                );
                return Err(Error::new(
                    StatusCode::BadSequenceNumberInvalid,
                    format!(
                        "Chunk sequence number of {incoming_sequence_number} is not the expected value of {expected}"
                    ),
                ));
            }
        }
        self.increment(1);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::SequenceNumberHandle;

    #[test]
    fn test_sequence_numbers() {
        let mut seq = SequenceNumberHandle::new(true);
        assert_eq!(seq.current(), 1);
        assert_eq!(seq.max_value(), u32::MAX - 1024);
        assert_eq!(seq.min_value(), 1);
        assert!(seq.is_legacy());
        seq.increment(1);
        assert_eq!(seq.current(), 2);

        seq.increment(1022);
        assert_eq!(seq.current(), 1024);
        seq.increment(u32::MAX - 2048);
        assert_eq!(seq.current(), u32::MAX - 1024);
        seq.increment(1);
        assert_eq!(seq.current(), 1);

        seq.increment(u32::MAX - 1026);
        assert_eq!(seq.current(), u32::MAX - 1025);
        seq.increment(3);
        assert_eq!(seq.current(), 2);
    }

    #[test]
    fn test_sequence_numbers_non_legacy() {
        let mut seq = SequenceNumberHandle::new(false);
        assert_eq!(seq.current(), 0);
        assert_eq!(seq.max_value(), u32::MAX);
        assert_eq!(seq.min_value(), 0);
        assert!(!seq.is_legacy());
        seq.increment(1);
        assert_eq!(seq.current(), 1);

        seq.increment(u32::MAX - 1);
        assert_eq!(seq.current(), u32::MAX);
        seq.increment(1);
        assert_eq!(seq.current(), 0);

        seq.increment(u32::MAX - 1);
        assert_eq!(seq.current(), u32::MAX - 1);
        seq.increment(3);
        assert_eq!(seq.current(), 1);
    }

    #[test]
    fn test_sequence_numbers_validate() {
        let mut seq = SequenceNumberHandle::new(true);
        assert_eq!(seq.current(), 1);
        assert!(seq.validate_and_increment(1).is_ok());
        assert_eq!(seq.current(), 2);
        assert!(seq.validate_and_increment(2).is_ok());
        assert_eq!(seq.current(), 3);
        assert!(seq.validate_and_increment(5).is_err());
        assert_eq!(seq.current(), 3);

        // Reset to initial conditions.
        seq.set(1);
        assert!(seq.validate_and_increment(50).is_ok());
        assert_eq!(seq.current(), 51);
        assert!(seq.validate_and_increment(50).is_err());
        assert_eq!(seq.current(), 51);
        assert!(seq.validate_and_increment(51).is_ok());
        assert_eq!(seq.current(), 52);

        // Overflow
        seq.set(u32::MAX - 1024);
        assert!(seq.validate_and_increment(u32::MAX - 1024).is_ok());
        assert_eq!(seq.current(), 1);
        assert!(seq.validate_and_increment(20).is_ok());
        assert_eq!(seq.current(), 21);
    }

    #[test]
    fn test_sequence_numbers_validate_non_legacy() {
        let mut seq = SequenceNumberHandle::new(false);
        assert_eq!(seq.current(), 0);
        assert!(seq.validate_and_increment(0).is_ok());
        assert_eq!(seq.current(), 1);
        assert!(seq.validate_and_increment(1).is_ok());
        assert_eq!(seq.current(), 2);
        assert!(seq.validate_and_increment(5).is_err());
        assert_eq!(seq.current(), 2);

        // Reset to initial conditions.
        seq.set(0);
        // Non-legacy mode does not allow setting arbitrary values less than 1024.
        assert!(seq.validate_and_increment(50).is_err());
        assert_eq!(seq.current(), 0);
        assert!(seq.validate_and_increment(0).is_ok());
        assert_eq!(seq.current(), 1);

        // Overflow
        seq.set(u32::MAX);
        assert!(seq.validate_and_increment(u32::MAX).is_ok());
        assert_eq!(seq.current(), 0);
        assert!(seq.validate_and_increment(0).is_ok());
        assert_eq!(seq.current(), 1);
    }
}
