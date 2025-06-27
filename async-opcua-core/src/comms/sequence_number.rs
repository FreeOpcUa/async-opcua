//! Utility for managing sequence numbers

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
        self.is_legacy = is_legacy;
        if self.current_value > self.max_value() {
            // If the current value is greater than the max value, wrap around to the min value
            self.current_value = self.min_value() + (self.current_value - self.max_value() - 1);
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
    pub(crate) fn current(&self) -> u32 {
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
}
