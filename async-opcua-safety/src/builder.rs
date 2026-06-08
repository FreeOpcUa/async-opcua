use crate::spdu::Spdu;

/// Builder for Safety Protocol Data Units (SPDU)
pub struct SpduBuilder {
    safety_data: Vec<u8>,
    sequence_number: u32,
    timestamp: u64,
}

impl SpduBuilder {
    /// Create a new builder with the given safety data
    pub fn new(safety_data: Vec<u8>) -> Self {
        Self {
            safety_data,
            sequence_number: 0,
            timestamp: 0,
        }
    }

    /// Set the sequence number
    pub fn with_sequence_number(mut self, seq: u32) -> Self {
        self.sequence_number = seq;
        self
    }

    /// Set the timestamp
    pub fn with_timestamp(mut self, ts: u64) -> Self {
        self.timestamp = ts;
        self
    }

    /// Build the SPDU with calculated CRC
    pub fn build(self) -> Spdu {
        let mut spdu = Spdu::new(self.safety_data, self.sequence_number, self.timestamp, 0);
        spdu.crc = crate::crc::calculate_crc(&spdu.to_bytes_for_crc());
        spdu
    }
}
