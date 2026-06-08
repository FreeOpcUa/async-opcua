/// Safety Protocol Data Unit (SPDU) containing safety-critical data and validation fields.
#[derive(Debug, Clone, PartialEq)]
pub struct Spdu {
    /// The actual safety-critical data payload.
    pub safety_data: Vec<u8>,
    /// Monotonically increasing sequence number to detect reordering, loss, or insertion.
    pub sequence_number: u32,
    /// Transmission timestamp to verify latency bounds.
    pub timestamp: u64,
    /// 32-bit CRC checksum protecting all fields.
    pub crc: u32,
}

impl Spdu {
    /// Create a new SPDU instance.
    pub fn new(safety_data: Vec<u8>, sequence_number: u32, timestamp: u64, crc: u32) -> Self {
        Self {
            safety_data,
            sequence_number,
            timestamp,
            crc,
        }
    }

    /// Serialize the SPDU fields (excluding the CRC itself) into a byte buffer for CRC calculation.
    pub fn to_bytes_for_crc(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.safety_data.len() + 12);
        bytes.extend_from_slice(&self.safety_data);
        bytes.extend_from_slice(&self.sequence_number.to_be_bytes());
        bytes.extend_from_slice(&self.timestamp.to_be_bytes());
        bytes
    }
}
