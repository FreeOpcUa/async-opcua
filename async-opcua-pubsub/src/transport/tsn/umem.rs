// UMEM mapping for AF_XDP raw sockets

use xsk_rs::config::UmemConfig;

/// A structure representing a UMEM mapping.
pub struct UmemMapping {
    config: UmemConfig,
    #[allow(dead_code)]
    frame_count: u32,
}

impl UmemMapping {
    /// Create a new UMEM mapping configuration.
    pub fn new(frame_count: u32) -> Self {
        // Retrieve the default configuration from the crate.
        let config = UmemConfig::default();

        UmemMapping {
            config,
            frame_count,
        }
    }

    /// Retrieve the underling config.
    pub fn config(&self) -> &UmemConfig {
        &self.config
    }
}
