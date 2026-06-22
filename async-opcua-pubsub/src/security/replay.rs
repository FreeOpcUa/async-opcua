//! Subscriber anti-replay window for secured PubSub NetworkMessages.

use opcua_types::{Error, StatusCode};

const WINDOW: u16 = 64;
const REPLAY_ERROR: &str = "replayed or stale PubSub NetworkMessage sequence number";

/// Sliding-window anti-replay state for a PubSub security token epoch.
#[derive(Debug, Clone, Default)]
pub struct ReplayWindow {
    current_token: Option<u32>,
    highest: u16,
    bitmap: u64,
}

impl ReplayWindow {
    /// Creates an empty replay window.
    pub fn new() -> Self {
        Self::default()
    }

    /// Checks and records a NetworkMessage sequence number for `token_id`.
    pub fn check(&mut self, token_id: u32, sequence_number: u16) -> Result<(), Error> {
        if self.current_token != Some(token_id) {
            self.current_token = Some(token_id);
            self.highest = sequence_number;
            self.bitmap = 1;
            return Ok(());
        }

        let ahead = sequence_number.wrapping_sub(self.highest);
        let behind = self.highest.wrapping_sub(sequence_number);

        if ahead != 0 && ahead <= u16::MAX / 2 {
            if ahead >= WINDOW {
                self.bitmap = 0;
            } else {
                self.bitmap <<= u32::from(ahead);
            }
            self.bitmap |= 1;
            self.highest = sequence_number;
            return Ok(());
        }

        if behind >= WINDOW {
            return Err(replay_error());
        }

        // ponytail: WINDOW=64 is the reordering tolerance ceiling; widen only if a deployment needs it.
        let bit = 1u64 << u32::from(behind);
        if self.bitmap & bit != 0 {
            return Err(replay_error());
        }

        self.bitmap |= bit;
        Ok(())
    }
}

fn replay_error() -> Error {
    Error::new(StatusCode::BadSecurityChecksFailed, REPLAY_ERROR)
}
