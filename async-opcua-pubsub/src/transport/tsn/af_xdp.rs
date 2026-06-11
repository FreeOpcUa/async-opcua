// AF_XDP transport stub for TSN low‑latency raw sockets

use std::collections::VecDeque;
use std::io;
use std::sync::Mutex;
use xsk_rs::socket::Socket;

/// Structure representing an AF_XDP socket with simulated Tx/Rx queues.
pub struct AfXdp {
    /// Name of the network interface (e.g. "eth0").
    interface_name: String,
    /// Underlying Socket handle – currently unused and kept as an `Option`.
    // Held for the future hardware-backed implementation; the simulated
    // loopback never reads it.
    #[allow(dead_code)]
    socket: Option<Socket>,
    /// Memory queue representing the Tx ring.
    tx_queue: Mutex<VecDeque<Vec<u8>>>,
    /// Memory queue representing the Rx ring.
    rx_queue: Mutex<VecDeque<Vec<u8>>>,
}

impl AfXdp {
    /// Create a new `AfXdp` for the given network interface.
    pub fn new(interface: &str) -> Self {
        AfXdp {
            interface_name: interface.to_string(),
            socket: None,
            tx_queue: Mutex::new(VecDeque::new()),
            rx_queue: Mutex::new(VecDeque::new()),
        }
    }

    /// Transmit queue (Tx) dispatch implementation – pushes packet to the Tx queue and loopbacks.
    pub fn send(&self, buf: &[u8]) -> Result<(), io::Error> {
        tracing::debug!(
            "AF_XDP [{}] Tx dispatch: sending {} bytes",
            self.interface_name,
            buf.len()
        );
        self.tx_queue.lock().unwrap().push_back(buf.to_vec());

        // Loopback simulation for local/testing routing
        self.rx_queue.lock().unwrap().push_back(buf.to_vec());
        Ok(())
    }

    /// Receive queue (Rx) polling implementation – retrieves received packets from the Rx queue.
    pub fn recv(&self) -> Result<Vec<u8>, io::Error> {
        if let Some(buf) = self.rx_queue.lock().unwrap().pop_front() {
            tracing::debug!(
                "AF_XDP [{}] Rx poll: received {} bytes",
                self.interface_name,
                buf.len()
            );
            Ok(buf)
        } else {
            Ok(Vec::new())
        }
    }
}
