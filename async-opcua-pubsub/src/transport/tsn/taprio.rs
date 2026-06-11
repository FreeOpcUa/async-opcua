// tc taprio UDP fallback driver implementation

use std::io;
use std::process::Command;

/// Configuration settings for the taprio scheduler.
#[derive(Debug, Clone)]
pub struct TaprioConfig {
    /// Network interface name (e.g. "eth0")
    pub interface: String,
    /// Number of traffic classes
    pub num_tc: u32,
    /// Traffic class mapping
    pub map: Vec<u32>,
    /// Queue mapping per traffic class
    pub queues: Vec<String>,
    /// Base time offset
    pub base_time: u64,
    /// Cycle time in nanoseconds
    pub cycle_time: u64,
    /// Scheduler entry definitions
    pub sched_entries: Vec<String>,
}

/// A driver to configure the Linux `tc taprio` qdisc.
pub struct TaprioDriver {
    config: TaprioConfig,
}

impl TaprioDriver {
    /// Create a new TaprioDriver instance.
    pub fn new(config: TaprioConfig) -> Self {
        TaprioDriver { config }
    }

    /// Apply the taprio configuration to the network interface by shelling out to `tc`.
    pub fn apply(&self) -> io::Result<()> {
        let mut cmd = Command::new("tc");
        cmd.args(&[
            "qdisc",
            "replace",
            "dev",
            &self.config.interface,
            "parent",
            "root",
            "handle",
            "100:",
            "taprio",
            "num_tc",
            &self.config.num_tc.to_string(),
            "map",
        ]);

        for m in &self.config.map {
            cmd.arg(m.to_string());
        }

        cmd.arg("queues");
        for q in &self.config.queues {
            cmd.arg(q);
        }

        cmd.arg("base-time");
        cmd.arg(self.config.base_time.to_string());

        cmd.arg("cycle-time");
        cmd.arg(self.config.cycle_time.to_string());

        for entry in &self.config.sched_entries {
            // entry format: e.g. "sched-entry S 01 300000"
            // we split entry to pass as arguments
            for part in entry.split_whitespace() {
                cmd.arg(part);
            }
        }

        tracing::info!("Applying tc taprio configuration: {:?}", cmd);

        let output = cmd.output()?;
        if !output.status.success() {
            let err_msg = String::from_utf8_lossy(&output.stderr);
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("tc taprio command failed: {}", err_msg),
            ));
        }

        Ok(())
    }

    /// Query the current qdisc configuration for the interface.
    pub fn query(&self) -> io::Result<String> {
        let output = Command::new("tc")
            .args(&["qdisc", "show", "dev", &self.config.interface])
            .output()?;

        if !output.status.success() {
            let err_msg = String::from_utf8_lossy(&output.stderr);
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("tc qdisc query failed: {}", err_msg),
            ));
        }

        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    /// Clear the taprio qdisc configuration from the interface.
    pub fn clear(&self) -> io::Result<()> {
        let output = Command::new("tc")
            .args(&["qdisc", "del", "dev", &self.config.interface, "root"])
            .output()?;

        // If it's already deleted or doesn't exist, ignore the error.
        if !output.status.success() {
            let err_msg = String::from_utf8_lossy(&output.stderr);
            if !err_msg.contains("No such file or directory")
                && !err_msg.contains("Invalid argument")
            {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("tc qdisc delete failed: {}", err_msg),
                ));
            }
        }

        Ok(())
    }
}
