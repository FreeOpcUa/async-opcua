//! CLI parser implementation using `clap` for SPDU encoding and decoding/validation.

use clap::{Parser, Subcommand};
use crate::builder::SpduBuilder;
use crate::validator::{SafetyValidator, SafetyError};
use crate::spdu::Spdu;

/// CLI tool for SIL 3 OPC-UA Safety Profile (Part 15) SPDU validation and generation.
#[derive(Parser, Debug)]
#[command(name = "async-opcua-safety")]
#[command(author = "Antigravity")]
#[command(version = "1.0")]
#[command(about = "Encodes and validates OPC-UA Safety SPDUs", long_about = None)]
pub struct Cli {
    /// Subcommand to run
    #[command(subcommand)]
    pub command: Commands,
}

/// Available subcommands
#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Encode safety data into an SPDU with calculated CRC
    Encode {
        /// Safety data payload as a hex-encoded string (e.g., "DEADBEEF")
        #[arg(long)]
        safety_data: String,

        /// Monotonically increasing sequence number
        #[arg(long)]
        sequence_number: u32,

        /// Timestamp in milliseconds
        #[arg(long)]
        timestamp: u64,
    },
    /// Validate an SPDU against safety constraints (CRC, sequence, timeout)
    Validate {
        /// Safety data payload as a hex-encoded string (e.g., "DEADBEEF")
        #[arg(long)]
        safety_data: String,

        /// Sequence number present in the SPDU
        #[arg(long)]
        sequence_number: u32,

        /// Timestamp present in the SPDU
        #[arg(long)]
        timestamp: u64,

        /// CRC checksum present in the SPDU
        #[arg(long)]
        crc: u32,

        /// The sequence number the validator expects
        #[arg(long)]
        expected_sequence_number: u32,

        /// The maximum allowed delay (in milliseconds)
        #[arg(long)]
        max_delay: u64,

        /// Current system time (in milliseconds) for timeout checking
        #[arg(long)]
        current_time: u64,
    },
}

/// Executes the parsed CLI commands.
pub fn run_cli() -> Result<(), String> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Encode { safety_data, sequence_number, timestamp } => {
            let data = hex::decode(safety_data.trim_start_matches("0x"))
                .map_err(|e| format!("Invalid hex safety data: {}", e))?;
            let spdu = SpduBuilder::new(data)
                .with_sequence_number(sequence_number)
                .with_timestamp(timestamp)
                .build();
            println!("SPDU Encoded successfully:");
            println!("  Safety Data (hex): {}", hex::encode(&spdu.safety_data));
            println!("  Sequence Number  : {}", spdu.sequence_number);
            println!("  Timestamp        : {}", spdu.timestamp);
            println!("  Calculated CRC   : {}", spdu.crc);
            println!("  Calculated CRC (hex): 0x{:08X}", spdu.crc);
        }
        Commands::Validate {
            safety_data,
            sequence_number,
            timestamp,
            crc,
            expected_sequence_number,
            max_delay,
            current_time,
        } => {
            let data = hex::decode(safety_data.trim_start_matches("0x"))
                .map_err(|e| format!("Invalid hex safety data: {}", e))?;
            let spdu = Spdu::new(data, sequence_number, timestamp, crc);
            let mut validator = SafetyValidator::new(expected_sequence_number, max_delay);

            match validator.validate(&spdu, current_time) {
                Ok(()) => {
                    println!("Validation SUCCESS: SPDU is safe and authentic.");
                    println!("Next expected sequence number: {}", validator.expected_sequence_number());
                }
                Err(SafetyError::InvalidCrc) => {
                    return Err("Validation FAILED: Invalid CRC checksum (data corruption detected).".to_string());
                }
                Err(SafetyError::SequenceMismatch) => {
                    return Err(format!(
                        "Validation FAILED: Sequence number mismatch (expected {}, got {}).",
                        expected_sequence_number, sequence_number
                    ));
                }
                Err(SafetyError::Timeout) => {
                    return Err(format!(
                        "Validation FAILED: Message delay exceeded limit (timestamp {}, current time {}, max delay {}).",
                        timestamp, current_time, max_delay
                    ));
                }
            }
        }
    }
    Ok(())
}
