// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2024 Adam Lock

#![warn(missing_docs)]

//! The OPC UA Core module holds functionality that is common to server and clients that make use of OPC UA.
//! It contains message chunking, cryptography / pki, communications and standard handshake messages.

/// Contains debugging utility helper functions
pub mod debug {
    use tracing::{enabled, trace};

    /// Prints out the content of a slice in hex and visible char format to aid debugging. Format
    /// is similar to corresponding functionality in node-opcua
    pub fn log_buffer(message: &str, buf: &[u8]) {
        // No point doing anything unless debug level is on
        if !enabled!(target: "hex", tracing::Level::TRACE) {
            return;
        }

        let line_len = 32;
        let len = buf.len();
        let last_line_padding = ((len / line_len) + 1) * line_len - len;

        trace!(target: "hex", "{}", message);

        let mut char_line = String::new();
        let mut hex_line = format!("{:08x}: ", 0);

        for (i, b) in buf.iter().enumerate() {
            let value = { *b };
            if i > 0 && i % line_len == 0 {
                trace!(target: "hex", "{} {}", hex_line, char_line);
                hex_line = format!("{:08}: ", i);
                char_line.clear();
            }
            hex_line = format!("{} {:02x}", hex_line, value);
            char_line.push(if (32..=126).contains(&value) {
                value as char
            } else {
                '.'
            });
        }
        if last_line_padding > 0 {
            for _ in 0..last_line_padding {
                hex_line.push_str("   ");
            }
            trace!(target: "hex", "{} {}", hex_line, char_line);
        }
    }
}

#[cfg(test)]
pub(crate) mod tests;

/// Contains common OPC-UA constants.
pub mod constants {
    /// Default OPC UA port number. Used by a discovery server. Other servers would normally run
    /// on a different port. So OPC UA for Rust does not use this nr by default but it is used
    /// implicitly in opc.tcp:// urls and elsewhere.
    pub const DEFAULT_OPC_UA_SERVER_PORT: u16 = 4840;
}

pub mod comms;
pub mod config;
pub mod handle;

pub mod messages;
use std::sync::atomic::AtomicBool;

pub use messages::{Message, MessageType, RequestMessage, ResponseMessage};

/// Check for the environment variable OPCUA_TRACE_LOCKS. If it is set to 1 or true, then
/// tracing will be enabled for locks. This is useful for debugging deadlocks.
pub fn trace_locks() -> bool {
    static ENABLED: AtomicBool = AtomicBool::new(false);
    if ENABLED.load(std::sync::atomic::Ordering::Relaxed) {
        return true;
    }
    let enabled = match std::env::var("OPCUA_TRACE_LOCKS") {
        Ok(s) => s != "0",
        Err(_) => false,
    };

    ENABLED.store(enabled, std::sync::atomic::Ordering::Relaxed);

    enabled
}
/// Re-export the tracing crate. This is used for logging and debugging.
pub use tracing;

/// Tracing macro for obtaining a lock on a `Mutex`. Sometimes deadlocks can happen in code,
/// and if they do, this macro is useful for finding out where they happened.
#[macro_export]
macro_rules! trace_lock {
    ( $x:expr ) => {{
        use std::thread;
        if $crate::trace_locks() {
            $crate::tracing::trace!(
                "Thread {:?}, {} locking at {}, line {}",
                thread::current().id(),
                stringify!($x),
                file!(),
                line!()
            );
        }
        let v = $x.lock();
        if $crate::trace_locks() {
            $crate::tracing::trace!(
                "Thread {:?}, {} lock completed",
                thread::current().id(),
                stringify!($x)
            );
        }
        v
    }};
}

/// Tracing macro for obtaining a read lock on a `RwLock`.
#[macro_export]
macro_rules! trace_read_lock {
    ( $x:expr ) => {{
        use std::thread;
        if $crate::trace_locks() {
            $crate::tracing::trace!(
                "Thread {:?}, {} read locking at {}, line {}",
                thread::current().id(),
                stringify!($x),
                file!(),
                line!()
            );
        }
        let v = $x.read();
        if $crate::trace_locks() {
            $crate::tracing::trace!(
                "Thread {:?}, {} read lock completed",
                thread::current().id(),
                stringify!($x)
            );
        }
        v
    }};
}

/// Tracing macro for obtaining a write lock on a `RwLock`.
#[macro_export]
macro_rules! trace_write_lock {
    ( $x:expr ) => {{
        use std::thread;
        if $crate::trace_locks() {
            $crate::tracing::trace!(
                "Thread {:?}, {} write locking at {}, line {}",
                thread::current().id(),
                stringify!($x),
                file!(),
                line!()
            );
        }
        let v = $x.write();
        if $crate::trace_locks() {
            $crate::tracing::trace!(
                "Thread {:?}, {} write lock completed",
                thread::current().id(),
                stringify!($x)
            );
        }
        v
    }};
}

/// Common synchronous locks. Re-exports locks from parking_lot used internally.
pub mod sync {
    /// Read-write lock. Use this if you usually only need to read the value.
    pub type RwLock<T> = parking_lot::RwLock<T>;
    /// Mutually exclusive lock. Use this if you need both read and write often.
    pub type Mutex<T> = parking_lot::Mutex<T>;
}
