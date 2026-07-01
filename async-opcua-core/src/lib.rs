// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2024 Adam Lock

#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic
    )
)]
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
                hex_line = format!("{i:08}: ");
                char_line.clear();
            }
            hex_line = format!("{hex_line} {value:02x}");
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
/// Common advanced-compliance status code aliases.
pub mod error;
pub mod handle;

pub mod messages;
use std::sync::atomic::{AtomicU8, Ordering};

pub use messages::{
    Message, MessageType, PublishResponseShared, RepublishResponseShared, RequestMessage,
    ResponseMessage,
};

const TRACE_LOCKS_UNKNOWN: u8 = 0;
const TRACE_LOCKS_DISABLED: u8 = 1;
const TRACE_LOCKS_ENABLED: u8 = 2;

// Feature 049: intentionally process-global - process-wide OPCUA_TRACE_LOCKS config cache.

static TRACE_LOCKS_STATE: AtomicU8 = AtomicU8::new(TRACE_LOCKS_UNKNOWN);

/// Check for the environment variable OPCUA_TRACE_LOCKS. If it is set to a value other than `0`,
/// then tracing will be enabled for locks. This is useful for debugging deadlocks.
pub fn trace_locks() -> bool {
    match TRACE_LOCKS_STATE.load(Ordering::Relaxed) {
        TRACE_LOCKS_ENABLED => return true,
        TRACE_LOCKS_DISABLED => return false,
        _ => {}
    }

    let state = match std::env::var("OPCUA_TRACE_LOCKS") {
        Ok(s) if s != "0" => TRACE_LOCKS_ENABLED,
        _ => TRACE_LOCKS_DISABLED,
    };

    TRACE_LOCKS_STATE.store(state, Ordering::Relaxed);

    state == TRACE_LOCKS_ENABLED
}

#[cfg(test)]
fn reset_trace_locks_cache_for_test() {
    TRACE_LOCKS_STATE.store(TRACE_LOCKS_UNKNOWN, Ordering::Relaxed);
}

#[cfg(test)]
mod trace_locks_tests {
    use std::sync::Mutex;

    use super::{reset_trace_locks_cache_for_test, trace_locks};

    // Feature 049: intentionally process-global - serializes process env mutation.

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn trace_locks_caches_disabled_result() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::remove_var("OPCUA_TRACE_LOCKS");
        reset_trace_locks_cache_for_test();

        assert!(!trace_locks());

        std::env::set_var("OPCUA_TRACE_LOCKS", "1");
        assert!(!trace_locks());

        std::env::remove_var("OPCUA_TRACE_LOCKS");
        reset_trace_locks_cache_for_test();
    }

    #[test]
    fn trace_locks_caches_enabled_result() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("OPCUA_TRACE_LOCKS", "1");
        reset_trace_locks_cache_for_test();

        assert!(trace_locks());

        std::env::set_var("OPCUA_TRACE_LOCKS", "0");
        assert!(trace_locks());

        std::env::remove_var("OPCUA_TRACE_LOCKS");
        reset_trace_locks_cache_for_test();
    }
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

/// Shared compliance traits and enums.
pub mod traits;
pub use traits::*;

/// Logging, masking, and tracing helpers.
pub mod logging;

/// Alarms & Conditions event types structures.
pub mod events;
pub use events::AlarmEvent;
