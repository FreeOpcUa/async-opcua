// OPCUA for Rust
// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2017-2024 Adam Lock

//! Utility for producing sequential message handles.

use std::sync::atomic::{AtomicU32, Ordering};

use serde::Serialize;

/// A simple handle factory for incrementing sequences of numbers.
#[derive(Debug, Clone, Serialize)]
pub struct Handle {
    next: u32,
    first: u32,
}

impl Handle {
    /// Creates a new handle factory, that starts with the supplied number
    pub fn new(first: u32) -> Handle {
        Handle { next: first, first }
    }

    /// Returns the next handle to be issued, internally incrementing each time so the handle
    /// is always different until it wraps back to the start.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> u32 {
        let next = self.next;
        // Increment next
        if self.next == u32::MAX {
            self.next = self.first;
        } else {
            self.next += 1;
        }
        next
    }

    /// Peek the next value of the handle, without incrementing.
    pub fn peek_next(&self) -> u32 {
        self.next
    }

    /// Set the next handle value manually.
    pub fn set_next(&mut self, next: u32) {
        self.next = next;
    }

    /// Resets the handle to its initial state
    pub fn reset(&mut self) {
        self.set_next(self.first);
    }
}

/// Variant of the handle factory using atomics
#[derive(Debug)]
pub struct AtomicHandle {
    next: AtomicU32,
    first: u32,
}

impl AtomicHandle {
    /// Create a new atomic handle. `first` is the starting point and lowest value
    /// this will produce.
    pub fn new(first: u32) -> Self {
        Self {
            next: AtomicU32::new(first),
            first,
        }
    }

    /// Get the next handle.
    pub fn next(&self) -> u32 {
        let mut val = self.next.fetch_add(1, Ordering::Relaxed);

        while val < self.first {
            // On overflow, try to reset the next value to first + 1
            match self.next.compare_exchange(
                val + 1,
                self.first + 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                // If it succeeds, just use first directly.
                Ok(_) => val = self.first,
                Err(v) => {
                    if v >= self.first {
                        val = self.next.fetch_add(1, Ordering::Relaxed);
                    } else {
                        val = v;
                    }
                }
            }
        }
        val
    }

    /// Set the next handle.
    pub fn set_next(&self, next: u32) {
        debug_assert!(next >= self.first);
        self.next.store(next, Ordering::Relaxed);
    }

    /// Resets the handle to its initial state
    pub fn reset(&self) {
        self.set_next(self.first);
    }
}

#[test]
fn handle_increment() {
    // Expect sequential handles
    let mut h = Handle::new(0);
    assert_eq!(h.next(), 0);
    assert_eq!(h.next(), 1);
    assert_eq!(h.next(), 2);
    let mut h = Handle::new(100);
    assert_eq!(h.next(), 100);
    assert_eq!(h.next(), 101);
}

#[test]
fn handle_wrap() {
    // Simulate wrapping around
    let mut h = Handle::new(u32::MAX - 2);
    assert_eq!(h.next(), u32::MAX - 2);
    assert_eq!(h.next(), u32::MAX - 1);
    assert_eq!(h.next(), u32::MAX);
    assert_eq!(h.next(), u32::MAX - 2);
}

#[test]
fn atomic_handle_increment() {
    // Expect sequential handles
    let h = AtomicHandle::new(0);
    assert_eq!(h.next(), 0);
    assert_eq!(h.next(), 1);
    assert_eq!(h.next(), 2);
    let h = AtomicHandle::new(100);
    assert_eq!(h.next(), 100);
    assert_eq!(h.next(), 101);
}

#[test]
fn atomic_handle_wrap() {
    // Simulate wrapping around
    let h = AtomicHandle::new(u32::MAX - 2);
    assert_eq!(h.next(), u32::MAX - 2);
    assert_eq!(h.next(), u32::MAX - 1);
    assert_eq!(h.next(), u32::MAX);
    assert_eq!(h.next(), u32::MAX - 2);
}
